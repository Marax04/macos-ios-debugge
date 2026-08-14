//! `rustre-emu-shellcode::shellcode_emulator`
//!
//! High-level shellcode emulation: context management, API hooking,
//! memory dumps, and a rich result type.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── MemoryRegion ─────────────────────────────────────────────────────────────

/// A memory region allocated inside the emulated address space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulatedMemoryRegion {
    /// Base address.
    pub base: u64,
    /// Size in bytes.
    pub size: usize,
    /// Region tag (e.g. `"stack"`, `"heap"`, `"shellcode"`).
    pub tag: String,
    /// Contents.
    pub data: Vec<u8>,
    /// Whether the region is executable.
    pub executable: bool,
}

impl EmulatedMemoryRegion {
    /// Create a new zeroed region.
    ///
    /// `size` is capped at 256 MiB to prevent memory exhaustion when an
    /// attacker-controlled value is forwarded from a VirtualAlloc stub or
    /// similar API hook. Callers that legitimately need a larger region should
    /// use a mapped-file or lazy-allocation scheme instead.
    #[must_use]
    pub fn new(base: u64, size: usize, tag: impl Into<String>) -> Self {
        const MAX_REGION: usize = 256 * 1024 * 1024; // 256 MiB hard cap
        let size = size.min(MAX_REGION);
        Self {
            base,
            size,
            data: vec![0u8; size],
            tag: tag.into(),
            executable: false,
        }
    }

    /// Mark this region executable.
    #[must_use]
    pub const fn executable(mut self) -> Self {
        self.executable = true;
        self
    }

    /// Write bytes at an offset within the region.
    ///
    /// Returns the number of bytes written.
    pub fn write_at(&mut self, offset: usize, bytes: &[u8]) -> usize {
        if offset >= self.data.len() {
            return 0;
        }
        let n = bytes.len().min(self.data.len() - offset);
        self.data[offset..offset + n].copy_from_slice(&bytes[..n]);
        n
    }

    /// Read bytes starting at `offset`.
    #[must_use]
    pub fn read_at(&self, offset: usize, len: usize) -> &[u8] {
        let start = offset.min(self.data.len());
        let end = (start + len).min(self.data.len());
        &self.data[start..end]
    }

    /// Return `true` if `addr` falls within this region.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base.saturating_add(self.size as u64)
    }
}

impl fmt::Display for EmulatedMemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:#x}..{:#x}] {} {}",
            self.base,
            self.base + self.size as u64,
            self.tag,
            if self.executable { "exec" } else { "data" },
        )
    }
}

// ─── ShellcodeContext ─────────────────────────────────────────────────────────

/// Snapshot of the emulated CPU state at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellcodeContext {
    /// Named register values (e.g. `"rax"`, `"rsp"`, `"rip"`).
    pub registers: HashMap<String, u64>,
    /// Allocated memory regions.
    pub regions: Vec<EmulatedMemoryRegion>,
    /// Current instruction pointer.
    pub rip: u64,
    /// Current stack pointer.
    pub rsp: u64,
    /// Execution step count at time of snapshot.
    pub step: u64,
}

impl ShellcodeContext {
    /// Create an empty context.
    #[must_use]
    pub fn new() -> Self {
        Self {
            registers: HashMap::new(),
            regions: Vec::new(),
            rip: 0,
            rsp: 0,
            step: 0,
        }
    }

    /// Set a register value.
    pub fn set_reg(&mut self, name: impl Into<String>, value: u64) {
        let name = name.into();
        if name == "rip" {
            self.rip = value;
        }
        if name == "rsp" {
            self.rsp = value;
        }
        self.registers.insert(name, value);
    }

    /// Get a register value, returning `0` if not set.
    #[must_use]
    pub fn get_reg(&self, name: &str) -> u64 {
        self.registers.get(name).copied().unwrap_or(0)
    }

    /// Find the region containing `addr`, if any.
    #[must_use]
    pub fn region_at(&self, addr: u64) -> Option<&EmulatedMemoryRegion> {
        self.regions.iter().find(|r| r.contains(addr))
    }

    /// Find a mutable region containing `addr`.
    #[must_use]
    pub fn region_at_mut(&mut self, addr: u64) -> Option<&mut EmulatedMemoryRegion> {
        self.regions.iter_mut().find(|r| r.contains(addr))
    }

    /// Add a memory region to the context.
    pub fn add_region(&mut self, region: EmulatedMemoryRegion) {
        self.regions.push(region);
    }

    /// Read `len` bytes from virtual address `addr`.
    ///
    /// `len` is capped at 64 MiB to prevent memory exhaustion when the caller
    /// passes an attacker-controlled length for an unmapped address (the
    /// fallback `vec![0u8; len]` path would otherwise allocate without bound).
    #[must_use]
    pub fn read_va(&self, addr: u64, len: usize) -> Vec<u8> {
        const MAX_READ: usize = 64 * 1024 * 1024; // 64 MiB hard cap
        let len = len.min(MAX_READ);
        if let Some(region) = self.region_at(addr) {
            let offset = (addr - region.base) as usize;
            region.read_at(offset, len).to_vec()
        } else {
            vec![0u8; len]
        }
    }

    /// Write `bytes` to virtual address `addr`.
    ///
    /// Returns the number of bytes written.
    pub fn write_va(&mut self, addr: u64, bytes: &[u8]) -> usize {
        if let Some(region) = self.region_at_mut(addr) {
            let offset = (addr - region.base) as usize;
            region.write_at(offset, bytes)
        } else {
            0
        }
    }

    /// Return the total number of mapped bytes.
    #[must_use]
    pub fn total_mapped_bytes(&self) -> usize {
        self.regions.iter().map(|r| r.size).sum()
    }
}

impl Default for ShellcodeContext {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ShellcodeContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ShellcodeContext {{ rip={:#x} rsp={:#x} step={} regions={} }}",
            self.rip,
            self.rsp,
            self.step,
            self.regions.len(),
        )
    }
}

// ─── ApiHook ──────────────────────────────────────────────────────────────────

/// A hook for a specific API function call.
#[derive(Debug, Clone)]
pub struct ApiHook {
    /// API name (e.g. `"VirtualAlloc"`).
    pub name: String,
    /// Virtual address where the hook fires.
    pub address: u64,
    /// Return value to inject.
    pub return_value: u64,
    /// Number of times this hook has fired.
    pub hit_count: u64,
    /// Whether the hook is enabled.
    pub enabled: bool,
    /// Optional size hint for allocation APIs.
    pub alloc_size_arg_index: Option<usize>,
}

impl ApiHook {
    /// Create a new hook.
    #[must_use]
    pub fn new(name: impl Into<String>, address: u64, return_value: u64) -> Self {
        Self {
            name: name.into(),
            address,
            return_value,
            hit_count: 0,
            enabled: true,
            alloc_size_arg_index: None,
        }
    }

    /// Create a `VirtualAlloc` hook.
    #[must_use]
    pub fn virtual_alloc(address: u64, alloc_base: u64) -> Self {
        let mut h = Self::new("VirtualAlloc", address, alloc_base);
        h.alloc_size_arg_index = Some(1); // lpSize is arg1
        h
    }

    /// Create a `LoadLibrary` hook.
    #[must_use]
    pub fn load_library(address: u64, module_handle: u64) -> Self {
        Self::new("LoadLibraryA", address, module_handle)
    }

    /// Create a `GetProcAddress` hook.
    #[must_use]
    pub fn get_proc_address(address: u64, proc_address: u64) -> Self {
        Self::new("GetProcAddress", address, proc_address)
    }

    /// Fire the hook: increment hit count and return the configured return value.
    pub const fn fire(&mut self, _args: &[u64]) -> u64 {
        self.hit_count += 1;
        self.return_value
    }

    /// Disable this hook.
    pub const fn disable(&mut self) {
        self.enabled = false;
    }

    /// Enable this hook.
    pub const fn enable(&mut self) {
        self.enabled = true;
    }
}

impl fmt::Display for ApiHook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ApiHook {{ {} @ {:#x} ret={:#x} hits={} enabled={} }}",
            self.name, self.address, self.return_value, self.hit_count, self.enabled,
        )
    }
}

// ─── ApiCallRecord ────────────────────────────────────────────────────────────

/// A recorded API call intercepted during emulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCallRecord {
    /// API name.
    pub name: String,
    /// Virtual address of the hook.
    pub address: u64,
    /// Arguments captured from registers.
    pub args: Vec<u64>,
    /// Return value injected.
    pub ret: u64,
    /// Instruction pointer at the time of the call.
    pub call_rip: u64,
}

impl fmt::Display for ApiCallRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}({}) -> {:#x}  [call site: {:#x}]",
            self.name,
            self.args
                .iter()
                .map(|a| format!("{a:#x}"))
                .collect::<Vec<_>>()
                .join(", "),
            self.ret,
            self.call_rip,
        )
    }
}

// ─── MemoryDump ───────────────────────────────────────────────────────────────

/// A snapshot of the emulated memory at a specific point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDump {
    /// Step count at time of dump.
    pub step: u64,
    /// (`base_address`, data) pairs for each region.
    pub regions: Vec<(u64, Vec<u8>)>,
    /// Register state at time of dump.
    pub registers: HashMap<String, u64>,
    /// Label for this dump (e.g. `"pre_decode"`, `"post_decode"`).
    pub label: String,
}

impl MemoryDump {
    /// Create from a `ShellcodeContext`.
    #[must_use]
    pub fn from_context(ctx: &ShellcodeContext, label: impl Into<String>) -> Self {
        Self {
            step: ctx.step,
            regions: ctx
                .regions
                .iter()
                .map(|r| (r.base, r.data.clone()))
                .collect(),
            registers: ctx.registers.clone(),
            label: label.into(),
        }
    }

    /// Find a region by base address.
    #[must_use]
    pub fn region(&self, base: u64) -> Option<&[u8]> {
        self.regions
            .iter()
            .find(|(b, _)| *b == base)
            .map(|(_, d)| d.as_slice())
    }

    /// Total bytes captured.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.regions.iter().map(|(_, d)| d.len()).sum()
    }

    /// Extract printable ASCII strings (>= 4 chars) from all regions.
    #[must_use]
    pub fn extract_strings(&self, min_len: usize) -> Vec<String> {
        let mut result = Vec::new();
        for (_, data) in &self.regions {
            let mut current = Vec::new();
            for &b in data {
                if (0x20..0x7F).contains(&b) {
                    current.push(b);
                } else {
                    if current.len() >= min_len
                        && let Ok(s) = std::str::from_utf8(&current) {
                            result.push(s.to_owned());
                        }
                    current.clear();
                }
            }
            if current.len() >= min_len
                && let Ok(s) = std::str::from_utf8(&current) {
                    result.push(s.to_owned());
                }
        }
        result.sort();
        result.dedup();
        result
    }

    /// Diff two dumps: return `(base_address, changed_bytes)` pairs for every
    /// region where at least one byte differs between `before` and `after`.
    ///
    /// Changed bytes are represented as `Some(new_value)`; unchanged bytes are
    /// `None`.  This avoids the false-negative that arises when a byte changes
    /// *to* zero (e.g. XOR clear, null-terminator writes).
    #[must_use]
    pub fn diff(before: &Self, after: &Self) -> Vec<(u64, Vec<Option<u8>>)> {
        let mut diffs = Vec::new();
        for (base, after_data) in &after.regions {
            if let Some(before_data) = before.region(*base) {
                let changed: Vec<Option<u8>> = after_data
                    .iter()
                    .zip(before_data.iter())
                    .map(|(&a, &b)| if a == b { None } else { Some(a) })
                    .collect();
                if changed.iter().any(|slot| slot.is_some()) {
                    diffs.push((*base, changed));
                }
            }
        }
        diffs
    }
}

impl fmt::Display for MemoryDump {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MemoryDump '{}' step={} regions={} total={}B",
            self.label,
            self.step,
            self.regions.len(),
            self.total_bytes(),
        )
    }
}

// ─── EmulationResult ──────────────────────────────────────────────────────────

/// The complete result of running the `ShellcodeEmulator`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulationResult {
    /// Decoded payload — bytes that were written to memory post-decode.
    pub decoded_payload: Vec<u8>,
    /// API calls intercepted during emulation.
    pub api_calls: Vec<ApiCallRecord>,
    /// Printable strings found in memory post-emulation.
    pub strings_produced: Vec<String>,
    /// Final register snapshot.
    pub final_registers: HashMap<String, u64>,
    /// Total instructions executed.
    pub instructions_executed: u64,
    /// Reason execution stopped.
    pub exit_reason: String,
    /// Memory dumps collected during execution.
    pub dumps: Vec<MemoryDump>,
}

impl EmulationResult {
    /// Create an empty result.
    #[must_use]
    pub fn new(exit_reason: impl Into<String>) -> Self {
        Self {
            decoded_payload: Vec::new(),
            api_calls: Vec::new(),
            strings_produced: Vec::new(),
            final_registers: HashMap::new(),
            instructions_executed: 0,
            exit_reason: exit_reason.into(),
            dumps: Vec::new(),
        }
    }

    /// Return `true` if any API call matches the given name.
    #[must_use]
    pub fn called_api(&self, name: &str) -> bool {
        self.api_calls.iter().any(|a| a.name == name)
    }

    /// Return all API calls with a given name.
    #[must_use]
    pub fn calls_to(&self, name: &str) -> Vec<&ApiCallRecord> {
        self.api_calls.iter().filter(|a| a.name == name).collect()
    }

    /// Return `true` if the decoded payload is non-empty.
    #[must_use]
    pub const fn has_decoded_payload(&self) -> bool {
        !self.decoded_payload.is_empty()
    }

    /// Return the number of distinct API names called.
    #[must_use]
    pub fn distinct_apis_called(&self) -> usize {
        let mut names: Vec<&str> = self.api_calls.iter().map(|a| a.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        names.len()
    }

    /// Find a dump by label.
    #[must_use]
    pub fn dump(&self, label: &str) -> Option<&MemoryDump> {
        self.dumps.iter().find(|d| d.label == label)
    }
}

impl fmt::Display for EmulationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EmulationResult {{ exit={} instrs={} apis={} strings={} payload={}B }}",
            self.exit_reason,
            self.instructions_executed,
            self.api_calls.len(),
            self.strings_produced.len(),
            self.decoded_payload.len(),
        )
    }
}

// ─── ShellcodeEmulator ────────────────────────────────────────────────────────

/// High-level shellcode emulator that manages context, hooks, and results.
///
/// Does not depend on the Unicorn/emulator back-end directly; instead it
/// operates on [`ShellcodeContext`] objects and delegates execution to a
/// configurable callback.
#[derive(Debug)]
pub struct ShellcodeEmulator {
    /// Current execution context.
    pub context: ShellcodeContext,
    /// Registered API hooks.
    pub hooks: Vec<ApiHook>,
    /// Maximum number of emulation steps.
    pub max_steps: u64,
    /// Collect memory dumps at these step intervals (0 = never).
    pub dump_interval: u64,
    /// Whether to extract strings from all dumps.
    pub extract_strings: bool,
    /// Minimum string length to extract.
    pub min_string_len: usize,
}

impl ShellcodeEmulator {
    /// Create an emulator with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            context: ShellcodeContext::new(),
            hooks: Vec::new(),
            max_steps: 100_000,
            dump_interval: 0,
            extract_strings: true,
            min_string_len: 4,
        }
    }

    /// Set the maximum steps.
    #[must_use]
    pub const fn with_max_steps(mut self, n: u64) -> Self {
        self.max_steps = n;
        self
    }

    /// Enable memory dumps every `n` steps.
    #[must_use]
    pub const fn with_dump_interval(mut self, n: u64) -> Self {
        self.dump_interval = n;
        self
    }

    /// Load shellcode into a new executable region at `base`.
    pub fn load_shellcode(&mut self, base: u64, code: &[u8]) {
        let mut region = EmulatedMemoryRegion::new(base, code.len().max(0x1000), "shellcode");
        region.executable = true;
        region.write_at(0, code);
        self.context.add_region(region);
        self.context.set_reg("rip", base);
    }

    /// Add a stack region and set RSP.
    pub fn add_stack(&mut self, base: u64, size: usize) {
        let sp = base + (size as u64 / 2);
        self.context
            .add_region(EmulatedMemoryRegion::new(base, size, "stack"));
        self.context.set_reg("rsp", sp);
    }

    /// Add a heap region.
    pub fn add_heap(&mut self, base: u64, size: usize) {
        self.context
            .add_region(EmulatedMemoryRegion::new(base, size, "heap"));
    }

    /// Register an API hook.
    pub fn add_hook(&mut self, hook: ApiHook) {
        self.hooks.push(hook);
    }

    /// Add common Windows shellcode hooks.
    pub fn add_common_windows_hooks(&mut self) {
        self.add_hook(ApiHook::virtual_alloc(0x7ffe_0000, 0x0040_0000));
        self.add_hook(ApiHook::load_library(0x7ffe_1000, 0x7000_0000));
        self.add_hook(ApiHook::get_proc_address(0x7ffe_2000, 0x7000_1000));
    }

    /// Find a hook by address.
    #[must_use]
    pub fn hook_at(&self, addr: u64) -> Option<&ApiHook> {
        self.hooks.iter().find(|h| h.address == addr && h.enabled)
    }

    /// Find a mutable hook by address.
    #[must_use]
    pub fn hook_at_mut(&mut self, addr: u64) -> Option<&mut ApiHook> {
        self.hooks
            .iter_mut()
            .find(|h| h.address == addr && h.enabled)
    }

    /// Simulate execution: step through a sequence of pre-computed instructions.
    ///
    /// This method performs a lightweight simulation suitable for unit tests and
    /// analysis pipelines, without requiring a real emulator back-end.  It
    /// processes `steps` entries from the `instruction_pcs` iterator, checks
    /// for hook matches, and collects results.
    ///
    /// For each PC value:
    /// - If a hook is registered at that address, it fires and an `ApiCallRecord`
    ///   is produced.
    /// - Otherwise the step is counted.
    pub fn simulate<I>(&mut self, instruction_pcs: I) -> EmulationResult
    where
        I: IntoIterator<Item = (u64, Vec<u64>)>, // (pc, args)
    {
        let mut result = EmulationResult::new("simulated");
        let mut dumps: Vec<MemoryDump> = Vec::new();

        for (step, (pc, args)) in instruction_pcs.into_iter().enumerate() {
            if step as u64 >= self.max_steps {
                result.exit_reason = "max_steps".to_string();
                break;
            }

            self.context.rip = pc;
            self.context.step = step as u64;

            // Periodic dump.
            if self.dump_interval > 0 && (step as u64).is_multiple_of(self.dump_interval) {
                dumps.push(MemoryDump::from_context(
                    &self.context,
                    format!("step_{step}"),
                ));
            }

            // Hook check.
            if let Some(hook) = self.hooks.iter_mut().find(|h| h.address == pc && h.enabled) {
                let ret = hook.fire(&args);
                result.api_calls.push(ApiCallRecord {
                    name: hook.name.clone(),
                    address: pc,
                    args: args.clone(),
                    ret,
                    call_rip: pc,
                });
                // Advance RIP past the hook stub (simulated).
                self.context.rip = pc + 5;
            }

            result.instructions_executed += 1;
        }

        // Post-emulation: collect strings from context.
        if self.extract_strings {
            let dump = MemoryDump::from_context(&self.context, "final");
            result.strings_produced = dump.extract_strings(self.min_string_len);
        }

        result.dumps = dumps;
        result.final_registers.clone_from(&self.context.registers);
        result
    }

    /// Run the emulator and return a result.
    ///
    /// `steps` is a slice of `(pc, args)` pairs to simulate.
    #[must_use]
    pub fn run(&mut self, steps: Vec<(u64, Vec<u64>)>) -> EmulationResult {
        self.simulate(steps)
    }

    /// Collect a snapshot dump of the current context.
    #[must_use]
    pub fn dump(&self, label: impl Into<String>) -> MemoryDump {
        MemoryDump::from_context(&self.context, label)
    }
}

impl Default for ShellcodeEmulator {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ShellcodeEmulator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ShellcodeEmulator {{ hooks={} max_steps={} ctx={} }}",
            self.hooks.len(),
            self.max_steps,
            self.context,
        )
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn build_emulator() -> ShellcodeEmulator {
        let mut emu = ShellcodeEmulator::new().with_max_steps(1000);
        emu.load_shellcode(0x1000, &[0x90u8; 32]);
        emu.add_stack(0x0010_0000, 0x1000);
        emu.add_heap(0x0020_0000, 0x4000);
        emu.add_common_windows_hooks();
        emu
    }

    // ── EmulatedMemoryRegion ──────────────────────────────────────────────────

    #[test]
    fn region_contains() {
        let r = EmulatedMemoryRegion::new(0x1000, 0x100, "test");
        assert!(r.contains(0x1000));
        assert!(r.contains(0x10FF));
        assert!(!r.contains(0x1100));
        assert!(!r.contains(0x0FFF));
    }

    #[test]
    fn region_write_and_read() {
        let mut r = EmulatedMemoryRegion::new(0x1000, 0x10, "test");
        let n = r.write_at(2, &[0xDE, 0xAD]);
        assert_eq!(n, 2);
        let bytes = r.read_at(2, 2);
        assert_eq!(bytes, &[0xDE, 0xAD]);
    }

    #[test]
    fn region_write_past_end_clamped() {
        let mut r = EmulatedMemoryRegion::new(0, 4, "t");
        let n = r.write_at(3, &[1, 2, 3]); // Only 1 byte fits.
        assert_eq!(n, 1);
    }

    #[test]
    fn region_display() {
        let r = EmulatedMemoryRegion::new(0x1000, 0x100, "stack").executable();
        assert!(r.to_string().contains("exec"));
    }

    // ── ShellcodeContext ──────────────────────────────────────────────────────

    #[test]
    fn context_set_and_get_reg() {
        let mut ctx = ShellcodeContext::new();
        ctx.set_reg("rax", 0xDEAD);
        assert_eq!(ctx.get_reg("rax"), 0xDEAD);
        assert_eq!(ctx.get_reg("rcx"), 0); // not set
    }

    #[test]
    fn context_rip_rsp_aliases() {
        let mut ctx = ShellcodeContext::new();
        ctx.set_reg("rip", 0x4000);
        ctx.set_reg("rsp", 0x5000);
        assert_eq!(ctx.rip, 0x4000);
        assert_eq!(ctx.rsp, 0x5000);
    }

    #[test]
    fn context_region_at() {
        let mut ctx = ShellcodeContext::new();
        ctx.add_region(EmulatedMemoryRegion::new(0x1000, 0x100, "code"));
        assert!(ctx.region_at(0x1000).is_some());
        assert!(ctx.region_at(0x2000).is_none());
    }

    #[test]
    fn context_read_write_va() {
        let mut ctx = ShellcodeContext::new();
        ctx.add_region(EmulatedMemoryRegion::new(0x1000, 0x100, "data"));
        let n = ctx.write_va(0x1010, &[1, 2, 3, 4]);
        assert_eq!(n, 4);
        let bytes = ctx.read_va(0x1010, 4);
        assert_eq!(bytes, vec![1, 2, 3, 4]);
    }

    #[test]
    fn context_total_mapped_bytes() {
        let mut ctx = ShellcodeContext::new();
        ctx.add_region(EmulatedMemoryRegion::new(0, 0x1000, "a"));
        ctx.add_region(EmulatedMemoryRegion::new(0x2000, 0x2000, "b"));
        assert_eq!(ctx.total_mapped_bytes(), 0x3000);
    }

    // ── ApiHook ───────────────────────────────────────────────────────────────

    #[test]
    fn hook_fire_increments_hit_count() {
        let mut h = ApiHook::new("malloc", 0x7000, 0x0040_0000);
        let ret = h.fire(&[64]);
        assert_eq!(ret, 0x0040_0000);
        assert_eq!(h.hit_count, 1);
    }

    #[test]
    fn hook_enable_disable() {
        let mut h = ApiHook::new("fn", 0, 0);
        h.disable();
        assert!(!h.enabled);
        h.enable();
        assert!(h.enabled);
    }

    #[test]
    fn hook_virtual_alloc_constructor() {
        let h = ApiHook::virtual_alloc(0x7000, 0x0040_0000);
        assert_eq!(h.name, "VirtualAlloc");
        assert!(h.alloc_size_arg_index.is_some());
    }

    #[test]
    fn hook_display() {
        let h = ApiHook::new("GetProcAddress", 0x7001, 0xDEAD);
        let s = h.to_string();
        assert!(s.contains("GetProcAddress"));
        assert!(s.contains("0x7001"));
    }

    // ── MemoryDump ────────────────────────────────────────────────────────────

    #[test]
    fn dump_from_context() {
        let mut ctx = ShellcodeContext::new();
        ctx.add_region(EmulatedMemoryRegion::new(0x1000, 0x100, "test"));
        let dump = MemoryDump::from_context(&ctx, "test_dump");
        assert_eq!(dump.label, "test_dump");
        assert_eq!(dump.total_bytes(), 0x100);
    }

    #[test]
    fn dump_extract_strings() {
        let mut ctx = ShellcodeContext::new();
        let mut region = EmulatedMemoryRegion::new(0x1000, 64, "data");
        region.write_at(0, b"Hello, World!\x00garbage");
        ctx.add_region(region);
        let dump = MemoryDump::from_context(&ctx, "d");
        let strings = dump.extract_strings(4);
        assert!(strings.iter().any(|s| s.contains("Hello")));
    }

    #[test]
    fn dump_diff_detects_change() {
        let mut ctx = ShellcodeContext::new();
        ctx.add_region(EmulatedMemoryRegion::new(0x1000, 8, "data"));
        let before = MemoryDump::from_context(&ctx, "before");
        ctx.write_va(0x1000, &[0xAA, 0xBB]);
        let after = MemoryDump::from_context(&ctx, "after");
        let diffs = MemoryDump::diff(&before, &after);
        assert!(!diffs.is_empty());
    }

    #[test]
    fn dump_diff_no_change() {
        let mut ctx = ShellcodeContext::new();
        ctx.add_region(EmulatedMemoryRegion::new(0x1000, 8, "data"));
        let a = MemoryDump::from_context(&ctx, "a");
        let b = MemoryDump::from_context(&ctx, "b");
        assert!(MemoryDump::diff(&a, &b).is_empty());
    }

    // ── EmulationResult ───────────────────────────────────────────────────────

    #[test]
    fn result_called_api() {
        let mut r = EmulationResult::new("ok");
        r.api_calls.push(ApiCallRecord {
            name: "VirtualAlloc".to_string(),
            address: 0,
            args: vec![],
            ret: 0,
            call_rip: 0,
        });
        assert!(r.called_api("VirtualAlloc"));
        assert!(!r.called_api("LoadLibraryA"));
    }

    #[test]
    fn result_distinct_apis() {
        let mut r = EmulationResult::new("ok");
        r.api_calls.push(ApiCallRecord {
            name: "malloc".to_string(),
            address: 0,
            args: vec![],
            ret: 0,
            call_rip: 0,
        });
        r.api_calls.push(ApiCallRecord {
            name: "malloc".to_string(),
            address: 0,
            args: vec![],
            ret: 0,
            call_rip: 0,
        });
        r.api_calls.push(ApiCallRecord {
            name: "free".to_string(),
            address: 0,
            args: vec![],
            ret: 0,
            call_rip: 0,
        });
        assert_eq!(r.distinct_apis_called(), 2);
    }

    #[test]
    fn result_has_decoded_payload() {
        let mut r = EmulationResult::new("ok");
        assert!(!r.has_decoded_payload());
        r.decoded_payload = vec![1, 2, 3];
        assert!(r.has_decoded_payload());
    }

    // ── ShellcodeEmulator ─────────────────────────────────────────────────────

    #[test]
    fn emulator_load_shellcode_sets_rip() {
        let mut emu = ShellcodeEmulator::new();
        emu.load_shellcode(0x2000, &[0x90u8; 8]);
        assert_eq!(emu.context.rip, 0x2000);
    }

    #[test]
    fn emulator_add_stack_sets_rsp() {
        let mut emu = ShellcodeEmulator::new();
        emu.add_stack(0x0010_0000, 0x2000);
        assert_eq!(emu.context.rsp, 0x0010_1000);
    }

    #[test]
    fn emulator_hook_at_found() {
        let emu = build_emulator();
        assert!(emu.hook_at(0x7ffe_0000).is_some());
    }

    #[test]
    fn emulator_hook_at_not_found() {
        let emu = build_emulator();
        assert!(emu.hook_at(0x1234_5678).is_none());
    }

    #[test]
    fn emulator_simulate_counts_instructions() {
        let mut emu = build_emulator();
        let steps: Vec<(u64, Vec<u64>)> = (0u64..10).map(|i| (0x1000 + i, vec![])).collect();
        let result = emu.simulate(steps);
        assert_eq!(result.instructions_executed, 10);
    }

    #[test]
    fn emulator_simulate_fires_hook() {
        let mut emu = build_emulator();
        let steps = vec![(0x7ffe_0000u64, vec![0, 0x1000, 0, 0x40])];
        let result = emu.simulate(steps);
        assert!(result.called_api("VirtualAlloc"));
    }

    #[test]
    fn emulator_simulate_max_steps_respected() {
        let mut emu = ShellcodeEmulator::new().with_max_steps(5);
        emu.load_shellcode(0x1000, &[0x90u8; 32]);
        let steps: Vec<(u64, Vec<u64>)> = (0u64..100).map(|i| (0x1000 + i, vec![])).collect();
        let result = emu.simulate(steps);
        assert_eq!(result.instructions_executed, 5);
        assert_eq!(result.exit_reason, "max_steps");
    }

    #[test]
    fn emulator_dump_returns_snapshot() {
        let emu = build_emulator();
        let dump = emu.dump("snap");
        assert_eq!(dump.label, "snap");
        assert!(!dump.regions.is_empty());
    }

    #[test]
    fn emulator_run_empty_steps() {
        let mut emu = build_emulator();
        let result = emu.run(vec![]);
        assert_eq!(result.instructions_executed, 0);
    }

    #[test]
    fn emulator_display_format() {
        let emu = build_emulator();
        let s = emu.to_string();
        assert!(s.contains("ShellcodeEmulator"));
    }
}
