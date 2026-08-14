//! `rhai_debug_api` — Debug-related API bindings exposed to Rhai scripts.
//!
//! Provides a mock debugger backend and a set of Rhai host functions that
//! allow scripts to set breakpoints, read/write registers and memory,
//! single-step, continue execution, and inspect the call stack.
//!
//! # Key types
//!
//! | Type | Purpose |
//! |---|---|
//! | [`RhaiDebugApi`] | Registers all debug functions with a Rhai engine |
//! | [`MockDebugger`] | In-process mock debugger backend |
//! | [`DebuggerState`] | Tracks running/paused/stopped state |
//! | [`Breakpoint`] | An address breakpoint |
//! | [`RegisterFile`] | x86-64 register snapshot |
//! | [`CallFrame`] | Single call-stack frame |
//! | [`MemoryRegion`] | Simulated memory region |
//! | [`DebugSession`] | A complete debug session wrapping a MockDebugger |

#![allow(dead_code)]

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use rhai::{Dynamic, Engine};

use crate::{sat_i64_to_usize, sat_u64_to_usize, sat_usize_to_i64};

// ─────────────────────────────────────────────────────────────────────────────
// DebuggerState
// ─────────────────────────────────────────────────────────────────────────────

/// The execution state of the debugger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebuggerState {
    /// Not yet attached to a process.
    Detached,
    /// Process is running.
    Running,
    /// Process is paused at a breakpoint or after a step.
    Paused,
    /// Process has exited.
    Stopped,
}

impl fmt::Display for DebuggerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Detached => "detached",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Stopped => "stopped",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Breakpoint
// ─────────────────────────────────────────────────────────────────────────────

/// A single address breakpoint.
#[derive(Debug, Clone)]
pub struct Breakpoint {
    /// Virtual address of the breakpoint.
    pub address: u64,
    /// Human-readable label (optional).
    pub label: String,
    /// Whether this breakpoint is currently enabled.
    pub enabled: bool,
    /// Number of times this breakpoint has been hit.
    pub hit_count: u32,
}

impl Breakpoint {
    /// Create a new enabled breakpoint.
    #[must_use]
    pub fn new(address: u64, label: impl Into<String>) -> Self {
        Self {
            address,
            label: label.into(),
            enabled: true,
            hit_count: 0,
        }
    }
}

impl fmt::Display for Breakpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "bp@{:#x} '{}' [{}] hits={}",
            self.address,
            self.label,
            if self.enabled { "on" } else { "off" },
            self.hit_count
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegisterFile
// ─────────────────────────────────────────────────────────────────────────────

/// Snapshot of x86-64 general-purpose and status registers.
#[derive(Debug, Clone, Default)]
pub struct RegisterFile {
    regs: HashMap<String, u64>,
}

impl RegisterFile {
    /// Create a zeroed register file.
    #[must_use]
    pub fn new() -> Self {
        let mut regs = HashMap::new();
        for name in &[
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "r8", "r9", "r10", "r11",
            "r12", "r13", "r14", "r15", "rip", "rflags", "cs", "ss", "ds", "es", "fs", "gs",
        ] {
            regs.insert(name.to_string(), 0u64);
        }
        Self { regs }
    }

    /// Read a register value.
    #[must_use]
    pub fn read(&self, name: &str) -> Option<u64> {
        self.regs.get(name).copied()
    }

    /// Write a register value.
    ///
    /// Returns `false` if the register name is not known.
    pub fn write(&mut self, name: &str, value: u64) -> bool {
        if let Some(r) = self.regs.get_mut(name) {
            *r = value;
            return true;
        }
        false
    }

    /// Return all register names.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.regs.keys().map(String::as_str).collect()
    }

    /// Current instruction pointer.
    #[must_use]
    pub fn rip(&self) -> u64 {
        self.regs.get("rip").copied().unwrap_or(0)
    }

    /// Current stack pointer.
    #[must_use]
    pub fn rsp(&self) -> u64 {
        self.regs.get("rsp").copied().unwrap_or(0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallFrame
// ─────────────────────────────────────────────────────────────────────────────

/// A single frame in the call stack.
#[derive(Debug, Clone)]
pub struct CallFrame {
    /// Virtual address of the frame's return address.
    pub return_address: u64,
    /// Function name (if known).
    pub function_name: String,
    /// Stack pointer for this frame.
    pub frame_sp: u64,
    /// Frame number (0 = innermost).
    pub frame_num: u32,
}

impl CallFrame {
    /// Create a new call frame.
    #[must_use]
    pub fn new(
        frame_num: u32,
        return_address: u64,
        function_name: impl Into<String>,
        sp: u64,
    ) -> Self {
        Self {
            frame_num,
            return_address,
            function_name: function_name.into(),
            frame_sp: sp,
        }
    }
}

impl fmt::Display for CallFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "#{} {:#x} {} (sp={:#x})",
            self.frame_num, self.return_address, self.function_name, self.frame_sp
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryRegion
// ─────────────────────────────────────────────────────────────────────────────

/// A simulated memory region.
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// Base virtual address.
    pub base: u64,
    /// Raw bytes.
    pub data: Vec<u8>,
    /// Region name (e.g. `.text`, `[stack]`).
    pub name: String,
    /// Readable.
    pub readable: bool,
    /// Writable.
    pub writable: bool,
    /// Executable.
    pub executable: bool,
}

impl MemoryRegion {
    /// Create a new region.
    #[must_use]
    pub fn new(base: u64, data: Vec<u8>, name: impl Into<String>) -> Self {
        Self {
            base,
            data,
            name: name.into(),
            readable: true,
            writable: false,
            executable: false,
        }
    }

    /// Return the byte at `va`, or `None` if out of range.
    #[must_use]
    pub fn read_byte(&self, va: u64) -> Option<u8> {
        if va < self.base {
            return None;
        }
        let off = sat_u64_to_usize(va - self.base);
        self.data.get(off).copied()
    }

    /// Read `len` bytes starting at `va`.
    #[must_use]
    pub fn read_bytes(&self, va: u64, len: usize) -> Vec<u8> {
        if va < self.base {
            return Vec::new();
        }
        let off = sat_u64_to_usize(va - self.base);
        let end = (off + len).min(self.data.len());
        if off >= self.data.len() {
            return Vec::new();
        }
        self.data[off..end].to_vec()
    }

    /// Write bytes at `va`. Returns `false` if not writable or out of range.
    pub fn write_bytes(&mut self, va: u64, bytes: &[u8]) -> bool {
        if !self.writable || va < self.base {
            return false;
        }
        let off = sat_u64_to_usize(va - self.base);
        if off + bytes.len() > self.data.len() {
            return false;
        }
        self.data[off..off + bytes.len()].copy_from_slice(bytes);
        true
    }

    /// Size of the region.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if `va` is within this region.
    #[must_use]
    pub const fn contains(&self, va: u64) -> bool {
        va >= self.base && va < self.base + self.data.len() as u64
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MockDebugger
// ─────────────────────────────────────────────────────────────────────────────

/// In-process mock debugger backend.
///
/// Used for testing scripts without a real debugger connection.
#[derive(Debug)]
pub struct MockDebugger {
    state: DebuggerState,
    registers: RegisterFile,
    breakpoints: Vec<Breakpoint>,
    call_stack: Vec<CallFrame>,
    memory: Vec<MemoryRegion>,
    /// Log of all commands executed.
    command_log: Vec<String>,
    /// Step counter.
    step_count: u64,
}

impl MockDebugger {
    /// Create a new mock debugger in the paused state.
    #[must_use]
    pub fn new() -> Self {
        let mut regs = RegisterFile::new();
        regs.write("rip", 0x0040_1000);
        regs.write("rsp", 0x7fff_fff0);
        regs.write("rbp", 0x7fff_fff0);

        // Pre-populate a fake call stack.
        let call_stack = vec![
            CallFrame::new(0, 0x0040_1000, "main", 0x7fff_fff0),
            CallFrame::new(1, 0x0040_0800, "__libc_start_main", 0x7fff_ffd0),
            CallFrame::new(2, 0x0040_0500, "_start", 0x7fff_ffb0),
        ];

        // Pre-populate a fake memory region.
        let mut code = vec![0x55, 0x48, 0x89, 0xE5, 0x90, 0x90, 0xC3];
        code.extend(vec![0u8; 256 - code.len()]);
        let mut mem_region = MemoryRegion::new(0x0040_1000, code, ".text");
        mem_region.executable = true;

        let mut stack = vec![0u8; 256];
        // Encode a fake return address at [rsp].
        stack[0..8].copy_from_slice(&0x0040_0800_u64.to_le_bytes());
        let mut stack_region = MemoryRegion::new(0x7fff_ffb0, stack, "[stack]");
        stack_region.writable = true;
        stack_region.readable = true;

        Self {
            state: DebuggerState::Paused,
            registers: regs,
            breakpoints: Vec::new(),
            call_stack,
            memory: vec![mem_region, stack_region],
            command_log: Vec::new(),
            step_count: 0,
        }
    }

    /// Set a breakpoint at `address`. Returns the breakpoint index.
    pub fn set_breakpoint(&mut self, address: u64) -> usize {
        let label = format!("bp_{address:#x}");
        self.breakpoints.push(Breakpoint::new(address, label));
        self.command_log
            .push(format!("set_breakpoint({address:#x})"));
        self.breakpoints.len() - 1
    }

    /// Remove a breakpoint by index.
    pub fn remove_breakpoint(&mut self, index: usize) -> bool {
        if index < self.breakpoints.len() {
            self.breakpoints.remove(index);
            self.command_log.push(format!("remove_breakpoint({index})"));
            true
        } else {
            false
        }
    }

    /// Read a register value.
    #[must_use]
    pub fn read_register(&self, name: &str) -> Option<u64> {
        self.registers.read(name)
    }

    /// Write a register value.
    pub fn write_register(&mut self, name: &str, value: u64) -> bool {
        self.command_log
            .push(format!("write_register({name}, {value:#x})"));
        self.registers.write(name, value)
    }

    /// Read bytes from memory.
    #[must_use]
    pub fn read_memory(&self, address: u64, len: usize) -> Vec<u8> {
        for region in &self.memory {
            if region.contains(address) {
                return region.read_bytes(address, len);
            }
        }
        vec![0u8; len]
    }

    /// Write bytes to memory.
    pub fn write_memory(&mut self, address: u64, bytes: &[u8]) -> bool {
        self.command_log
            .push(format!("write_memory({address:#x}, {} bytes)", bytes.len()));
        for region in &mut self.memory {
            if region.contains(address) {
                return region.write_bytes(address, bytes);
            }
        }
        false
    }

    /// Single step. Advances RIP by a simulated instruction size.
    pub fn step(&mut self) {
        self.step_count += 1;
        let rip = self.registers.rip();
        // Simulate instruction decode — NOP is 1 byte, others vary.
        let insn_size = {
            let byte = self.read_memory(rip, 1).into_iter().next().unwrap_or(0x90);
            match byte {
                0x90 | 0x55 | 0xC3 => 1, // NOP / PUSH RBP / RET
                0xE8 | 0xE9 => 5, // CALL rel32 / JMP rel32
                _ => 2,
            }
        };
        self.registers.write("rip", rip + insn_size);
        self.state = DebuggerState::Paused;
        self.command_log
            .push(format!("step() => rip={:#x}", rip + insn_size));
    }

    /// Continue execution (transitions to Running then immediately Paused in mock).
    pub fn cont(&mut self) {
        self.state = DebuggerState::Running;
        self.command_log.push("continue()".into());
        // In the mock, immediately hit a breakpoint if any exist.
        if let Some(bp) = self.breakpoints.iter_mut().find(|b| b.enabled) {
            let addr = bp.address;
            bp.hit_count += 1;
            self.registers.write("rip", addr);
            self.state = DebuggerState::Paused;
            self.command_log.push(format!("hit breakpoint @ {addr:#x}"));
        }
    }

    /// Return the current call stack.
    #[must_use]
    pub fn call_stack(&self) -> &[CallFrame] {
        &self.call_stack
    }

    /// Current debugger state.
    #[must_use]
    pub const fn state(&self) -> DebuggerState {
        self.state
    }

    /// Number of step operations performed.
    #[must_use]
    pub const fn step_count(&self) -> u64 {
        self.step_count
    }

    /// Command log (for test verification).
    #[must_use]
    pub fn command_log(&self) -> &[String] {
        &self.command_log
    }

    /// All breakpoints.
    #[must_use]
    pub fn breakpoints(&self) -> &[Breakpoint] {
        &self.breakpoints
    }

    /// Number of breakpoints.
    #[must_use]
    pub const fn breakpoint_count(&self) -> usize {
        self.breakpoints.len()
    }
}

impl Default for MockDebugger {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DebugSession
// ─────────────────────────────────────────────────────────────────────────────

/// A complete debug session wrapping a [`MockDebugger`].
///
/// This is the object that gets exposed to Rhai scripts via the debug API.
#[derive(Debug)]
pub struct DebugSession {
    debugger: Arc<Mutex<MockDebugger>>,
    session_id: String,
}

impl DebugSession {
    /// Create a new session.
    #[must_use]
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            debugger: Arc::new(Mutex::new(MockDebugger::new())),
            session_id: session_id.into(),
        }
    }

    /// Session identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.session_id
    }

    /// Set a breakpoint at `ea`.
    ///
    /// # Panics
    /// Panics if the debugger lock is poisoned.
    #[must_use]
    pub fn set_breakpoint(&self, ea: u64) -> usize {
        self.debugger.lock().unwrap().set_breakpoint(ea)
    }

    /// Read a register.
    ///
    /// # Panics
    /// Panics if the debugger lock is poisoned.
    #[must_use]
    pub fn read_register(&self, name: &str) -> Option<u64> {
        self.debugger.lock().unwrap().read_register(name)
    }

    /// Write a register.
    ///
    /// # Panics
    /// Panics if the debugger lock is poisoned.
    #[must_use]
    pub fn write_register(&self, name: &str, value: u64) -> bool {
        self.debugger.lock().unwrap().write_register(name, value)
    }

    /// Read `len` bytes from `ea`.
    ///
    /// # Panics
    /// Panics if the debugger lock is poisoned.
    #[must_use]
    pub fn read_memory(&self, ea: u64, len: usize) -> Vec<u8> {
        self.debugger.lock().unwrap().read_memory(ea, len)
    }

    /// Write bytes to `ea`.
    ///
    /// # Panics
    /// Panics if the debugger lock is poisoned.
    #[must_use]
    pub fn write_memory(&self, ea: u64, bytes: &[u8]) -> bool {
        self.debugger.lock().unwrap().write_memory(ea, bytes)
    }

    /// Single step.
    ///
    /// # Panics
    /// Panics if the debugger lock is poisoned.
    pub fn step(&self) {
        self.debugger.lock().unwrap().step();
    }

    /// Continue.
    ///
    /// # Panics
    /// Panics if the debugger lock is poisoned.
    pub fn cont(&self) {
        self.debugger.lock().unwrap().cont();
    }

    /// Get the call stack as a vector of strings.
    ///
    /// # Panics
    /// Panics if the debugger lock is poisoned.
    #[must_use]
    pub fn call_stack_strings(&self) -> Vec<String> {
        self.debugger
            .lock()
            .unwrap()
            .call_stack()
            .iter()
            .map(std::string::ToString::to_string)
            .collect()
    }

    /// Current state string.
    ///
    /// # Panics
    /// Panics if the debugger lock is poisoned.
    #[must_use]
    pub fn state_str(&self) -> String {
        self.debugger.lock().unwrap().state().to_string()
    }

    /// Clone the underlying Arc for sharing with Rhai callbacks.
    #[must_use]
    pub fn debugger_arc(&self) -> Arc<Mutex<MockDebugger>> {
        Arc::clone(&self.debugger)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RhaiDebugApi
// ─────────────────────────────────────────────────────────────────────────────

/// Registers all debug-related API functions with a Rhai engine.
///
/// The session is passed in as an `Arc<Mutex<MockDebugger>>` shared
/// between the host and the Rhai script.
pub struct RhaiDebugApi;

impl RhaiDebugApi {
    /// Register all debug functions on `engine` using `session`.
    ///
    /// # Panics
    /// Panics if any debugger lock is poisoned during registration or callback invocation.
    pub fn register(engine: &mut Engine, session: Arc<Mutex<MockDebugger>>) {
        // rhai_set_breakpoint(ea) -> int (index)
        {
            let s = Arc::clone(&session);
            engine.register_fn("rhai_set_breakpoint", move |ea: i64| -> i64 {
                sat_usize_to_i64(s.lock().unwrap().set_breakpoint(ea.cast_unsigned()))
            });
        }

        // rhai_read_register(name) -> int
        {
            let s = Arc::clone(&session);
            engine.register_fn("rhai_read_register", move |name: &str| -> i64 {
                s.lock()
                    .unwrap()
                    .read_register(name)
                    .unwrap_or(0)
                    .cast_signed()
            });
        }

        // rhai_write_register(name, val)
        {
            let s = Arc::clone(&session);
            engine.register_fn("rhai_write_register", move |name: &str, val: i64| -> bool {
                s.lock().unwrap().write_register(name, val.cast_unsigned())
            });
        }

        // rhai_read_memory(ea, len) -> blob
        {
            let s = Arc::clone(&session);
            engine.register_fn("rhai_read_memory", move |ea: i64, len: i64| -> rhai::Blob {
                s.lock()
                    .unwrap()
                    .read_memory(ea.cast_unsigned(), sat_i64_to_usize(len))
            });
        }

        // rhai_write_memory(ea, bytes) -> bool
        {
            let s = Arc::clone(&session);
            engine.register_fn(
                "rhai_write_memory",
                move |ea: i64, bytes: rhai::Blob| -> bool {
                    s.lock().unwrap().write_memory(ea.cast_unsigned(), &bytes)
                },
            );
        }

        // rhai_step()
        {
            let s = Arc::clone(&session);
            engine.register_fn("rhai_step", move || {
                s.lock().unwrap().step();
            });
        }

        // rhai_continue()
        {
            let s = Arc::clone(&session);
            engine.register_fn("rhai_continue", move || {
                s.lock().unwrap().cont();
            });
        }

        // rhai_get_call_stack() -> Array of strings
        {
            let s = Arc::clone(&session);
            engine.register_fn("rhai_get_call_stack", move || -> rhai::Array {
                s.lock()
                    .unwrap()
                    .call_stack()
                    .iter()
                    .map(|f| Dynamic::from(f.to_string()))
                    .collect()
            });
        }

        // rhai_debugger_state() -> string
        {
            let s = Arc::clone(&session);
            engine.register_fn("rhai_debugger_state", move || -> String {
                s.lock().unwrap().state().to_string()
            });
        }

        // rhai_breakpoint_count() -> int
        {
            let s = Arc::clone(&session);
            engine.register_fn("rhai_breakpoint_count", move || -> i64 {
                sat_usize_to_i64(s.lock().unwrap().breakpoint_count())
            });
        }

        // rhai_step_count() -> int
        {
            let s = Arc::clone(&session);
            engine.register_fn("rhai_step_count", move || -> i64 {
                s.lock().unwrap().step_count().cast_signed()
            });
        }

        // rhai_remove_breakpoint(index) -> bool
        {
            let s = Arc::clone(&session);
            engine.register_fn("rhai_remove_breakpoint", move |index: i64| -> bool {
                s.lock().unwrap().remove_breakpoint(sat_i64_to_usize(index))
            });
        }
    }

    /// Register debug API and return the shared debugger for test inspection.
    #[must_use]
    pub fn register_with_session(engine: &mut Engine) -> Arc<Mutex<MockDebugger>> {
        let session = Arc::new(Mutex::new(MockDebugger::new()));
        Self::register(engine, Arc::clone(&session));
        session
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── DebuggerState ─────────────────────────────────────────────────────────

    #[test]
    fn test_debugger_state_display() {
        assert_eq!(DebuggerState::Paused.to_string(), "paused");
        assert_eq!(DebuggerState::Running.to_string(), "running");
        assert_eq!(DebuggerState::Stopped.to_string(), "stopped");
        assert_eq!(DebuggerState::Detached.to_string(), "detached");
    }

    // ── Breakpoint ────────────────────────────────────────────────────────────

    #[test]
    fn test_breakpoint_new() {
        let bp = Breakpoint::new(0x401000, "main");
        assert_eq!(bp.address, 0x401000);
        assert!(bp.enabled);
        assert_eq!(bp.hit_count, 0);
        assert_eq!(bp.label, "main");
    }

    #[test]
    fn test_breakpoint_display() {
        let bp = Breakpoint::new(0x401000, "test");
        assert!(bp.to_string().contains("0x401000"));
        assert!(bp.to_string().contains("test"));
    }

    // ── RegisterFile ──────────────────────────────────────────────────────────

    #[test]
    fn test_register_file_default_zero() {
        let rf = RegisterFile::new();
        assert_eq!(rf.read("rax"), Some(0));
        assert_eq!(rf.read("rip"), Some(0));
    }

    #[test]
    fn test_register_file_write_read() {
        let mut rf = RegisterFile::new();
        assert!(rf.write("rax", 0xDEADBEEF));
        assert_eq!(rf.read("rax"), Some(0xDEADBEEF));
    }

    #[test]
    fn test_register_file_unknown_reg() {
        let mut rf = RegisterFile::new();
        assert!(!rf.write("xyz", 0));
        assert_eq!(rf.read("xyz"), None);
    }

    #[test]
    fn test_register_file_rip_rsp() {
        let mut rf = RegisterFile::new();
        rf.write("rip", 0x401000);
        rf.write("rsp", 0x7fff_ff00);
        assert_eq!(rf.rip(), 0x401000);
        assert_eq!(rf.rsp(), 0x7fff_ff00);
    }

    // ── CallFrame ────────────────────────────────────────────────────────────

    #[test]
    fn test_call_frame_display() {
        let f = CallFrame::new(0, 0x401000, "main", 0x7fff_fff0);
        let s = f.to_string();
        assert!(s.contains("#0"));
        assert!(s.contains("main"));
    }

    // ── MemoryRegion ─────────────────────────────────────────────────────────

    #[test]
    fn test_memory_region_read_byte() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let region = MemoryRegion::new(0x1000, data, ".data");
        assert_eq!(region.read_byte(0x1000), Some(0xDE));
        assert_eq!(region.read_byte(0x1003), Some(0xEF));
        assert_eq!(region.read_byte(0x0FFF), None);
        assert_eq!(region.read_byte(0x1004), None);
    }

    #[test]
    fn test_memory_region_read_bytes() {
        let data = vec![1, 2, 3, 4, 5];
        let region = MemoryRegion::new(0x2000, data, "r");
        let bytes = region.read_bytes(0x2001, 3);
        assert_eq!(bytes, vec![2, 3, 4]);
    }

    #[test]
    fn test_memory_region_write_bytes() {
        let data = vec![0u8; 8];
        let mut region = MemoryRegion::new(0x3000, data, "w");
        region.writable = true;
        assert!(region.write_bytes(0x3000, &[0xAA, 0xBB]));
        assert_eq!(region.read_byte(0x3000), Some(0xAA));
        assert_eq!(region.read_byte(0x3001), Some(0xBB));
    }

    #[test]
    fn test_memory_region_write_not_writable() {
        let data = vec![0u8; 8];
        let mut region = MemoryRegion::new(0x3000, data, "ro");
        // writable = false by default
        assert!(!region.write_bytes(0x3000, &[0xFF]));
    }

    #[test]
    fn test_memory_region_contains() {
        let region = MemoryRegion::new(0x1000, vec![0u8; 256], "test");
        assert!(region.contains(0x1000));
        assert!(region.contains(0x10FF));
        assert!(!region.contains(0x0FFF));
        assert!(!region.contains(0x1100));
    }

    // ── MockDebugger ──────────────────────────────────────────────────────────

    #[test]
    fn test_mock_debugger_initial_state() {
        let dbg = MockDebugger::new();
        assert_eq!(dbg.state(), DebuggerState::Paused);
        assert_eq!(dbg.step_count(), 0);
        assert_eq!(dbg.breakpoint_count(), 0);
    }

    #[test]
    fn test_mock_debugger_set_breakpoint() {
        let mut dbg = MockDebugger::new();
        let idx = dbg.set_breakpoint(0x401010);
        assert_eq!(idx, 0);
        assert_eq!(dbg.breakpoint_count(), 1);
        assert_eq!(dbg.breakpoints()[0].address, 0x401010);
    }

    #[test]
    fn test_mock_debugger_remove_breakpoint() {
        let mut dbg = MockDebugger::new();
        dbg.set_breakpoint(0x401000);
        assert!(dbg.remove_breakpoint(0));
        assert_eq!(dbg.breakpoint_count(), 0);
    }

    #[test]
    fn test_mock_debugger_read_rip() {
        let dbg = MockDebugger::new();
        assert_eq!(dbg.read_register("rip"), Some(0x401000));
    }

    #[test]
    fn test_mock_debugger_write_register() {
        let mut dbg = MockDebugger::new();
        assert!(dbg.write_register("rax", 0x1234));
        assert_eq!(dbg.read_register("rax"), Some(0x1234));
    }

    #[test]
    fn test_mock_debugger_read_memory_code() {
        let dbg = MockDebugger::new();
        let bytes = dbg.read_memory(0x401000, 4);
        // First bytes should be 0x55 0x48 0x89 0xE5 (push rbp; mov rbp,rsp)
        assert_eq!(bytes[0], 0x55);
        assert_eq!(bytes[1], 0x48);
    }

    #[test]
    fn test_mock_debugger_step() {
        let mut dbg = MockDebugger::new();
        let rip_before = dbg.read_register("rip").unwrap();
        dbg.step();
        let rip_after = dbg.read_register("rip").unwrap();
        assert!(rip_after > rip_before);
        assert_eq!(dbg.step_count(), 1);
        assert_eq!(dbg.state(), DebuggerState::Paused);
    }

    #[test]
    fn test_mock_debugger_continue_no_bp() {
        let mut dbg = MockDebugger::new();
        dbg.cont();
        // No breakpoints — stays in Running
        assert_eq!(dbg.state(), DebuggerState::Running);
    }

    #[test]
    fn test_mock_debugger_continue_hits_bp() {
        let mut dbg = MockDebugger::new();
        dbg.set_breakpoint(0x401020);
        dbg.cont();
        assert_eq!(dbg.state(), DebuggerState::Paused);
        assert_eq!(dbg.read_register("rip"), Some(0x401020));
        assert_eq!(dbg.breakpoints()[0].hit_count, 1);
    }

    #[test]
    fn test_mock_debugger_call_stack_nonempty() {
        let dbg = MockDebugger::new();
        assert!(!dbg.call_stack().is_empty());
        assert!(dbg.call_stack()[0].function_name.contains("main"));
    }

    #[test]
    fn test_mock_debugger_command_log() {
        let mut dbg = MockDebugger::new();
        dbg.set_breakpoint(0x401000);
        dbg.step();
        assert!(!dbg.command_log().is_empty());
    }

    // ── DebugSession ──────────────────────────────────────────────────────────

    #[test]
    fn test_debug_session_id() {
        let session = DebugSession::new("test-session");
        assert_eq!(session.id(), "test-session");
    }

    #[test]
    fn test_debug_session_set_breakpoint() {
        let session = DebugSession::new("s");
        let idx = session.set_breakpoint(0x401000);
        assert_eq!(idx, 0);
    }

    #[test]
    fn test_debug_session_read_register() {
        let session = DebugSession::new("s");
        assert_eq!(session.read_register("rip"), Some(0x401000));
    }

    #[test]
    fn test_debug_session_write_register() {
        let session = DebugSession::new("s");
        assert!(session.write_register("rax", 0xABCD));
        assert_eq!(session.read_register("rax"), Some(0xABCD));
    }

    #[test]
    fn test_debug_session_step() {
        let session = DebugSession::new("s");
        session.step();
        assert_eq!(session.state_str(), "paused");
    }

    #[test]
    fn test_debug_session_call_stack_strings() {
        let session = DebugSession::new("s");
        let cs = session.call_stack_strings();
        assert!(!cs.is_empty());
        assert!(cs[0].contains("main"));
    }

    // ── RhaiDebugApi ──────────────────────────────────────────────────────────

    #[test]
    fn test_rhai_debug_api_register() {
        let mut engine = Engine::new();
        let _session = RhaiDebugApi::register_with_session(&mut engine);
        // All functions should be callable without panic.
        let result = engine.eval::<i64>("rhai_breakpoint_count()").unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn test_rhai_set_breakpoint() {
        let mut engine = Engine::new();
        let _session = RhaiDebugApi::register_with_session(&mut engine);
        engine.eval::<i64>("rhai_set_breakpoint(0x401000)").unwrap();
        let count = engine.eval::<i64>("rhai_breakpoint_count()").unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_rhai_read_register() {
        let mut engine = Engine::new();
        let _session = RhaiDebugApi::register_with_session(&mut engine);
        let rip = engine.eval::<i64>("rhai_read_register(\"rip\")").unwrap();
        assert_eq!(rip as u64, 0x401000);
    }

    #[test]
    fn test_rhai_write_register() {
        let mut engine = Engine::new();
        let _session = RhaiDebugApi::register_with_session(&mut engine);
        engine
            .eval::<bool>("rhai_write_register(\"rax\", 999)")
            .unwrap();
        let rax = engine.eval::<i64>("rhai_read_register(\"rax\")").unwrap();
        assert_eq!(rax, 999);
    }

    #[test]
    fn test_rhai_step() {
        let mut engine = Engine::new();
        let _session = RhaiDebugApi::register_with_session(&mut engine);
        engine.eval::<()>("rhai_step()").unwrap();
        let count = engine.eval::<i64>("rhai_step_count()").unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_rhai_read_memory() {
        let mut engine = Engine::new();
        let _session = RhaiDebugApi::register_with_session(&mut engine);
        let bytes = engine
            .eval::<rhai::Blob>("rhai_read_memory(0x401000, 2)")
            .unwrap();
        assert_eq!(bytes.len(), 2);
        assert_eq!(bytes[0], 0x55);
    }

    #[test]
    fn test_rhai_get_call_stack() {
        let mut engine = Engine::new();
        let _session = RhaiDebugApi::register_with_session(&mut engine);
        let stack = engine.eval::<rhai::Array>("rhai_get_call_stack()").unwrap();
        assert!(!stack.is_empty());
    }

    #[test]
    fn test_rhai_debugger_state() {
        let mut engine = Engine::new();
        let _session = RhaiDebugApi::register_with_session(&mut engine);
        let state = engine.eval::<String>("rhai_debugger_state()").unwrap();
        assert_eq!(state, "paused");
    }
}
