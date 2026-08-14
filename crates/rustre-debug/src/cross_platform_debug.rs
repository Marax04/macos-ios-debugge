//! Cross-platform debugger abstraction.
//!
//! Provides a unified API for debugging processes on Linux, Windows, macOS,
//! and remote targets, with breakpoint management, step control, memory
//! inspection, and register inspection.
//!
//! # Structs
//! - [`DebugTarget`]       — target specification (local pid / remote / core)
//! - [`BreakpointManager`] — manages software and hardware breakpoints
//! - [`StepController`]    — controls single-step / step-over / step-out
//! - [`MemoryInspector`]   — reads and displays memory from a target
//! - [`RegisterInspector`] — reads and displays register state
//! - [`CrossPlatformDebug`]— top-level coordinator

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from the cross-platform debugger.
#[derive(Debug, Error)]
pub enum CrossDebugError {
    #[error("not attached")]
    NotAttached,
    #[error("attach failed: {0}")]
    AttachFailed(String),
    #[error("breakpoint at {0:#x} already exists")]
    BreakpointExists(u64),
    #[error("breakpoint at {0:#x} not found")]
    BreakpointNotFound(u64),
    #[error("memory read error at {0:#x}: {1}")]
    MemoryRead(u64, String),
    #[error("memory write error at {0:#x}: {1}")]
    MemoryWrite(u64, String),
    #[error("register error: {0}")]
    Register(String),
    #[error("step error: {0}")]
    Step(String),
    #[error("unsupported on {platform}: {op}")]
    Unsupported { platform: String, op: String },
    #[error("timeout after {0:?}")]
    Timeout(Duration),
    #[error("permission denied: {0}")]
    Permission(String),
    #[error("platform error: {0}")]
    Platform(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// Platform
// ─────────────────────────────────────────────────────────────────────────────

/// Target platform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    Linux,
    Windows,
    MacOs,
    Remote { host: String, port: u16 },
    Core { path: String },
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Linux => write!(f, "linux"),
            Self::Windows => write!(f, "windows"),
            Self::MacOs => write!(f, "macos"),
            Self::Remote { host, port } => write!(f, "remote({host}:{port})"),
            Self::Core { path } => write!(f, "core({path})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Architecture
// ─────────────────────────────────────────────────────────────────────────────

/// CPU architecture of the target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Architecture {
    X86_64,
    X86,
    Aarch64,
    Arm,
    Mips,
    RiscV64,
    Unknown(String),
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::X86_64 => write!(f, "x86_64"),
            Self::X86 => write!(f, "x86"),
            Self::Aarch64 => write!(f, "aarch64"),
            Self::Arm => write!(f, "arm"),
            Self::Mips => write!(f, "mips"),
            Self::RiscV64 => write!(f, "riscv64"),
            Self::Unknown(s) => write!(f, "unknown({s})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DebugTarget
// ─────────────────────────────────────────────────────────────────────────────

/// Specification of the debug target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugTarget {
    /// Platform.
    pub platform: Platform,
    /// Architecture.
    pub arch: Architecture,
    /// Process ID (0 for core/remote).
    pub pid: u32,
    /// Process name.
    pub process_name: String,
    /// Executable path.
    pub executable: Option<String>,
    /// Whether this is a live process.
    pub is_live: bool,
    /// Attached timestamp.
    pub attached_at: Option<SystemTime>,
    /// Session id.
    pub session_id: u64,
}

impl DebugTarget {
    /// Create a local live target.
    #[must_use]
    pub fn local(pid: u32, platform: Platform, arch: Architecture) -> Self {
        Self {
            platform,
            arch,
            pid,
            process_name: format!("pid-{pid}"),
            executable: None,
            is_live: true,
            attached_at: None,
            session_id: 0,
        }
    }

    /// Create a remote target.
    #[must_use]
    pub fn remote(host: impl Into<String>, port: u16, arch: Architecture) -> Self {
        let host = host.into();
        Self {
            platform: Platform::Remote {
                host: host.clone(),
                port,
            },
            arch,
            pid: 0,
            process_name: format!("remote@{host}:{port}"),
            executable: None,
            is_live: true,
            attached_at: None,
            session_id: 0,
        }
    }

    /// Create a core file target.
    #[must_use]
    pub fn core(path: impl Into<String>, arch: Architecture) -> Self {
        let path = path.into();
        Self {
            platform: Platform::Core { path: path.clone() },
            arch,
            pid: 0,
            process_name: format!("core:{path}"),
            executable: None,
            is_live: false,
            attached_at: None,
            session_id: 0,
        }
    }

    /// Mark as attached now.
    pub fn mark_attached(&mut self, session_id: u64) {
        self.attached_at = Some(SystemTime::now());
        self.session_id = session_id;
    }

    /// Whether this target is a core file.
    #[must_use]
    pub const fn is_core(&self) -> bool {
        matches!(self.platform, Platform::Core { .. })
    }

    /// Whether this is a remote target.
    #[must_use]
    pub const fn is_remote(&self) -> bool {
        matches!(self.platform, Platform::Remote { .. })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BreakpointKind
// ─────────────────────────────────────────────────────────────────────────────

/// How a breakpoint is implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BpKind {
    /// Software INT3 (x86/64) or BRK (arm).
    Software,
    /// Hardware execution breakpoint.
    Hardware,
    /// Hardware read watchpoint.
    WatchRead,
    /// Hardware write watchpoint.
    WatchWrite,
    /// Hardware access watchpoint.
    WatchAccess,
}

impl std::fmt::Display for BpKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Software => write!(f, "sw"),
            Self::Hardware => write!(f, "hw-exec"),
            Self::WatchRead => write!(f, "hw-read"),
            Self::WatchWrite => write!(f, "hw-write"),
            Self::WatchAccess => write!(f, "hw-access"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Breakpoint
// ─────────────────────────────────────────────────────────────────────────────

/// A single breakpoint or watchpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Breakpoint {
    pub id: u32,
    pub addr: u64,
    pub kind: BpKind,
    pub enabled: bool,
    pub hit_count: u64,
    pub condition: Option<String>,
    pub original_byte: Option<u8>,
    pub label: Option<String>,
    pub thread_filter: Option<u32>,
}

impl Breakpoint {
    #[must_use]
    pub const fn software(id: u32, addr: u64) -> Self {
        Self {
            id,
            addr,
            kind: BpKind::Software,
            enabled: true,
            hit_count: 0,
            condition: None,
            original_byte: None,
            label: None,
            thread_filter: None,
        }
    }

    #[must_use]
    pub const fn hardware(id: u32, addr: u64) -> Self {
        let mut b = Self::software(id, addr);
        b.kind = BpKind::Hardware;
        b
    }

    #[must_use]
    pub const fn watchpoint(id: u32, addr: u64, kind: BpKind) -> Self {
        let mut b = Self::software(id, addr);
        b.kind = kind;
        b
    }

    #[must_use]
    pub const fn is_watchpoint(&self) -> bool {
        matches!(
            self.kind,
            BpKind::WatchRead | BpKind::WatchWrite | BpKind::WatchAccess
        )
    }

    pub const fn hit(&mut self) {
        self.hit_count += 1;
    }

    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    #[must_use]
    pub fn with_condition(mut self, cond: impl Into<String>) -> Self {
        self.condition = Some(cond.into());
        self
    }

    /// Restrict this breakpoint to one thread (gdb's `break … thread N`).
    #[must_use]
    pub const fn with_thread(mut self, tid: u32) -> Self {
        self.thread_filter = Some(tid);
        self
    }

    /// Whether a hit on `tid` belongs to this breakpoint.
    ///
    /// `thread_filter` was declared on this type and read by nothing, which is
    /// the worst state for a filter to be in: a caller sets it, sees the field
    /// in `breakpoints()`, and keeps stopping on every other thread. In a
    /// server with a worker pool a shared function is hit constantly by threads
    /// the user is not debugging, and the filter existing-but-ignored looks
    /// exactly like a filter that does not work.
    #[must_use]
    pub const fn allows_thread(&self, tid: u32) -> bool {
        match self.thread_filter {
            None => true,
            Some(only) => only == tid,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BreakpointManager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages software and hardware breakpoints.
#[derive(Debug, Default)]
pub struct BreakpointManager {
    breakpoints: HashMap<u64, Breakpoint>,
    next_id: u32,
    pub total_set: u64,
    pub total_hit: u64,
}

impl BreakpointManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a software breakpoint at `addr`.
    ///
    /// # Errors
    /// [`CrossDebugError::BreakpointExists`] if already set.
    pub fn set_software(&mut self, addr: u64) -> Result<u32, CrossDebugError> {
        if self.breakpoints.contains_key(&addr) {
            return Err(CrossDebugError::BreakpointExists(addr));
        }
        let id = self.next_id;
        self.next_id += 1;
        self.breakpoints
            .insert(addr, Breakpoint::software(id, addr));
        self.total_set += 1;
        Ok(id)
    }

    /// Set a hardware execution breakpoint.
    ///
    /// # Errors
    /// Returns [`CrossDebugError::BreakpointExists`] if a breakpoint already exists at `addr`.
    pub fn set_hardware(&mut self, addr: u64) -> Result<u32, CrossDebugError> {
        if self.breakpoints.contains_key(&addr) {
            return Err(CrossDebugError::BreakpointExists(addr));
        }
        let id = self.next_id;
        self.next_id += 1;
        self.breakpoints
            .insert(addr, Breakpoint::hardware(id, addr));
        self.total_set += 1;
        Ok(id)
    }

    /// Set a watchpoint.
    ///
    /// # Errors
    /// Returns [`CrossDebugError::BreakpointExists`] if a breakpoint already exists at `addr`.
    pub fn set_watchpoint(&mut self, addr: u64, kind: BpKind) -> Result<u32, CrossDebugError> {
        if self.breakpoints.contains_key(&addr) {
            return Err(CrossDebugError::BreakpointExists(addr));
        }
        let id = self.next_id;
        self.next_id += 1;
        self.breakpoints
            .insert(addr, Breakpoint::watchpoint(id, addr, kind));
        self.total_set += 1;
        Ok(id)
    }

    /// Remove a breakpoint.
    ///
    /// # Errors
    /// Returns [`CrossDebugError::BreakpointNotFound`] if no breakpoint exists at `addr`.
    pub fn remove(&mut self, addr: u64) -> Result<Breakpoint, CrossDebugError> {
        self.breakpoints
            .remove(&addr)
            .ok_or(CrossDebugError::BreakpointNotFound(addr))
    }

    /// Enable a breakpoint.
    ///
    /// # Errors
    /// Returns [`CrossDebugError::BreakpointNotFound`] if no breakpoint exists at `addr`.
    pub fn enable(&mut self, addr: u64) -> Result<(), CrossDebugError> {
        self.breakpoints
            .get_mut(&addr)
            .ok_or(CrossDebugError::BreakpointNotFound(addr))
            .map(|b| b.enabled = true)
    }

    /// Disable a breakpoint (without removing it).
    ///
    /// # Errors
    /// Returns [`CrossDebugError::BreakpointNotFound`] if no breakpoint exists at `addr`.
    pub fn disable(&mut self, addr: u64) -> Result<(), CrossDebugError> {
        self.breakpoints
            .get_mut(&addr)
            .ok_or(CrossDebugError::BreakpointNotFound(addr))
            .map(|b| b.enabled = false)
    }

    /// Record a hit at `addr`.
    pub fn record_hit(&mut self, addr: u64) {
        if let Some(bp) = self.breakpoints.get_mut(&addr) {
            bp.hit();
            self.total_hit += 1;
        }
    }

    /// All breakpoints.
    #[must_use]
    pub fn all(&self) -> Vec<&Breakpoint> {
        self.breakpoints.values().collect()
    }

    /// Enabled breakpoints.
    #[must_use]
    pub fn enabled(&self) -> Vec<&Breakpoint> {
        self.breakpoints.values().filter(|b| b.enabled).collect()
    }

    /// Lookup by address.
    #[must_use]
    pub fn get(&self, addr: u64) -> Option<&Breakpoint> {
        self.breakpoints.get(&addr)
    }

    /// Number of breakpoints.
    #[must_use]
    pub fn len(&self) -> usize {
        self.breakpoints.len()
    }

    /// Returns `true` if no breakpoints.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.breakpoints.is_empty()
    }

    /// Clear all breakpoints.
    pub fn clear(&mut self) {
        self.breakpoints.clear();
    }

    /// Most-hit breakpoint.
    #[must_use]
    pub fn most_hit(&self) -> Option<&Breakpoint> {
        self.breakpoints.values().max_by_key(|b| b.hit_count)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StepMode
// ─────────────────────────────────────────────────────────────────────────────

/// What kind of step to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepMode {
    /// Execute exactly one machine instruction.
    Instruction,
    /// Execute one source line (may span many instructions).
    SourceLine,
    /// Step over function calls (return to the next instruction after the call).
    Over,
    /// Step out of the current function.
    Out,
}

impl std::fmt::Display for StepMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Instruction => write!(f, "step-instruction"),
            Self::SourceLine => write!(f, "step-source-line"),
            Self::Over => write!(f, "step-over"),
            Self::Out => write!(f, "step-out"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StepEvent
// ─────────────────────────────────────────────────────────────────────────────

/// The result of a single step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepEvent {
    pub mode: StepMode,
    pub new_pc: u64,
    pub tid: u32,
    pub instruction_count: u64,
    pub hit_breakpoint: Option<u64>,
}

impl StepEvent {
    #[must_use]
    pub const fn new(mode: StepMode, new_pc: u64, tid: u32) -> Self {
        Self {
            mode,
            new_pc,
            tid,
            instruction_count: 1,
            hit_breakpoint: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StepController
// ─────────────────────────────────────────────────────────────────────────────

/// Controls single-step / step-over / step-out.
#[derive(Debug, Default)]
pub struct StepController {
    /// Total steps performed.
    pub total_steps: u64,
    /// Step events.
    pub history: Vec<StepEvent>,
    /// Maximum history to retain.
    pub max_history: usize,
    /// Current thread id.
    pub current_tid: u32,
    /// Simulated call depth (for step-over / step-out logic).
    pub call_depth: u32,
}

impl StepController {
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_history: 1000,
            ..Default::default()
        }
    }

    /// Simulate a single-instruction step.
    pub fn step_instruction(&mut self, new_pc: u64) -> StepEvent {
        self.total_steps += 1;
        let ev = StepEvent::new(StepMode::Instruction, new_pc, self.current_tid);
        self.push_event(ev.clone());
        ev
    }

    /// Simulate a step-over (skip call, land on return address).
    pub fn step_over(&mut self, return_addr: u64) -> StepEvent {
        self.total_steps += 1;
        let ev = StepEvent::new(StepMode::Over, return_addr, self.current_tid);
        self.push_event(ev.clone());
        ev
    }

    /// Simulate a step-out (land on return address after pop).
    pub fn step_out(&mut self, return_addr: u64) -> StepEvent {
        self.total_steps += 1;
        self.call_depth = self.call_depth.saturating_sub(1);
        let ev = StepEvent::new(StepMode::Out, return_addr, self.current_tid);
        self.push_event(ev.clone());
        ev
    }

    /// Record a function call (increases depth).
    pub const fn record_call(&mut self) {
        self.call_depth += 1;
    }

    /// Most recent step event.
    #[must_use]
    pub fn latest(&self) -> Option<&StepEvent> {
        self.history.last()
    }

    fn push_event(&mut self, ev: StepEvent) {
        self.history.push(ev);
        if self.history.len() > self.max_history {
            self.history.remove(0);
        }
    }

    pub fn reset(&mut self) {
        self.history.clear();
        self.total_steps = 0;
        self.call_depth = 0;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryRegion
// ─────────────────────────────────────────────────────────────────────────────

/// A virtual memory region in the target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub name: Option<String>,
}

impl MemoryRegion {
    #[must_use]
    pub const fn new(base: u64, size: u64, r: bool, w: bool, x: bool) -> Self {
        Self {
            base,
            size,
            readable: r,
            writable: w,
            executable: x,
            name: None,
        }
    }

    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && (addr - self.base) < self.size
    }

    #[must_use]
    pub fn perms_string(&self) -> String {
        format!(
            "{}{}{}",
            if self.readable { "r" } else { "-" },
            if self.writable { "w" } else { "-" },
            if self.executable { "x" } else { "-" },
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryInspector
// ─────────────────────────────────────────────────────────────────────────────

/// Reads and displays memory from a simulated target address space.
#[derive(Debug, Default)]
pub struct MemoryInspector {
    /// Simulated memory: base → bytes.
    memory: HashMap<u64, Vec<u8>>,
    /// Known memory regions.
    pub regions: Vec<MemoryRegion>,
    /// Total reads performed.
    pub total_reads: u64,
    /// Total writes performed.
    pub total_writes: u64,
}

impl MemoryInspector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Map a memory region.
    pub fn map(&mut self, region: MemoryRegion, data: Vec<u8>) {
        self.memory.insert(region.base, data);
        self.regions.push(region);
    }

    /// Read `size` bytes from `addr`.
    ///
    /// # Errors
    /// [`CrossDebugError::MemoryRead`] if the region is unmapped.
    pub fn read(&mut self, addr: u64, size: usize) -> Result<Vec<u8>, CrossDebugError> {
        self.total_reads += 1;
        for (&base, data) in &self.memory {
            if addr >= base {
                let off = addr - base;
                let Some(end) = off.checked_add(size as u64) else { continue };
                if end <= data.len() as u64 {
                    let off = usize::try_from(off).unwrap_or(usize::MAX);
                    return Ok(data[off..off + size].to_vec());
                }
            }
        }
        Err(CrossDebugError::MemoryRead(addr, "unmapped".into()))
    }

    /// Write `data` to `addr`.
    ///
    /// # Errors
    /// Returns [`CrossDebugError::MemoryWrite`] if the region is unmapped.
    pub fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), CrossDebugError> {
        self.total_writes += 1;
        for (&base, region_data) in &mut self.memory {
            if addr >= base && addr + data.len() as u64 <= base + region_data.len() as u64 {
                let off = usize::try_from(addr - base).unwrap_or(usize::MAX);
                region_data[off..off + data.len()].copy_from_slice(data);
                return Ok(());
            }
        }
        Err(CrossDebugError::MemoryWrite(addr, "unmapped".into()))
    }

    /// Read a `u8` from `addr`.
    ///
    /// # Errors
    /// Returns [`CrossDebugError::MemoryRead`] if the region is unmapped.
    pub fn read_u8(&mut self, addr: u64) -> Result<u8, CrossDebugError> {
        Ok(self.read(addr, 1)?[0])
    }

    /// Read a `u32` LE from `addr`.
    ///
    /// # Errors
    /// Returns [`CrossDebugError::MemoryRead`] if the region is unmapped.
    pub fn read_u32_le(&mut self, addr: u64) -> Result<u32, CrossDebugError> {
        let b = self.read(addr, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a `u64` LE from `addr`.
    ///
    /// # Errors
    /// Returns [`CrossDebugError::MemoryRead`] if the region is unmapped.
    pub fn read_u64_le(&mut self, addr: u64) -> Result<u64, CrossDebugError> {
        let b = self.read(addr, 8)?;
        let arr: [u8; 8] = b.as_slice().try_into().map_err(|_| {
            CrossDebugError::MemoryRead(addr, format!("short read: {} bytes", b.len()))
        })?;
        Ok(u64::from_le_bytes(arr))
    }

    /// Format memory as a classic hex dump string.
    #[must_use]
    pub fn hex_dump(&mut self, addr: u64, size: usize) -> String {
        self.read(addr, size).map_or_else(
            |_| format!("(unreadable: {addr:#x})"),
            |bytes| {
                bytes
                    .chunks(16)
                    .enumerate()
                    .map(|(row, chunk)| {
                        let addr_part = format!("{:#010x}  ", addr + (row * 16) as u64);
                        let hex_part: String = chunk.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02X} "); acc });
                        let ascii_part: String = chunk
                            .iter()
                            .map(|&b| if b.is_ascii_graphic() { b as char } else { '.' })
                            .collect();
                        format!("{addr_part}{hex_part:<48}  {ascii_part}")
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            },
        )
    }

    /// Find a region containing `addr`.
    #[must_use]
    pub fn region_for(&self, addr: u64) -> Option<&MemoryRegion> {
        self.regions.iter().find(|r| r.contains(addr))
    }

    /// Number of mapped regions.
    #[must_use]
    pub const fn region_count(&self) -> usize {
        self.regions.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegisterInspector
// ─────────────────────────────────────────────────────────────────────────────

/// Reads and displays register state.
#[derive(Debug, Default)]
pub struct RegisterInspector {
    /// Register file: thread id → (name → value).
    regs: HashMap<u32, HashMap<String, u64>>,
    pub total_reads: u64,
    pub total_writes: u64,
}

impl RegisterInspector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a register value for thread `tid`.
    pub fn set(&mut self, tid: u32, name: &str, value: u64) {
        self.regs
            .entry(tid)
            .or_default()
            .insert(name.to_string(), value);
        self.total_writes += 1;
    }

    /// Read a register value.
    ///
    /// # Errors
    /// [`CrossDebugError::Register`] if not found.
    pub fn get(&mut self, tid: u32, name: &str) -> Result<u64, CrossDebugError> {
        self.total_reads += 1;
        self.regs
            .get(&tid)
            .and_then(|m| m.get(name))
            .copied()
            .ok_or_else(|| CrossDebugError::Register(format!("{name} not found for tid {tid}")))
    }

    /// All registers for thread `tid`.
    #[must_use]
    pub fn all_for_tid(&self, tid: u32) -> HashMap<String, u64> {
        self.regs.get(&tid).cloned().unwrap_or_default()
    }

    /// Program-counter register names, most specific first.
    ///
    /// One list, used for both reading and writing. When they were separate —
    /// `pc()` accepting three names while every writer hard-coded `"rip"` — an
    /// ARM64 register file ended up holding two program counters, only one of
    /// which the target actually uses.
    const PC_NAMES: [&'static str; 3] = ["rip", "pc", "eip"];

    /// Which program-counter register thread `tid`'s register file uses.
    ///
    /// Falls back to `rip` for an empty file, so a fresh x86-64 thread keeps
    /// its usual name; once any PC is present, that one wins.
    #[must_use]
    pub fn pc_name(&self, tid: u32) -> &'static str {
        self.regs.get(&tid).map_or(Self::PC_NAMES[0], |m| {
            Self::PC_NAMES
                .into_iter()
                .find(|c| m.contains_key(*c))
                .unwrap_or(Self::PC_NAMES[0])
        })
    }

    /// Program counter for thread `tid`.
    ///
    /// # Errors
    /// Returns [`CrossDebugError::Register`] if no program counter register is found.
    pub fn pc(&mut self, tid: u32) -> Result<u64, CrossDebugError> {
        let name = self.pc_name(tid);
        self.get(tid, name)
    }

    /// Set the program counter for thread `tid`, using the name that thread's
    /// register file already uses.
    pub fn set_pc(&mut self, tid: u32, value: u64) {
        let name = self.pc_name(tid);
        self.set(tid, name, value);
    }

    /// Stack pointer for thread `tid`.
    ///
    /// # Errors
    /// Returns [`CrossDebugError::Register`] if no stack pointer register is found.
    pub fn sp(&mut self, tid: u32) -> Result<u64, CrossDebugError> {
        self.get(tid, "rsp")
            .or_else(|_| self.get(tid, "sp"))
            .or_else(|_| self.get(tid, "esp"))
    }

    /// Produce a formatted register dump string.
    #[must_use]
    pub fn dump(&self, tid: u32) -> String {
        let regs = self.all_for_tid(tid);
        let mut pairs: Vec<(&String, &u64)> = regs.iter().collect();
        pairs.sort_by_key(|(k, _)| k.as_str());
        pairs
            .iter()
            .map(|(k, v)| format!("{k:6} = {v:#018x}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// All tracked thread IDs.
    #[must_use]
    pub fn threads(&self) -> Vec<u32> {
        self.regs.keys().copied().collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DebugEvent
// ─────────────────────────────────────────────────────────────────────────────

/// An event emitted during debugging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DebugEventKind {
    Breakpoint { addr: u64 },
    Step { new_pc: u64 },
    Exception { code: u32, addr: u64 },
    ProcessExit { exit_code: i32 },
    ThreadCreate { tid: u32 },
    ThreadExit { tid: u32, exit_code: i32 },
    ModuleLoad { base: u64, name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugEvent {
    pub kind: DebugEventKind,
    pub tid: u32,
    pub timestamp: SystemTime,
}

impl DebugEvent {
    #[must_use]
    pub fn new(kind: DebugEventKind, tid: u32) -> Self {
        Self {
            kind,
            tid,
            timestamp: SystemTime::now(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CrossPlatformDebug
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level cross-platform debugger coordinator.
pub struct CrossPlatformDebug {
    /// Active target.
    pub target: Option<DebugTarget>,
    /// Breakpoint manager.
    pub breakpoints: BreakpointManager,
    /// Step controller.
    pub stepper: StepController,
    /// Memory inspector.
    pub memory: MemoryInspector,
    /// Register inspector.
    pub registers: RegisterInspector,
    /// Event log.
    pub events: Vec<DebugEvent>,
    /// Whether currently attached.
    pub attached: bool,
    /// Session id counter.
    session_counter: u64,
}

impl CrossPlatformDebug {
    #[must_use]
    pub fn new() -> Self {
        Self {
            target: None,
            breakpoints: BreakpointManager::new(),
            stepper: StepController::new(),
            memory: MemoryInspector::new(),
            registers: RegisterInspector::new(),
            events: Vec::new(),
            attached: false,
            session_counter: 1,
        }
    }

    /// Attach to a target.
    ///
    /// # Errors
    /// Returns [`CrossDebugError::AttachFailed`] if the target cannot be attached.
    pub fn attach(&mut self, mut target: DebugTarget) -> Result<(), CrossDebugError> {
        target.mark_attached(self.session_counter);
        self.session_counter += 1;
        self.target = Some(target);
        self.attached = true;
        Ok(())
    }

    /// Detach from the current target.
    ///
    /// # Errors
    /// Returns [`CrossDebugError::NotAttached`] if not currently attached.
    pub const fn detach(&mut self) -> Result<(), CrossDebugError> {
        if !self.attached {
            return Err(CrossDebugError::NotAttached);
        }
        self.attached = false;
        Ok(())
    }

    /// Set a software breakpoint.
    ///
    /// # Errors
    /// Returns [`CrossDebugError::NotAttached`] or [`CrossDebugError::BreakpointExists`].
    pub fn set_breakpoint(&mut self, addr: u64) -> Result<u32, CrossDebugError> {
        if !self.attached {
            return Err(CrossDebugError::NotAttached);
        }
        self.breakpoints.set_software(addr)
    }

    /// Remove a breakpoint.
    ///
    /// # Errors
    /// Returns [`CrossDebugError::BreakpointNotFound`] if no breakpoint exists at `addr`.
    pub fn remove_breakpoint(&mut self, addr: u64) -> Result<(), CrossDebugError> {
        self.breakpoints.remove(addr)?;
        Ok(())
    }

    /// Continue execution (simulated: records a run event).
    ///
    /// # Errors
    /// Returns [`CrossDebugError::NotAttached`] if not currently attached.
    pub fn continue_execution(&mut self, tid: u32) -> Result<(), CrossDebugError> {
        if !self.attached {
            return Err(CrossDebugError::NotAttached);
        }
        // In a real impl we'd resume the process; here we record the resume as
        // a Step event at the thread's current PC so the event log carries
        // per-thread provenance.
        // The thread's real program counter, never a fabricated one: a logged
        // `new_pc: 0` is indistinguishable downstream from a genuine address.
        let pc = self.registers.pc(tid)?;
        self.events
            .push(DebugEvent::new(DebugEventKind::Step { new_pc: pc }, tid));
        Ok(())
    }

    /// Single-step thread `tid` to `new_pc`.
    ///
    /// # Errors
    /// Returns [`CrossDebugError::NotAttached`] if not currently attached.
    pub fn step(&mut self, tid: u32, new_pc: u64) -> Result<StepEvent, CrossDebugError> {
        if !self.attached {
            return Err(CrossDebugError::NotAttached);
        }
        let ev = self.stepper.step_instruction(new_pc);
        self.registers.set_pc(tid, new_pc);
        // Check if we landed on a breakpoint
        if self.breakpoints.get(new_pc).is_some() {
            self.breakpoints.record_hit(new_pc);
            self.events.push(DebugEvent::new(
                DebugEventKind::Breakpoint { addr: new_pc },
                tid,
            ));
        }
        Ok(ev)
    }

    /// Step over a call instruction; `return_addr` is the address after the call.
    ///
    /// # Errors
    /// Returns [`CrossDebugError::NotAttached`] if not currently attached.
    pub fn step_over(&mut self, tid: u32, return_addr: u64) -> Result<StepEvent, CrossDebugError> {
        if !self.attached {
            return Err(CrossDebugError::NotAttached);
        }
        let ev = self.stepper.step_over(return_addr);
        // Track the thread the step belongs to so consumers can correlate
        // events back to the originating thread.
        self.registers.set_pc(tid, return_addr);
        self.events.push(DebugEvent::new(
            DebugEventKind::Step {
                new_pc: return_addr,
            },
            tid,
        ));
        Ok(ev)
    }

    /// Step out of the current function.
    ///
    /// # Errors
    /// Returns [`CrossDebugError::NotAttached`] if not currently attached.
    pub fn step_out(&mut self, tid: u32, return_addr: u64) -> Result<StepEvent, CrossDebugError> {
        if !self.attached {
            return Err(CrossDebugError::NotAttached);
        }
        let ev = self.stepper.step_out(return_addr);
        self.registers.set_pc(tid, return_addr);
        self.events.push(DebugEvent::new(
            DebugEventKind::Step {
                new_pc: return_addr,
            },
            tid,
        ));
        Ok(ev)
    }

    /// Read memory.
    ///
    /// # Errors
    /// Returns [`CrossDebugError::NotAttached`] or [`CrossDebugError::MemoryRead`].
    pub fn read_memory(&mut self, addr: u64, size: usize) -> Result<Vec<u8>, CrossDebugError> {
        if !self.attached {
            return Err(CrossDebugError::NotAttached);
        }
        self.memory.read(addr, size)
    }

    /// Write memory.
    ///
    /// # Errors
    /// Returns [`CrossDebugError::NotAttached`] or [`CrossDebugError::MemoryWrite`].
    pub fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), CrossDebugError> {
        if !self.attached {
            return Err(CrossDebugError::NotAttached);
        }
        self.memory.write(addr, data)
    }

    /// Read a register.
    ///
    /// # Errors
    /// Returns [`CrossDebugError::Register`] if the register is not found.
    pub fn read_register(&mut self, tid: u32, name: &str) -> Result<u64, CrossDebugError> {
        self.registers.get(tid, name)
    }

    /// Set a register.
    pub fn write_register(&mut self, tid: u32, name: &str, value: u64) {
        self.registers.set(tid, name, value);
    }

    /// Emit a debug event.
    pub fn emit_event(&mut self, ev: DebugEvent) {
        self.events.push(ev);
    }

    /// Number of events emitted.
    #[must_use]
    pub const fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Current target.
    #[must_use]
    pub const fn target(&self) -> Option<&DebugTarget> {
        self.target.as_ref()
    }
}

impl Default for CrossPlatformDebug {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_target() -> DebugTarget {
        DebugTarget::local(1234, Platform::Linux, Architecture::X86_64)
    }

    // ── Platform / Architecture display ──────────────────────────────────────

    #[test]
    fn platform_display() {
        assert_eq!(Platform::Linux.to_string(), "linux");
        assert_eq!(Platform::Windows.to_string(), "windows");
        assert_eq!(Platform::MacOs.to_string(), "macos");
        let r = Platform::Remote {
            host: "192.168.1.1".into(),
            port: 1234,
        };
        assert!(r.to_string().contains("remote"));
    }

    #[test]
    fn architecture_display() {
        assert_eq!(Architecture::X86_64.to_string(), "x86_64");
        assert_eq!(Architecture::Aarch64.to_string(), "aarch64");
    }

    // ── DebugTarget ───────────────────────────────────────────────────────────

    #[test]
    fn debug_target_local() {
        let t = make_target();
        assert_eq!(t.pid, 1234);
        assert!(t.is_live);
        assert!(!t.is_core());
        assert!(!t.is_remote());
    }

    #[test]
    fn debug_target_remote() {
        let t = DebugTarget::remote("10.0.0.1", 4444, Architecture::X86_64);
        assert!(t.is_remote());
        assert!(t.is_live);
    }

    #[test]
    fn debug_target_core() {
        let t = DebugTarget::core("/tmp/core.1234", Architecture::X86_64);
        assert!(t.is_core());
        assert!(!t.is_live);
    }

    #[test]
    fn debug_target_mark_attached() {
        let mut t = make_target();
        t.mark_attached(42);
        assert_eq!(t.session_id, 42);
        assert!(t.attached_at.is_some());
    }

    // ── BpKind ────────────────────────────────────────────────────────────────

    #[test]
    fn bp_kind_display() {
        assert_eq!(BpKind::Software.to_string(), "sw");
        assert_eq!(BpKind::Hardware.to_string(), "hw-exec");
        assert_eq!(BpKind::WatchWrite.to_string(), "hw-write");
    }

    // ── Breakpoint ────────────────────────────────────────────────────────────

    #[test]
    fn breakpoint_software() {
        let b = Breakpoint::software(1, 0x1000);
        assert_eq!(b.kind, BpKind::Software);
        assert!(b.enabled);
        assert!(!b.is_watchpoint());
    }

    #[test]
    fn breakpoint_watchpoint() {
        let b = Breakpoint::watchpoint(1, 0x4000, BpKind::WatchWrite);
        assert!(b.is_watchpoint());
    }

    #[test]
    fn breakpoint_hit_increments() {
        let mut b = Breakpoint::software(1, 0x1000);
        b.hit();
        b.hit();
        assert_eq!(b.hit_count, 2);
    }

    #[test]
    fn breakpoint_with_label_and_condition() {
        let b = Breakpoint::software(1, 0x1000)
            .with_label("entry")
            .with_condition("rax == 0");
        assert_eq!(b.label.as_deref(), Some("entry"));
        assert_eq!(b.condition.as_deref(), Some("rax == 0"));
    }

    // ── BreakpointManager ─────────────────────────────────────────────────────

    #[test]
    fn bp_manager_set_and_get() {
        let mut m = BreakpointManager::new();
        let _id = m.set_software(0x1000).unwrap();
        assert_eq!(m.len(), 1);
        assert!(m.get(0x1000).is_some());
        assert_eq!(m.total_set, 1);
    }

    #[test]
    fn bp_manager_duplicate_error() {
        let mut m = BreakpointManager::new();
        m.set_software(0x1000).unwrap();
        assert!(matches!(
            m.set_software(0x1000).unwrap_err(),
            CrossDebugError::BreakpointExists(_)
        ));
    }

    #[test]
    fn bp_manager_remove() {
        let mut m = BreakpointManager::new();
        m.set_software(0x1000).unwrap();
        m.remove(0x1000).unwrap();
        assert!(m.is_empty());
    }

    #[test]
    fn bp_manager_enable_disable() {
        let mut m = BreakpointManager::new();
        m.set_software(0x1000).unwrap();
        m.disable(0x1000).unwrap();
        assert_eq!(m.enabled().len(), 0);
        m.enable(0x1000).unwrap();
        assert_eq!(m.enabled().len(), 1);
    }

    #[test]
    fn bp_manager_record_hit() {
        let mut m = BreakpointManager::new();
        m.set_software(0x1000).unwrap();
        m.record_hit(0x1000);
        assert_eq!(m.get(0x1000).unwrap().hit_count, 1);
        assert_eq!(m.total_hit, 1);
    }

    #[test]
    fn bp_manager_most_hit() {
        let mut m = BreakpointManager::new();
        m.set_software(0x1000).unwrap();
        m.set_software(0x2000).unwrap();
        m.record_hit(0x2000);
        m.record_hit(0x2000);
        assert_eq!(m.most_hit().unwrap().addr, 0x2000);
    }

    // ── StepController ────────────────────────────────────────────────────────

    #[test]
    fn step_instruction() {
        let mut s = StepController::new();
        let ev = s.step_instruction(0x1005);
        assert_eq!(ev.new_pc, 0x1005);
        assert_eq!(ev.mode, StepMode::Instruction);
        assert_eq!(s.total_steps, 1);
    }

    #[test]
    fn step_over() {
        let mut s = StepController::new();
        let ev = s.step_over(0x100A);
        assert_eq!(ev.mode, StepMode::Over);
        assert_eq!(ev.new_pc, 0x100A);
    }

    #[test]
    fn step_out() {
        let mut s = StepController::new();
        s.record_call();
        let ev = s.step_out(0x100A);
        assert_eq!(ev.mode, StepMode::Out);
        assert_eq!(s.call_depth, 0);
    }

    #[test]
    fn step_history() {
        let mut s = StepController::new();
        s.step_instruction(0x1000);
        s.step_instruction(0x1005);
        assert_eq!(s.history.len(), 2);
        assert_eq!(s.latest().unwrap().new_pc, 0x1005);
    }

    // ── MemoryInspector ───────────────────────────────────────────────────────

    #[test]
    fn memory_inspector_read() {
        let mut m = MemoryInspector::new();
        m.map(
            MemoryRegion::new(0x1000, 16, true, false, false),
            vec![0xDE; 16],
        );
        let bytes = m.read(0x1000, 4).unwrap();
        assert_eq!(bytes, vec![0xDE; 4]);
    }

    #[test]
    fn memory_inspector_write() {
        let mut m = MemoryInspector::new();
        m.map(
            MemoryRegion::new(0x1000, 16, true, true, false),
            vec![0u8; 16],
        );
        m.write(0x1002, &[0xAA, 0xBB]).unwrap();
        let r = m.read(0x1002, 2).unwrap();
        assert_eq!(r, vec![0xAA, 0xBB]);
    }

    #[test]
    fn memory_inspector_read_unmapped() {
        let mut m = MemoryInspector::new();
        assert!(matches!(
            m.read(0xDEAD_0000, 4).unwrap_err(),
            CrossDebugError::MemoryRead(_, _)
        ));
    }

    #[test]
    fn memory_inspector_read_u32() {
        let mut m = MemoryInspector::new();
        let val: u32 = 0xDEAD_BEEF;
        let data = val.to_le_bytes().to_vec();
        m.map(MemoryRegion::new(0x2000, 4, true, false, false), data);
        assert_eq!(m.read_u32_le(0x2000).unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn memory_inspector_region_for() {
        let mut m = MemoryInspector::new();
        m.map(
            MemoryRegion::new(0x1000, 0x100, true, false, false),
            vec![0u8; 0x100],
        );
        assert!(m.region_for(0x1050).is_some());
        assert!(m.region_for(0x2000).is_none());
    }

    #[test]
    fn memory_inspector_hex_dump() {
        let mut m = MemoryInspector::new();
        m.map(
            MemoryRegion::new(0x1000, 32, true, false, false),
            vec![0x41u8; 32],
        );
        let dump = m.hex_dump(0x1000, 16);
        assert!(dump.contains("41"));
        assert!(dump.contains('A')); // ASCII 'A'
    }

    // ── RegisterInspector ─────────────────────────────────────────────────────

    #[test]
    fn register_inspector_set_get() {
        let mut r = RegisterInspector::new();
        r.set(1, "rax", 0xDEAD_BEEF);
        assert_eq!(r.get(1, "rax").unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn register_inspector_get_unknown() {
        let mut r = RegisterInspector::new();
        assert!(matches!(
            r.get(1, "rax").unwrap_err(),
            CrossDebugError::Register(_)
        ));
    }

    #[test]
    fn register_inspector_pc() {
        let mut r = RegisterInspector::new();
        r.set(1, "rip", 0x4000);
        assert_eq!(r.pc(1).unwrap(), 0x4000);
    }

    #[test]
    fn register_inspector_dump() {
        let mut r = RegisterInspector::new();
        r.set(1, "rax", 0x1234);
        r.set(1, "rbx", 0x5678);
        let dump = r.dump(1);
        assert!(dump.contains("rax"));
        assert!(dump.contains("rbx"));
    }

    #[test]
    fn register_inspector_threads() {
        let mut r = RegisterInspector::new();
        r.set(1, "rax", 0x1);
        r.set(2, "rax", 0x2);
        let tids = r.threads();
        assert!(tids.contains(&1));
        assert!(tids.contains(&2));
    }

    // ── CrossPlatformDebug ────────────────────────────────────────────────────

    #[test]
    fn debug_attach_and_detach() {
        let mut d = CrossPlatformDebug::new();
        d.attach(make_target()).unwrap();
        assert!(d.attached);
        d.detach().unwrap();
        assert!(!d.attached);
    }

    #[test]
    fn debug_detach_not_attached_error() {
        let mut d = CrossPlatformDebug::new();
        assert!(matches!(
            d.detach().unwrap_err(),
            CrossDebugError::NotAttached
        ));
    }

    #[test]
    fn debug_set_breakpoint() {
        let mut d = CrossPlatformDebug::new();
        d.attach(make_target()).unwrap();
        let _id = d.set_breakpoint(0x1000).unwrap();
        assert!(d.breakpoints.get(0x1000).is_some());
    }

    #[test]
    fn debug_step() {
        let mut d = CrossPlatformDebug::new();
        d.attach(make_target()).unwrap();
        d.registers.set(1, "rip", 0x1000);
        let ev = d.step(1, 0x1005).unwrap();
        assert_eq!(ev.new_pc, 0x1005);
        assert_eq!(d.registers.get(1, "rip").unwrap(), 0x1005);
    }

    /// Stepping must update the program counter the TARGET uses, not always
    /// `rip`.
    ///
    /// `RegisterInspector::pc` already accepts `rip`, `pc` or `eip`, so this
    /// type claims to serve more than x86-64 — but every stepping method wrote
    /// the literal `"rip"`. On an ARM64 thread that produced two program
    /// counters in one register file: a fresh `rip` nobody on that target reads,
    /// and the real `pc`, left at its stale pre-step value. `continue_execution`
    /// then read `rip` with `unwrap_or(0)` and logged `Step { new_pc: 0 }` —
    /// a fabricated address, indistinguishable from a real one downstream.
    #[test]
    fn stepping_updates_the_program_counter_the_target_actually_uses() {
        let mut d = CrossPlatformDebug::new();
        d.attach(make_target()).unwrap();
        // An ARM64-style register file: the program counter is `pc`.
        d.registers.set(1, "pc", 0x1000);

        d.step(1, 0x1004).unwrap();
        assert_eq!(
            d.registers.get(1, "pc").unwrap(),
            0x1004,
            "the target's own program counter must advance"
        );
        assert!(
            d.registers.get(1, "rip").is_err(),
            "an x86 register must not be invented in an ARM64 register file"
        );

        d.step_over(1, 0x1008).unwrap();
        assert_eq!(d.registers.get(1, "pc").unwrap(), 0x1008);
        d.step_out(1, 0x100C).unwrap();
        assert_eq!(d.registers.get(1, "pc").unwrap(), 0x100C);

        // And the resume event must carry the real PC, never a fabricated 0.
        d.continue_execution(1).unwrap();
        let last = d.events.last().expect("resume event");
        match last.kind {
            DebugEventKind::Step { new_pc } => {
                assert_eq!(new_pc, 0x100C, "resume logged a fabricated PC");
            }
            ref other => panic!("expected a Step event, got {other:?}"),
        }
    }

    #[test]
    fn debug_step_hits_breakpoint() {
        let mut d = CrossPlatformDebug::new();
        d.attach(make_target()).unwrap();
        d.set_breakpoint(0x1005).unwrap();
        d.step(1, 0x1005).unwrap();
        assert_eq!(d.breakpoints.get(0x1005).unwrap().hit_count, 1);
        assert_eq!(d.event_count(), 1);
    }

    #[test]
    fn debug_read_write_memory() {
        let mut d = CrossPlatformDebug::new();
        d.attach(make_target()).unwrap();
        d.memory.map(
            MemoryRegion::new(0x1000, 16, true, true, false),
            vec![0u8; 16],
        );
        d.write_memory(0x1000, &[0xAA, 0xBB, 0xCC]).unwrap();
        let r = d.read_memory(0x1000, 3).unwrap();
        assert_eq!(r, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn debug_read_write_register() {
        let mut d = CrossPlatformDebug::new();
        d.attach(make_target()).unwrap();
        d.write_register(1, "rax", 0x1234);
        assert_eq!(d.read_register(1, "rax").unwrap(), 0x1234);
    }

    /// `thread_filter` used to be a field nothing read. A breakpoint
    /// restricted to one thread must accept only that thread's hits, and an
    /// unrestricted one must keep accepting every thread — the second half
    /// matters just as much, because a filter that defaults to "nobody"
    /// silences every breakpoint in the process.
    #[test]
    fn a_thread_restricted_breakpoint_accepts_only_that_thread() {
        let bp = Breakpoint::software(1, 0x1000).with_thread(7);
        assert!(bp.allows_thread(7));
        assert!(!bp.allows_thread(8), "a hit on thread 8 is not this breakpoint's hit");
        assert_eq!(bp.thread_filter, Some(7));

        let unrestricted = Breakpoint::software(2, 0x2000);
        assert!(unrestricted.allows_thread(7));
        assert!(unrestricted.allows_thread(8));
        assert!(unrestricted.allows_thread(0));
    }
}
