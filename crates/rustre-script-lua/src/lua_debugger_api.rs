//! `lua_debugger_api` — Debugger control API exposed to Lua scripts.
//!
//! Provides a simulated debug session that Lua scripts can drive via the
//! `dbg.*` namespace.  The design mirrors a real ptrace / windbg integration
//! but all process I/O is stubbed so the module compiles without any native
//! debugger dependency.
//!
//! # Lua namespace: `dbg`
//!
//! | Function | Description |
//! |---|---|
//! | `dbg.attach(pid)` | Attach to a process by PID |
//! | `dbg.detach(session_id)` | Detach and clean up |
//! | `dbg.set_breakpoint(session_id, addr)` | Set software breakpoint |
//! | `dbg.remove_breakpoint(session_id, addr)` | Remove breakpoint |
//! | `dbg.run(session_id)` | Continue execution |
//! | `dbg.step_into(session_id)` | Single-step (into calls) |
//! | `dbg.step_over(session_id)` | Step over calls |
//! | `dbg.step_out(session_id)` | Run until function return |
//! | `dbg.get_registers(session_id)` | Return register table |
//! | `dbg.set_register(session_id, name, value)` | Modify a register |
//! | `dbg.read_memory(session_id, addr, size)` | Read process memory |
//! | `dbg.write_memory(session_id, addr, hex_str)` | Write process memory |
//! | `dbg.get_stack_trace(session_id)` | Return call stack frames |
//! | `dbg.evaluate(session_id, expr)` | Evaluate a simple expression |
//! | `dbg.set_watchpoint(session_id, addr, size, type)` | Set memory watchpoint |

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::{LuaError, LuaValue};

// ── Watchpoint type ───────────────────────────────────────────────────────────

/// The kind of access that triggers a watchpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchKind {
    Read,
    Write,
    ReadWrite,
    Execute,
}

impl WatchKind {
    fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "r" | "read" => Self::Read,
            "rw" | "read_write" | "readwrite" => Self::ReadWrite,
            "x" | "exec" | "execute" => Self::Execute,
            _ => Self::Write,
        }
    }
}

impl std::fmt::Display for WatchKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read => write!(f, "read"),
            Self::Write => write!(f, "write"),
            Self::ReadWrite => write!(f, "read_write"),
            Self::Execute => write!(f, "execute"),
        }
    }
}

// ── Breakpoint ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Breakpoint {
    pub addr: u64,
    pub original_byte: u8,
    pub hit_count: u64,
    pub enabled: bool,
}

// ── Watchpoint ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Watchpoint {
    pub addr: u64,
    pub size: usize,
    pub kind: WatchKind,
    pub hit_count: u64,
}

// ── Register file ─────────────────────────────────────────────────────────────

/// x86-64 general-purpose register file.
#[derive(Debug, Clone)]
pub struct RegisterFile {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub cs: u16,
    pub ss: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
}

impl Default for RegisterFile {
    fn default() -> Self {
        Self {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0x7fff_0000,
            rsp: 0x7ffe_ff00,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0x1400,
            rflags: 0x202,
            cs: 0x33,
            ss: 0x2b,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
        }
    }
}

impl RegisterFile {
    fn get(&self, name: &str) -> Option<u64> {
        match name.to_lowercase().as_str() {
            "rax" => Some(self.rax),
            "rbx" => Some(self.rbx),
            "rcx" => Some(self.rcx),
            "rdx" => Some(self.rdx),
            "rsi" => Some(self.rsi),
            "rdi" => Some(self.rdi),
            "rbp" => Some(self.rbp),
            "rsp" => Some(self.rsp),
            "r8" => Some(self.r8),
            "r9" => Some(self.r9),
            "r10" => Some(self.r10),
            "r11" => Some(self.r11),
            "r12" => Some(self.r12),
            "r13" => Some(self.r13),
            "r14" => Some(self.r14),
            "r15" => Some(self.r15),
            "rip" | "pc" | "eip" | "ip" => Some(self.rip),
            "rflags" | "eflags" | "flags" => Some(self.rflags),
            _ => None,
        }
    }

    fn set(&mut self, name: &str, value: u64) -> bool {
        match name.to_lowercase().as_str() {
            "rax" => self.rax = value,
            "rbx" => self.rbx = value,
            "rcx" => self.rcx = value,
            "rdx" => self.rdx = value,
            "rsi" => self.rsi = value,
            "rdi" => self.rdi = value,
            "rbp" => self.rbp = value,
            "rsp" => self.rsp = value,
            "r8" => self.r8 = value,
            "r9" => self.r9 = value,
            "r10" => self.r10 = value,
            "r11" => self.r11 = value,
            "r12" => self.r12 = value,
            "r13" => self.r13 = value,
            "r14" => self.r14 = value,
            "r15" => self.r15 = value,
            "rip" | "pc" => self.rip = value,
            "rflags" => self.rflags = value,
            _ => return false,
        }
        true
    }

    fn to_lua_table(&self) -> LuaValue {
        LuaValue::Table(vec![
            (LuaValue::String("rax".into()), LuaValue::Int(crate::casts::u64_to_i64(self.rax))),
            (LuaValue::String("rbx".into()), LuaValue::Int(crate::casts::u64_to_i64(self.rbx))),
            (LuaValue::String("rcx".into()), LuaValue::Int(crate::casts::u64_to_i64(self.rcx))),
            (LuaValue::String("rdx".into()), LuaValue::Int(crate::casts::u64_to_i64(self.rdx))),
            (LuaValue::String("rsi".into()), LuaValue::Int(crate::casts::u64_to_i64(self.rsi))),
            (LuaValue::String("rdi".into()), LuaValue::Int(crate::casts::u64_to_i64(self.rdi))),
            (LuaValue::String("rbp".into()), LuaValue::Int(crate::casts::u64_to_i64(self.rbp))),
            (LuaValue::String("rsp".into()), LuaValue::Int(crate::casts::u64_to_i64(self.rsp))),
            (LuaValue::String("rip".into()), LuaValue::Int(crate::casts::u64_to_i64(self.rip))),
            (LuaValue::String("rflags".into()), LuaValue::Int(crate::casts::u64_to_i64(self.rflags))),
            (LuaValue::String("r8".into()), LuaValue::Int(crate::casts::u64_to_i64(self.r8))),
            (LuaValue::String("r9".into()), LuaValue::Int(crate::casts::u64_to_i64(self.r9))),
            (LuaValue::String("r10".into()), LuaValue::Int(crate::casts::u64_to_i64(self.r10))),
            (LuaValue::String("r11".into()), LuaValue::Int(crate::casts::u64_to_i64(self.r11))),
            (LuaValue::String("r12".into()), LuaValue::Int(crate::casts::u64_to_i64(self.r12))),
            (LuaValue::String("r13".into()), LuaValue::Int(crate::casts::u64_to_i64(self.r13))),
            (LuaValue::String("r14".into()), LuaValue::Int(crate::casts::u64_to_i64(self.r14))),
            (LuaValue::String("r15".into()), LuaValue::Int(crate::casts::u64_to_i64(self.r15))),
        ])
    }
}

// ── Stack frame ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StackFrame {
    pub frame_index: usize,
    pub return_addr: u64,
    pub frame_ptr: u64,
    pub function_name: String,
}

// ── Debug session ─────────────────────────────────────────────────────────────

/// State of a debug session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Running,
    Stopped,
    Terminated,
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => write!(f, "running"),
            Self::Stopped => write!(f, "stopped"),
            Self::Terminated => write!(f, "terminated"),
        }
    }
}

/// A live debug session.
#[derive(Debug)]
pub struct DebugSession {
    pub id: String,
    pub pid: u32,
    pub state: SessionState,
    pub regs: RegisterFile,
    /// Software breakpoints indexed by address.
    pub breakpoints: HashMap<u64, Breakpoint>,
    /// Watchpoints.
    pub watchpoints: Vec<Watchpoint>,
    /// Simulated memory pages: `page_base` → 4096 bytes.
    pub memory: HashMap<u64, Vec<u8>>,
    /// Step counter (used to simulate RIP advancement).
    pub step_count: u64,
    /// Simulated call stack (most recent first).
    pub call_stack: Vec<StackFrame>,
}

impl DebugSession {
    fn new(pid: u32) -> Self {
        let id = format!("dbg-{pid}");
        let mut mem = HashMap::new();
        // Map a stub code page so memory reads return something sensible.
        let code: Vec<u8> = (0u8..=255u8).cycle().take(4096).collect();
        mem.insert(0x1000, code);
        // Stack page.
        mem.insert(0x7ffe_f000u64, vec![0u8; 4096]);
        Self {
            id,
            pid,
            state: SessionState::Running,
            regs: RegisterFile::default(),
            breakpoints: HashMap::new(),
            watchpoints: Vec::new(),
            memory: mem,
            step_count: 0,
            call_stack: vec![StackFrame {
                frame_index: 0,
                return_addr: 0,
                frame_ptr: 0x7fff_0000,
                function_name: "<entry>".into(),
            }],
        }
    }

    fn read_memory(&self, addr: u64, size: usize) -> Option<Vec<u8>> {
        let page = addr & !0xfff;
        let off = (addr & 0xfff) as usize;
        self.memory.get(&page).and_then(|p| {
            if off + size <= p.len() {
                Some(p[off..off + size].to_vec())
            } else {
                None
            }
        })
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> bool {
        let page = addr & !0xfff;
        let off = (addr & 0xfff) as usize;
        if let Some(p) = self.memory.get_mut(&page) {
            let end = (off + data.len()).min(p.len());
            if off < p.len() {
                p[off..end].copy_from_slice(&data[..end - off]);
                return true;
            }
        }
        false
    }

    fn advance_rip(&mut self) {
        self.regs.rip = self.regs.rip.wrapping_add(3);
        self.step_count += 1;
        // Hit a breakpoint?
        if self.breakpoints.contains_key(&self.regs.rip) {
            self.state = SessionState::Stopped;
            if let Some(bp) = self.breakpoints.get_mut(&self.regs.rip) {
                bp.hit_count += 1;
            }
        }
    }
}

// ── Session store ─────────────────────────────────────────────────────────────

fn session_store() -> &'static Mutex<HashMap<String, DebugSession>> {
    static S: OnceLock<Mutex<HashMap<String, DebugSession>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

// ── API handlers ──────────────────────────────────────────────────────────────

/// `dbg.attach(pid) → session_id:string`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn attach(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let pid = crate::casts::i64_to_u32(args
        .first()
        .and_then(LuaValue::as_int)
        .ok_or_else(|| LuaError::RuntimeError("attach: expected integer pid".into()))?);
    let session = DebugSession::new(pid);
    let id = session.id.clone();
    session_store()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(id.clone(), session);
    Ok(LuaValue::String(id))
}

/// `dbg.detach(session_id) → bool`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn detach(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_session_id(args)?;
    let removed = session_store()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&id)
        .is_some();
    Ok(LuaValue::Bool(removed))
}

/// `dbg.set_breakpoint(session_id, addr) → bool`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn set_breakpoint(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_session_id(args)?;
    let addr = crate::casts::i64_to_u64(args.get(1).and_then(LuaValue::as_int).unwrap_or(0));
    let mut guard = session_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let session = guard
        .get_mut(&id)
        .ok_or_else(|| LuaError::RuntimeError(format!("set_breakpoint: unknown session {id}")))?;
    let orig = session
        .read_memory(addr, 1)
        .and_then(|b| b.first().copied())
        .unwrap_or(0xcc);
    session.breakpoints.insert(
        addr,
        Breakpoint {
            addr,
            original_byte: orig,
            hit_count: 0,
            enabled: true,
        },
    );
    // Write INT3.
    session.write_memory(addr, &[0xcc]);
    drop(guard);
    Ok(LuaValue::Bool(true))
}

/// `dbg.remove_breakpoint(session_id, addr) → bool`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn remove_breakpoint(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_session_id(args)?;
    let addr = crate::casts::i64_to_u64(args.get(1).and_then(LuaValue::as_int).unwrap_or(0));
    let mut guard = session_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let session = guard
        .get_mut(&id)
        .ok_or_else(|| LuaError::RuntimeError(format!("remove_breakpoint: unknown session {id}")))?;
    let removed = session.breakpoints.remove(&addr).is_some_and(|bp| {
        session.write_memory(addr, &[bp.original_byte]);
        true
    });
    drop(guard);
    Ok(LuaValue::Bool(removed))
}

/// `dbg.run(session_id) → string`  (new state)
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn run(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_session_id(args)?;
    let mut guard = session_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let session = guard
        .get_mut(&id)
        .ok_or_else(|| LuaError::RuntimeError(format!("run: unknown session {id}")))?;
    session.state = SessionState::Running;
    // Simulate advancing to next breakpoint or running 100 steps.
    for _ in 0..100 {
        session.advance_rip();
        if session.state == SessionState::Stopped {
            break;
        }
    }
    let state_str = session.state.to_string();
    drop(guard);
    Ok(LuaValue::String(state_str))
}

/// `dbg.step_into(session_id) → table`  (register snapshot)
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn step_into(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_session_id(args)?;
    let mut guard = session_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let session = guard
        .get_mut(&id)
        .ok_or_else(|| LuaError::RuntimeError(format!("step_into: unknown session {id}")))?;
    session.advance_rip();
    let regs = session.regs.to_lua_table();
    drop(guard);
    Ok(regs)
}

/// `dbg.step_over(session_id) → table`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn step_over(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    // In a real implementation step_over would set a temp BP after any CALL.
    // Here we advance by one instruction.
    step_into(args)
}

/// `dbg.step_out(session_id) → table`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn step_out(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_session_id(args)?;
    let mut guard = session_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let session = guard
        .get_mut(&id)
        .ok_or_else(|| LuaError::RuntimeError(format!("step_out: unknown session {id}")))?;
    // Pop top frame, set RIP to return address.
    if let Some(frame) = session.call_stack.pop() {
        session.regs.rip = frame.return_addr;
        session.regs.rbp = frame.frame_ptr;
    } else {
        session.state = SessionState::Terminated;
    }
    let regs = session.regs.to_lua_table();
    drop(guard);
    Ok(regs)
}

/// `dbg.get_registers(session_id) → table`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn get_registers(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_session_id(args)?;
    let guard = session_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let session = guard
        .get(&id)
        .ok_or_else(|| LuaError::RuntimeError(format!("get_registers: unknown session {id}")))?;
    let regs = session.regs.to_lua_table();
    drop(guard);
    Ok(regs)
}

/// `dbg.set_register(session_id, name, value) → bool`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn set_register(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_session_id(args)?;
    let name = args
        .get(1)
        .and_then(|v| v.as_str().map(str::to_string))
        .ok_or_else(|| LuaError::RuntimeError("set_register: expected register name".into()))?;
    let value = crate::casts::i64_to_u64(args
        .get(2)
        .and_then(LuaValue::as_int)
        .ok_or_else(|| LuaError::RuntimeError("set_register: expected integer value".into()))?);
    let mut guard = session_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let session = guard
        .get_mut(&id)
        .ok_or_else(|| LuaError::RuntimeError(format!("set_register: unknown session {id}")))?;
    let ok = session.regs.set(&name, value);
    drop(guard);
    Ok(LuaValue::Bool(ok))
}

/// `dbg.read_memory(session_id, addr, size) → table (byte array)`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn read_memory(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    // Cap size to 4096 bytes (one page) to prevent DoS from a Lua script
    // passing an arbitrarily large value; negative i64 would also wrap to a
    // giant usize without this clamp.
    const MAX_READ_SIZE: usize = 4096;
    let id = require_session_id(args)?;
    let addr = crate::casts::i64_to_u64(args.get(1).and_then(LuaValue::as_int).unwrap_or(0));
    let size = args.get(2).and_then(LuaValue::as_int)
        .map_or(16, |n| crate::casts::i64_to_usize(n.max(0)).min(MAX_READ_SIZE));
    let guard = session_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let session = guard
        .get(&id)
        .ok_or_else(|| LuaError::RuntimeError(format!("read_memory: unknown session {id}")))?;
    let bytes_opt = session.read_memory(addr, size);
    drop(guard);
    bytes_opt.map_or_else(
        || Err(LuaError::RuntimeError(format!("read_memory: address {addr:#x} not mapped"))),
        |bytes| {
            let table: Vec<(LuaValue, LuaValue)> = bytes
                .iter()
                .enumerate()
                .map(|(i, &b)| (LuaValue::Int(crate::casts::usize_to_i64(i) + 1), LuaValue::Int(i64::from(b))))
                .collect();
            Ok(LuaValue::Table(table))
        },
    )
}

/// `dbg.write_memory(session_id, addr, hex_str) → bool`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn write_memory(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_session_id(args)?;
    let addr = crate::casts::i64_to_u64(args.get(1).and_then(LuaValue::as_int).unwrap_or(0));
    let hex_str = args
        .get(2)
        .and_then(|v| v.as_str().map(str::to_string))
        .ok_or_else(|| LuaError::RuntimeError("write_memory: expected hex string".into()))?;
    let bytes = parse_hex_bytes(&hex_str)
        .map_err(|e| LuaError::RuntimeError(format!("write_memory: {e}")))?;
    let mut guard = session_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let session = guard
        .get_mut(&id)
        .ok_or_else(|| LuaError::RuntimeError(format!("write_memory: unknown session {id}")))?;
    let ok = session.write_memory(addr, &bytes);
    drop(guard);
    Ok(LuaValue::Bool(ok))
}

/// `dbg.get_stack_trace(session_id) → table`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn get_stack_trace(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_session_id(args)?;
    let guard = session_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let session = guard
        .get(&id)
        .ok_or_else(|| LuaError::RuntimeError(format!("get_stack_trace: unknown session {id}")))?;
    let table: Vec<(LuaValue, LuaValue)> = session
        .call_stack
        .iter()
        .enumerate()
        .map(|(i, f)| {
            (
                LuaValue::Int(crate::casts::usize_to_i64(i) + 1),
                LuaValue::Table(vec![
                    (LuaValue::String("frame".into()), LuaValue::Int(crate::casts::usize_to_i64(f.frame_index))),
                    (LuaValue::String("return_addr".into()), LuaValue::Int(crate::casts::u64_to_i64(f.return_addr))),
                    (LuaValue::String("frame_ptr".into()), LuaValue::Int(crate::casts::u64_to_i64(f.frame_ptr))),
                    (LuaValue::String("function".into()), LuaValue::String(f.function_name.clone())),
                ]),
            )
        })
        .collect();
    drop(guard);
    Ok(LuaValue::Table(table))
}

/// `dbg.evaluate(session_id, expr) → int|string`
///
/// Evaluates simple register-name or `reg+offset` expressions.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn evaluate(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_session_id(args)?;
    let expr = args
        .get(1)
        .and_then(|v| v.as_str().map(str::to_string))
        .ok_or_else(|| LuaError::RuntimeError("evaluate: expected expression string".into()))?;
    let expr = expr.trim();
    let guard = session_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let session = guard
        .get(&id)
        .ok_or_else(|| LuaError::RuntimeError(format!("evaluate: unknown session {id}")))?;
    let reg_result: Option<i64> = split_reg_offset(expr).and_then(|(reg, offset)| {
        session.regs.get(&reg).map(|base| base.cast_signed().wrapping_add(offset))
    });
    drop(guard);
    if let Some(n) = reg_result {
        return Ok(LuaValue::Int(n));
    }
    // Try hex literal.
    if (expr.starts_with("0x") || expr.starts_with("0X"))
        && let Ok(n) = i64::from_str_radix(&expr[2..], 16) {
            return Ok(LuaValue::Int(n));
        }
    // Try decimal literal.
    if let Ok(n) = expr.parse::<i64>() {
        return Ok(LuaValue::Int(n));
    }
    // Unknown.
    Ok(LuaValue::String(format!("?({expr})")))
}

/// `dbg.set_watchpoint(session_id, addr, size, type) → bool`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn set_watchpoint(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_session_id(args)?;
    let addr = crate::casts::i64_to_u64(args.get(1).and_then(LuaValue::as_int).unwrap_or(0));
    // Clamp size: negative i64 would wrap to a giant usize.
    let size = args.get(2).and_then(LuaValue::as_int)
        .map_or(4, |n| crate::casts::i64_to_usize(n.max(0)));
    let kind_str = args
        .get(3)
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "write".into());
    let kind = WatchKind::parse(&kind_str);
    let mut guard = session_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let session = guard
        .get_mut(&id)
        .ok_or_else(|| LuaError::RuntimeError(format!("set_watchpoint: unknown session {id}")))?;
    session.watchpoints.push(Watchpoint {
        addr,
        size,
        kind,
        hit_count: 0,
    });
    drop(guard);
    Ok(LuaValue::Bool(true))
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

/// Dispatch a `dbg.*` call. Returns `Ok(None)` if not handled by this module.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn dispatch(name: &str, args: &[LuaValue]) -> Result<Option<LuaValue>, LuaError> {
    let result = match name {
        "dbg.attach" => Some(attach(args)?),
        "dbg.detach" => Some(detach(args)?),
        "dbg.set_breakpoint" => Some(set_breakpoint(args)?),
        "dbg.remove_breakpoint" => Some(remove_breakpoint(args)?),
        "dbg.run" => Some(run(args)?),
        "dbg.step_into" => Some(step_into(args)?),
        "dbg.step_over" => Some(step_over(args)?),
        "dbg.step_out" => Some(step_out(args)?),
        "dbg.get_registers" => Some(get_registers(args)?),
        "dbg.set_register" => Some(set_register(args)?),
        "dbg.read_memory" => Some(read_memory(args)?),
        "dbg.write_memory" => Some(write_memory(args)?),
        "dbg.get_stack_trace" => Some(get_stack_trace(args)?),
        "dbg.evaluate" => Some(evaluate(args)?),
        "dbg.set_watchpoint" => Some(set_watchpoint(args)?),
        _ => None,
    };
    Ok(result)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn require_session_id(args: &[LuaValue]) -> Result<String, LuaError> {
    args.first()
        .and_then(|v| v.as_str().map(str::to_string))
        .ok_or_else(|| LuaError::RuntimeError("expected session_id as first argument".into()))
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let joined: String = s.split_whitespace().collect();
    if !joined.len().is_multiple_of(2) {
        return Err("odd number of hex digits".into());
    }
    (0..joined.len() / 2)
        .map(|i| u8::from_str_radix(&joined[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn split_reg_offset(expr: &str) -> Option<(String, i64)> {
    if let Some(pos) = expr.find('+') {
        let reg = expr[..pos].trim().to_string();
        let off: i64 = expr[pos + 1..].trim().parse().ok()?;
        return Some((reg, off));
    }
    if let Some(pos) = expr.rfind('-')
        && pos > 0 {
            let reg = expr[..pos].trim().to_string();
            let off: i64 = expr[pos + 1..].trim().parse().ok()?;
            return Some((reg, -off));
        }
    // Just a register name, offset 0.
    Some((expr.to_string(), 0))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn str_arg(s: &str) -> LuaValue {
        LuaValue::String(s.into())
    }
    fn int_arg(n: i64) -> LuaValue {
        LuaValue::Int(n)
    }

    fn new_session() -> String {
        if let LuaValue::String(id) = attach(&[int_arg(1234)]).unwrap() {
            id
        } else {
            panic!("attach should return string id");
        }
    }

    #[test]
    fn test_attach_detach() {
        let id = new_session();
        assert!(id.starts_with("dbg-"));
        let result = detach(&[str_arg(&id)]).unwrap();
        assert!(matches!(result, LuaValue::Bool(true)));
    }

    #[test]
    fn test_get_registers_has_rip() {
        let id = new_session();
        let regs = get_registers(&[str_arg(&id)]).unwrap();
        if let LuaValue::Table(t) = regs {
            let has_rip = t.iter().any(|(k, _)| {
                if let LuaValue::String(s) = k {
                    s == "rip"
                } else {
                    false
                }
            });
            assert!(has_rip, "registers table should contain rip");
        } else {
            panic!("expected table");
        }
    }

    #[test]
    fn test_set_register() {
        let id = new_session();
        set_register(&[str_arg(&id), str_arg("rax"), int_arg(0xdead_beef)]).unwrap();
        let regs = get_registers(&[str_arg(&id)]).unwrap();
        if let LuaValue::Table(t) = regs {
            let rax = t.iter().find_map(|(k, v)| {
                if let (LuaValue::String(s), LuaValue::Int(n)) = (k, v) {
                    if s == "rax" {
                        Some(*n)
                    } else {
                        None
                    }
                } else {
                    None
                }
            });
            assert_eq!(rax, Some(0xdead_beef));
        }
    }

    #[test]
    fn test_set_breakpoint_and_run() {
        let id = new_session();
        let initial_rip = {
            let g = session_store().lock().unwrap();
            g.get(&id).unwrap().regs.rip
        };
        set_breakpoint(&[str_arg(&id), int_arg(crate::casts::u64_to_i64(initial_rip) + 3)]).unwrap();
        run(&[str_arg(&id)]).unwrap();
        let rip_after = {
            let g = session_store().lock().unwrap();
            g.get(&id).unwrap().regs.rip
        };
        assert!(rip_after > initial_rip, "RIP should have advanced");
    }

    #[test]
    fn test_read_write_memory() {
        let id = new_session();
        // Write to page 0x1000.
        write_memory(&[str_arg(&id), int_arg(0x1000), str_arg("de ad be ef")]).unwrap();
        let result = read_memory(&[str_arg(&id), int_arg(0x1000), int_arg(4)]).unwrap();
        if let LuaValue::Table(t) = result {
            let bytes: Vec<i64> = t
                .iter()
                .filter_map(|(_, v)| if let LuaValue::Int(n) = v { Some(*n) } else { None })
                .collect();
            assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
        } else {
            panic!("expected table");
        }
    }

    #[test]
    fn test_evaluate_register() {
        let id = new_session();
        set_register(&[str_arg(&id), str_arg("rax"), int_arg(100)]).unwrap();
        let result = evaluate(&[str_arg(&id), str_arg("rax+10")]).unwrap();
        assert_eq!(result.as_int(), Some(110));
    }

    #[test]
    fn test_watchpoint_stored() {
        let id = new_session();
        set_watchpoint(&[str_arg(&id), int_arg(0x5000), int_arg(4), str_arg("write")]).unwrap();
        let g = session_store().lock().unwrap();
        let s = g.get(&id).unwrap();
        assert_eq!(s.watchpoints.len(), 1);
        assert_eq!(s.watchpoints[0].kind, WatchKind::Write);
    }

    #[test]
    fn test_dispatch_unknown_returns_none() {
        let result = dispatch("dbg.unknown", &[]).unwrap();
        assert!(result.is_none());
    }
}
