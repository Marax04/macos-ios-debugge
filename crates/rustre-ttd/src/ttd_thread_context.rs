//! Thread context at TTD positions: register state, TEB snapshot, and stack
//! pointer reconstruction.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ttd_position::TtdPosition;

// ─── ThreadRegisters ─────────────────────────────────────────────────────────

/// Complete x86-64 register state for a single thread at one TTD position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadRegisters {
    /// General-purpose registers.
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    /// Instruction pointer.
    pub rip: u64,
    /// Flags register.
    pub rflags: u64,
    /// Segment registers (packed: CS, DS, ES, FS, GS, SS).
    pub cs: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
    pub ss: u16,
    /// Extended state: XMM registers (XMM0..XMM15), each 16 bytes.
    pub xmm: [[u8; 16]; 16],
    /// x87/SSE MXCSR control/status register.
    pub mxcsr: u32,
}

impl Default for ThreadRegisters {
    fn default() -> Self {
        Self {
            rax: 0, rbx: 0, rcx: 0, rdx: 0,
            rsi: 0, rdi: 0, rsp: 0, rbp: 0,
            r8: 0, r9: 0, r10: 0, r11: 0,
            r12: 0, r13: 0, r14: 0, r15: 0,
            rip: 0,
            rflags: 0,
            cs: 0x33, ds: 0x2b, es: 0x2b, fs: 0, gs: 0, ss: 0x2b,
            xmm: [[0u8; 16]; 16],
            mxcsr: 0x1f80,
        }
    }
}

impl ThreadRegisters {
    /// Create zero-initialised registers.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a register value by canonical name (case-insensitive).
    ///
    /// Returns `None` for unknown register names.
    #[must_use] 
    pub fn get(&self, name: &str) -> Option<u64> {
        match name.to_lowercase().as_str() {
            "rax" => Some(self.rax),
            "rbx" => Some(self.rbx),
            "rcx" => Some(self.rcx),
            "rdx" => Some(self.rdx),
            "rsi" => Some(self.rsi),
            "rdi" => Some(self.rdi),
            "rsp" => Some(self.rsp),
            "rbp" => Some(self.rbp),
            "r8"  => Some(self.r8),
            "r9"  => Some(self.r9),
            "r10" => Some(self.r10),
            "r11" => Some(self.r11),
            "r12" => Some(self.r12),
            "r13" => Some(self.r13),
            "r14" => Some(self.r14),
            "r15" => Some(self.r15),
            "rip" => Some(self.rip),
            "rflags" | "eflags" => Some(self.rflags),
            // 32-bit sub-registers.
            "eax" => Some(self.rax & 0xffff_ffff),
            "ebx" => Some(self.rbx & 0xffff_ffff),
            "ecx" => Some(self.rcx & 0xffff_ffff),
            "edx" => Some(self.rdx & 0xffff_ffff),
            "esp" => Some(self.rsp & 0xffff_ffff),
            "ebp" => Some(self.rbp & 0xffff_ffff),
            "esi" => Some(self.rsi & 0xffff_ffff),
            "edi" => Some(self.rdi & 0xffff_ffff),
            // 16-bit.
            "ax" => Some(self.rax & 0xffff),
            "bx" => Some(self.rbx & 0xffff),
            "cx" => Some(self.rcx & 0xffff),
            "dx" => Some(self.rdx & 0xffff),
            // 8-bit low.
            "al" => Some(self.rax & 0xff),
            "bl" => Some(self.rbx & 0xff),
            "cl" => Some(self.rcx & 0xff),
            "dl" => Some(self.rdx & 0xff),
            _ => None,
        }
    }

    /// Set a register value by canonical name (case-insensitive).
    ///
    /// Returns `false` if the name is unknown.
    pub fn set(&mut self, name: &str, value: u64) -> bool {
        match name.to_lowercase().as_str() {
            "rax" => { self.rax = value; true }
            "rbx" => { self.rbx = value; true }
            "rcx" => { self.rcx = value; true }
            "rdx" => { self.rdx = value; true }
            "rsi" => { self.rsi = value; true }
            "rdi" => { self.rdi = value; true }
            "rsp" => { self.rsp = value; true }
            "rbp" => { self.rbp = value; true }
            "r8"  => { self.r8  = value; true }
            "r9"  => { self.r9  = value; true }
            "r10" => { self.r10 = value; true }
            "r11" => { self.r11 = value; true }
            "r12" => { self.r12 = value; true }
            "r13" => { self.r13 = value; true }
            "r14" => { self.r14 = value; true }
            "r15" => { self.r15 = value; true }
            "rip" => { self.rip = value; true }
            "rflags" | "eflags" => { self.rflags = value; true }
            _ => false,
        }
    }

    /// Enumerate all GP register names and their current values.
    #[must_use] 
    pub fn gp_registers(&self) -> Vec<(&'static str, u64)> {
        vec![
            ("rax", self.rax), ("rbx", self.rbx), ("rcx", self.rcx), ("rdx", self.rdx),
            ("rsi", self.rsi), ("rdi", self.rdi), ("rsp", self.rsp), ("rbp", self.rbp),
            ("r8",  self.r8),  ("r9",  self.r9),  ("r10", self.r10), ("r11", self.r11),
            ("r12", self.r12), ("r13", self.r13), ("r14", self.r14), ("r15", self.r15),
            ("rip", self.rip), ("rflags", self.rflags),
        ]
    }

    /// Return `true` if the carry flag (CF, bit 0) is set.
    #[must_use] 
    pub const fn flag_cf(&self) -> bool { (self.rflags & 1) != 0 }
    /// Return `true` if the zero flag (ZF, bit 6) is set.
    #[must_use] 
    pub const fn flag_zf(&self) -> bool { (self.rflags & (1 << 6)) != 0 }
    /// Return `true` if the sign flag (SF, bit 7) is set.
    #[must_use] 
    pub const fn flag_sf(&self) -> bool { (self.rflags & (1 << 7)) != 0 }
    /// Return `true` if the overflow flag (OF, bit 11) is set.
    #[must_use] 
    pub const fn flag_of(&self) -> bool { (self.rflags & (1 << 11)) != 0 }
}

impl fmt::Display for ThreadRegisters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rax={:#018x} rbx={:#018x} rcx={:#018x} rdx={:#018x}\n\
             rsi={:#018x} rdi={:#018x} rsp={:#018x} rbp={:#018x}\n\
             r8 ={:#018x} r9 ={:#018x} r10={:#018x} r11={:#018x}\n\
             r12={:#018x} r13={:#018x} r14={:#018x} r15={:#018x}\n\
             rip={:#018x} rflags={:#018x}",
            self.rax, self.rbx, self.rcx, self.rdx,
            self.rsi, self.rdi, self.rsp, self.rbp,
            self.r8,  self.r9,  self.r10, self.r11,
            self.r12, self.r13, self.r14, self.r15,
            self.rip, self.rflags,
        )
    }
}

// ─── TebSnapshot ─────────────────────────────────────────────────────────────

/// A snapshot of the Thread Environment Block (TEB) for a Windows thread.
///
/// Only the most commonly needed fields are modelled; the raw bytes of the
/// full TEB page are stored as well for offline analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TebSnapshot {
    /// Base address of the TEB in the traced process.
    pub teb_base: u64,
    /// Base address of the thread's stack (TEB+0x08 on x64).
    pub stack_base: u64,
    /// Limit address of the thread's stack (TEB+0x10 on x64).
    pub stack_limit: u64,
    /// Address of the thread's structured exception handler chain (TEB+0x00 on x86).
    pub exception_list: u64,
    /// Thread ID (TEB+0x48 on x64).
    pub thread_id: u32,
    /// Process ID (TEB+0x40 on x64).
    pub process_id: u32,
    /// Last Win32 error code (TEB+0x68 on x64).
    pub last_error: u32,
    /// Address of TLS slots array (TEB+0x58 on x64).
    pub tls_array_ptr: u64,
    /// Raw bytes of the TEB page, when available.
    pub raw_bytes: Vec<u8>,
}

impl TebSnapshot {
    /// Create a minimal TEB snapshot with only an address set.
    #[must_use] 
    pub const fn new(teb_base: u64, thread_id: u32, process_id: u32) -> Self {
        Self {
            teb_base,
            stack_base: 0,
            stack_limit: 0,
            exception_list: 0,
            thread_id,
            process_id,
            last_error: 0,
            tls_array_ptr: 0,
            raw_bytes: Vec::new(),
        }
    }

    /// Parse `stack_base` and `stack_limit` from the raw TEB bytes (x64 layout).
    pub fn parse_stack_bounds_x64(&mut self) {
        if self.raw_bytes.len() >= 0x18 {
            self.stack_base = read_u64_le(&self.raw_bytes, 0x08);
            self.stack_limit = read_u64_le(&self.raw_bytes, 0x10);
        }
    }

    /// Return `true` if `addr` lies within the thread's stack region.
    #[must_use] 
    pub const fn stack_contains(&self, addr: u64) -> bool {
        if self.stack_base == 0 || self.stack_limit == 0 {
            return false;
        }
        // Stack grows downward: stack_limit <= addr < stack_base.
        addr >= self.stack_limit && addr < self.stack_base
    }
}

impl fmt::Display for TebSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TebSnapshot {{ teb={:#x}, tid={}, pid={}, stack={:#x}..{:#x}, last_err={:#x} }}",
            self.teb_base, self.thread_id, self.process_id,
            self.stack_limit, self.stack_base, self.last_error
        )
    }
}

// ─── ContextCapture ──────────────────────────────────────────────────────────

/// Strategy for capturing a thread context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextCapture {
    /// Capture at the exact TTD position.
    Exact,
    /// Capture at the nearest preceding position (floor).
    Floor,
    /// Capture at the nearest following position (ceiling).
    Ceiling,
}

// ─── TtdThreadContext ─────────────────────────────────────────────────────────

/// Complete thread state at a given TTD position.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtdThreadContext {
    /// Thread identifier.
    pub thread_id: u32,
    /// The TTD position this context was captured at.
    pub position: TtdPosition,
    /// Register state.
    pub registers: ThreadRegisters,
    /// TEB snapshot, if available.
    pub teb: Option<TebSnapshot>,
    /// Raw stack bytes starting from `registers.rsp` (up to some limit).
    pub stack_bytes: Vec<u8>,
    /// Additional metadata annotations (arbitrary key-value pairs).
    pub annotations: HashMap<String, String>,
}

impl TtdThreadContext {
    /// Create a minimal context for `thread_id` at `position`.
    #[must_use] 
    pub fn new(thread_id: u32, position: TtdPosition) -> Self {
        Self {
            thread_id,
            position,
            registers: ThreadRegisters::default(),
            teb: None,
            stack_bytes: Vec::new(),
            annotations: HashMap::new(),
        }
    }

    /// Return the current stack pointer.
    #[must_use] 
    pub const fn stack_pointer(&self) -> u64 {
        self.registers.rsp
    }

    /// Return the current instruction pointer.
    #[must_use] 
    pub const fn instruction_pointer(&self) -> u64 {
        self.registers.rip
    }

    /// Annotate this context with an arbitrary key-value pair.
    pub fn annotate(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.annotations.insert(key.into(), value.into());
    }

    /// Attempt to read a `u64` from the captured stack bytes at byte offset
    /// `rsp_offset` (relative to RSP).
    ///
    /// Returns `None` if the offset is out of range or stack bytes are empty.
    #[must_use] 
    pub fn read_stack_u64(&self, rsp_offset: usize) -> Option<u64> {
        if rsp_offset + 8 > self.stack_bytes.len() {
            return None;
        }
        Some(read_u64_le(&self.stack_bytes, rsp_offset))
    }

    /// Return the return address (first 8 bytes on the stack), if available.
    #[must_use] 
    pub fn return_address(&self) -> Option<u64> {
        self.read_stack_u64(0)
    }

    /// Return a synthetic "frame pointer chain": `(rbp, saved_rbp, return_addr)`.
    /// Useful for reconstructing a call frame from the context alone.
    #[must_use] 
    pub fn frame_pointer_chain(&self) -> Option<(u64, u64, u64)> {
        let rbp = self.registers.rbp;
        if rbp == 0 {
            return None;
        }
        // If stack_bytes covers [rsp, rsp + N), compute offsets.
        let rsp = self.registers.rsp;
        if rbp < rsp {
            return None;
        }
        let rbp_off = usize::try_from(rbp - rsp).ok()?;
        let saved_rbp = self.read_stack_u64(rbp_off)?;
        let ret_addr = self.read_stack_u64(rbp_off + 8)?;
        Some((rbp, saved_rbp, ret_addr))
    }
}

impl fmt::Display for TtdThreadContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TtdThreadContext {{ tid={}, pos={}, rip={:#x}, rsp={:#x} }}",
            self.thread_id,
            self.position,
            self.registers.rip,
            self.registers.rsp,
        )
    }
}

// ─── ContextStore ─────────────────────────────────────────────────────────────

/// Stores multiple thread contexts indexed by `(thread_id, position)`.
#[derive(Debug, Default)]
pub struct ContextStore {
    entries: Vec<TtdThreadContext>,
}

impl ContextStore {
    /// Create an empty store.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace the context for `(thread_id, position)`.
    pub fn insert(&mut self, ctx: TtdThreadContext) {
        // Replace if exact match exists, otherwise push.
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.thread_id == ctx.thread_id && e.position == ctx.position)
        {
            *existing = ctx;
        } else {
            self.entries.push(ctx);
        }
    }

    /// Look up the context for `(thread_id, position)` exactly.
    #[must_use] 
    pub fn get(&self, thread_id: u32, position: TtdPosition) -> Option<&TtdThreadContext> {
        self.entries
            .iter()
            .find(|e| e.thread_id == thread_id && e.position == position)
    }

    /// Return the context for `thread_id` whose position is the largest one
    /// that is still `<= position` (floor semantics).
    #[must_use] 
    pub fn get_floor(&self, thread_id: u32, position: TtdPosition) -> Option<&TtdThreadContext> {
        self.entries
            .iter()
            .filter(|e| e.thread_id == thread_id && e.position <= position)
            .max_by_key(|e| e.position)
    }

    /// Return the context for `thread_id` whose position is the smallest one
    /// that is `>= position` (ceiling semantics).
    #[must_use] 
    pub fn get_ceiling(&self, thread_id: u32, position: TtdPosition) -> Option<&TtdThreadContext> {
        self.entries
            .iter()
            .filter(|e| e.thread_id == thread_id && e.position >= position)
            .min_by_key(|e| e.position)
    }

    /// Return the context matching the given `capture` strategy.
    #[must_use] 
    pub fn get_with_strategy(
        &self,
        thread_id: u32,
        position: TtdPosition,
        strategy: ContextCapture,
    ) -> Option<&TtdThreadContext> {
        match strategy {
            ContextCapture::Exact => self.get(thread_id, position),
            ContextCapture::Floor => self.get_floor(thread_id, position),
            ContextCapture::Ceiling => self.get_ceiling(thread_id, position),
        }
    }

    /// Return all contexts for `thread_id` in position order.
    #[must_use] 
    pub fn thread_history(&self, thread_id: u32) -> Vec<&TtdThreadContext> {
        let mut v: Vec<&TtdThreadContext> = self
            .entries
            .iter()
            .filter(|e| e.thread_id == thread_id)
            .collect();
        v.sort_by_key(|e| e.position);
        v
    }

    /// Return the total number of stored contexts.
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if no contexts are stored.
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

#[inline]
fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    if offset + 8 > data.len() {
        return 0;
    }
    u64::from_le_bytes([
        data[offset],     data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ])
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_register_rax() {
        let mut r = ThreadRegisters::new();
        r.rax = 0xdead_beef;
        assert_eq!(r.get("rax"), Some(0xdead_beef));
        assert_eq!(r.get("eax"), Some(0xdead_beef_u64 & 0xffff_ffff));
        assert_eq!(r.get("ax"), Some(0xbeef));
        assert_eq!(r.get("al"), Some(0xef));
    }

    #[test]
    fn test_set_register_rsp() {
        let mut r = ThreadRegisters::new();
        assert!(r.set("rsp", 0x7fff_0000));
        assert_eq!(r.rsp, 0x7fff_0000);
    }

    #[test]
    fn test_unknown_register_returns_none() {
        let r = ThreadRegisters::default();
        assert!(r.get("cr0").is_none());
    }

    #[test]
    fn test_flags() {
        // Fix: literal had bits 14,15 set instead of SF(7)+OF(11); x86 RFLAGS bits are CF=0, ZF=6, SF=7, OF=11.
        let r = ThreadRegisters {
            rflags: (1 << 0) | (1 << 6) | (1 << 7) | (1 << 11), // CF + ZF + SF + OF
            ..ThreadRegisters::default()
        };
        assert!(r.flag_cf());
        assert!(r.flag_zf());
        assert!(r.flag_sf());
        assert!(r.flag_of());
    }

    #[test]
    fn test_teb_stack_contains() {
        let mut teb = TebSnapshot::new(0x7ffe_0000, 1, 100);
        teb.stack_limit = 0x7f00_0000;
        teb.stack_base  = 0x7f10_0000;
        assert!(teb.stack_contains(0x7f0f_f000));
        assert!(!teb.stack_contains(0x7f10_0000));
        assert!(!teb.stack_contains(0x7eff_ffff));
    }

    #[test]
    fn test_thread_context_read_stack() {
        let mut ctx = TtdThreadContext::new(1, TtdPosition::new(5, 0));
        ctx.registers.rsp = 0x7fff_0000;
        // Store a known u64 at offset 0.
        ctx.stack_bytes = 0xdead_beef_cafe_babe_u64.to_le_bytes().to_vec();
        assert_eq!(ctx.read_stack_u64(0), Some(0xdead_beef_cafe_babe));
    }

    #[test]
    fn test_context_store_floor() {
        let mut store = ContextStore::new();
        let p1 = TtdPosition::new(1, 0);
        let p2 = TtdPosition::new(3, 0);
        store.insert(TtdThreadContext::new(1, p1));
        store.insert(TtdThreadContext::new(1, p2));
        let floor = store.get_floor(1, TtdPosition::new(2, 5)).unwrap();
        assert_eq!(floor.position, p1);
    }

    #[test]
    fn test_context_store_ceiling() {
        let mut store = ContextStore::new();
        let p1 = TtdPosition::new(1, 0);
        let p3 = TtdPosition::new(3, 0);
        store.insert(TtdThreadContext::new(1, p1));
        store.insert(TtdThreadContext::new(1, p3));
        let ceil = store.get_ceiling(1, TtdPosition::new(2, 0)).unwrap();
        assert_eq!(ceil.position, p3);
    }

    #[test]
    fn test_context_store_thread_history_sorted() {
        let mut store = ContextStore::new();
        store.insert(TtdThreadContext::new(1, TtdPosition::new(5, 0)));
        store.insert(TtdThreadContext::new(1, TtdPosition::new(2, 0)));
        store.insert(TtdThreadContext::new(1, TtdPosition::new(8, 0)));
        let hist = store.thread_history(1);
        assert!(hist.windows(2).all(|w| w[0].position < w[1].position));
    }
}
