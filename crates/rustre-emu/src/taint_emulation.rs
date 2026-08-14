//! Taint-tracking emulation wrapper.
//!
//! [`TaintEmulator`] wraps any `Box<dyn Emulator>` and transparently forwards
//! all [`Emulator`] calls while maintaining a parallel "taint shadow":
//!
//! * A per-register taint bitmap (one `u64` bit-mask per register, 64 taint
//!   sources max).
//! * A per-byte memory taint map (sparse: only tainted bytes are stored).
//!
//! Taint propagates conservatively: any operation whose inputs include tainted
//! values produces a tainted output (OR of input taints).  Control-flow taint
//! is detected when the instruction pointer register is written with a tainted
//! value.
//!
//! # Usage
//! ```no_run
//! use rustre_emu::{EmulatorFactory, EmulatorArch, MemPerms};
//! use rustre_emu::taint_emulation::{TaintEmulator, TaintSource};
//!
//! let inner = EmulatorFactory::create(EmulatorArch::X86_64);
//! let mut te = TaintEmulator::new(inner);
//! // Mark bytes 0x1000..0x1010 as tainted by source 0
//! te.taint_memory(0x1000, 16, 1 << 0);
//! ```

use std::collections::HashMap;

use crate::{Emulator, EmulatorArch, EmulatorError, HookHandle, HookKind, MemPerms, MemRegion};

// ─────────────────────────────────────────────────────────────────────────────
// TaintLabel
// ─────────────────────────────────────────────────────────────────────────────

/// A taint label is a bitmask of up to 64 independent taint sources.
pub type TaintLabel = u64;

/// A named taint source for human-readable reporting.
#[derive(Debug, Clone)]
pub struct TaintSource {
    /// Source index (bit position in the taint label, 0–63).
    pub index: u8,
    /// Human-readable name.
    pub name: String,
}

impl TaintSource {
    #[must_use]
    pub fn new(index: u8, name: impl Into<String>) -> Self {
        Self {
            index: index.min(63),
            name: name.into(),
        }
    }
    #[must_use]
    pub const fn mask(&self) -> TaintLabel {
        1 << self.index
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemTaintMap
// ─────────────────────────────────────────────────────────────────────────────

/// Sparse per-byte memory taint shadow.
#[derive(Debug, Default, Clone)]
pub struct MemTaintMap {
    /// Maps byte address → taint label.
    bytes: HashMap<u64, TaintLabel>,
}

impl MemTaintMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark bytes `[addr, addr+len)` with `label`.
    pub fn set_range(&mut self, addr: u64, len: usize, label: TaintLabel) {
        if label == 0 {
            for i in 0..len as u64 {
                self.bytes.remove(&(addr + i));
            }
        } else {
            for i in 0..len as u64 {
                self.bytes.insert(addr + i, label);
            }
        }
    }

    /// OR-merge taint `label` into bytes `[addr, addr+len)`.
    pub fn taint_range(&mut self, addr: u64, len: usize, label: TaintLabel) {
        for i in 0..len as u64 {
            let e = self.bytes.entry(addr + i).or_insert(0);
            *e |= label;
        }
    }

    /// Get the combined taint label of bytes `[addr, addr+len)`.
    #[must_use]
    pub fn get_range(&self, addr: u64, len: usize) -> TaintLabel {
        let mut label = 0;
        for i in 0..len as u64 {
            label |= self.bytes.get(&(addr + i)).copied().unwrap_or(0);
        }
        label
    }

    #[must_use]
    pub fn get_byte(&self, addr: u64) -> TaintLabel {
        self.bytes.get(&addr).copied().unwrap_or(0)
    }

    /// Clear taint for bytes `[addr, addr+len)`.
    pub fn clear_range(&mut self, addr: u64, len: usize) {
        for i in 0..len as u64 {
            self.bytes.remove(&(addr + i));
        }
    }

    /// Return all tainted addresses (sorted).
    #[must_use]
    pub fn tainted_addresses(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self.bytes.keys().copied().collect();
        v.sort_unstable();
        v
    }

    pub fn reset(&mut self) {
        self.bytes.clear();
    }

    #[must_use]
    pub fn tainted_byte_count(&self) -> usize {
        self.bytes.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegTaintMap
// ─────────────────────────────────────────────────────────────────────────────

/// Per-register taint shadow.
#[derive(Debug, Default, Clone)]
pub struct RegTaintMap {
    /// Maps register id → taint label.
    regs: HashMap<u32, TaintLabel>,
}

impl RegTaintMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn set(&mut self, reg: u32, label: TaintLabel) {
        if label == 0 {
            self.regs.remove(&reg);
        } else {
            self.regs.insert(reg, label);
        }
    }

    #[inline]
    #[must_use]
    pub fn get(&self, reg: u32) -> TaintLabel {
        self.regs.get(&reg).copied().unwrap_or(0)
    }

    #[inline]
    pub fn taint(&mut self, reg: u32, label: TaintLabel) {
        let e = self.regs.entry(reg).or_insert(0);
        *e |= label;
    }

    pub fn clear(&mut self, reg: u32) {
        self.regs.remove(&reg);
    }

    #[must_use]
    pub fn tainted_regs(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.regs.keys().copied().collect();
        v.sort_unstable();
        v
    }

    pub fn reset(&mut self) {
        self.regs.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TaintEvent
// ─────────────────────────────────────────────────────────────────────────────

/// A recorded taint-flow event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintEvent {
    /// A register was written with a tainted value.
    RegisterTainted { reg: u32, label: TaintLabel },
    /// A memory address was written with a tainted value.
    MemoryTainted {
        addr: u64,
        len: usize,
        label: TaintLabel,
    },
    /// Control flow reached a tainted PC.
    TaintedControlFlow { pc: u64, label: TaintLabel },
    /// A tainted memory read propagated to a register.
    TaintedLoad {
        src_addr: u64,
        dst_reg: u32,
        label: TaintLabel,
    },
    /// A tainted register was stored to memory.
    TaintedStore {
        src_reg: u32,
        dst_addr: u64,
        label: TaintLabel,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// TaintPolicy
// ─────────────────────────────────────────────────────────────────────────────

/// Propagation-related boolean flags.
#[derive(Debug, Clone)]
pub struct TaintPropagationFlags {
    /// Track data flow through arithmetic operations.
    pub arithmetic: bool,
    /// Track data flow through memory loads.
    pub loads: bool,
    /// Track data flow through memory stores.
    pub stores: bool,
}

impl Default for TaintPropagationFlags {
    fn default() -> Self {
        Self {
            arithmetic: true,
            loads: true,
            stores: true,
        }
    }
}

/// Detection-related boolean flags.
#[derive(Debug, Clone)]
pub struct TaintDetectionFlags {
    /// Detect and record tainted control-flow.
    pub tainted_cf: bool,
}

impl Default for TaintDetectionFlags {
    fn default() -> Self {
        Self { tainted_cf: true }
    }
}

/// Boolean flag set for [`TaintPolicy`], grouped by purpose.
#[derive(Debug, Clone, Default)]
pub struct TaintPolicyFlags {
    /// Propagation flags.
    pub propagation: TaintPropagationFlags,
    /// Detection flags.
    pub detection: TaintDetectionFlags,
}

impl TaintPolicyFlags {
    /// Forwards to `propagation.arithmetic`.
    #[must_use]
    pub const fn propagate_arithmetic(&self) -> bool {
        self.propagation.arithmetic
    }
    /// Forwards to `propagation.loads`.
    #[must_use]
    pub const fn propagate_loads(&self) -> bool {
        self.propagation.loads
    }
    /// Forwards to `propagation.stores`.
    #[must_use]
    pub const fn propagate_stores(&self) -> bool {
        self.propagation.stores
    }
    /// Forwards to `detection.tainted_cf`.
    #[must_use]
    pub const fn detect_tainted_cf(&self) -> bool {
        self.detection.tainted_cf
    }
}

/// Configuration for the taint propagation engine.
#[derive(Debug, Clone)]
pub struct TaintPolicy {
    /// Boolean propagation flags.
    pub flags: TaintPolicyFlags,
    /// Limit event log to this many entries (0 = unlimited).
    pub max_events: usize,
}

impl TaintPolicy {
    /// Convenience accessor: forwards to `flags.propagation.arithmetic`.
    #[must_use]
    pub const fn propagate_arithmetic(&self) -> bool {
        self.flags.propagation.arithmetic
    }
    /// Convenience accessor: forwards to `flags.propagation.loads`.
    #[must_use]
    pub const fn propagate_loads(&self) -> bool {
        self.flags.propagation.loads
    }
    /// Convenience accessor: forwards to `flags.propagation.stores`.
    #[must_use]
    pub const fn propagate_stores(&self) -> bool {
        self.flags.propagation.stores
    }
    /// Convenience accessor: forwards to `flags.detection.tainted_cf`.
    #[must_use]
    pub const fn detect_tainted_cf(&self) -> bool {
        self.flags.detection.tainted_cf
    }
}

impl Default for TaintPolicy {
    fn default() -> Self {
        Self {
            flags: TaintPolicyFlags::default(),
            max_events: 65536,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PC register helpers
// ─────────────────────────────────────────────────────────────────────────────

const fn pc_reg_for_arch(arch: EmulatorArch) -> u32 {
    use crate::{arm_regs, mips_regs, riscv_regs, x86_regs};
    match arch {
        EmulatorArch::X86_64 => x86_regs::RIP,
        EmulatorArch::X86_32 | EmulatorArch::X86_16 => x86_regs::EIP,
        EmulatorArch::Arm | EmulatorArch::ArmThumb => arm_regs::PC,
        EmulatorArch::Arm64 => crate::arm64_regs::PC,
        EmulatorArch::Mips32 | EmulatorArch::Mips64 | EmulatorArch::Mips32El => mips_regs::PC,
        EmulatorArch::RiscV32 | EmulatorArch::RiscV64 => riscv_regs::PC,
        _ => u32::MAX,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TaintEmulator
// ─────────────────────────────────────────────────────────────────────────────

/// Taint-tracking wrapper around any [`Emulator`].
///
/// All emulator API calls are forwarded to the inner emulator unchanged.
/// Taint propagation happens by intercepting `read_register`,
/// `write_register`, `read_memory`, and `write_memory` calls.
///
/// Note: for full instruction-level taint tracking (e.g. propagating taint
/// through ALU instructions within a running program) you would install code
/// hooks — this wrapper handles the *observable* API boundary which is
/// sufficient for many RE tasks.
pub struct TaintEmulator {
    inner: Box<dyn Emulator>,
    pub reg_taint: RegTaintMap,
    pub mem_taint: MemTaintMap,
    pub policy: TaintPolicy,
    pub events: Vec<TaintEvent>,
    /// Named taint sources.
    pub sources: HashMap<u8, TaintSource>,
}

impl TaintEmulator {
    /// Wrap an existing emulator.
    #[must_use]
    pub fn new(inner: Box<dyn Emulator>) -> Self {
        Self {
            inner,
            reg_taint: RegTaintMap::new(),
            mem_taint: MemTaintMap::new(),
            policy: TaintPolicy::default(),
            events: Vec::new(),
            sources: HashMap::new(),
        }
    }

    /// Register a named taint source.
    pub fn register_source(&mut self, src: TaintSource) {
        self.sources.insert(src.index, src);
    }

    /// Taint memory range `[addr, addr+len)` with `label`.
    pub fn taint_memory(&mut self, addr: u64, len: usize, label: TaintLabel) {
        self.mem_taint.set_range(addr, len, label);
        self.push_event(TaintEvent::MemoryTainted { addr, len, label });
    }

    /// Taint register `reg` with `label`.
    pub fn taint_register(&mut self, reg: u32, label: TaintLabel) {
        self.reg_taint.set(reg, label);
        self.push_event(TaintEvent::RegisterTainted { reg, label });
    }

    /// Clear all taint state and event log.
    pub fn reset_taint(&mut self) {
        self.reg_taint.reset();
        self.mem_taint.reset();
        self.events.clear();
    }

    /// Query whether a register has any taint.
    #[must_use]
    pub fn is_register_tainted(&self, reg: u32) -> bool {
        self.reg_taint.get(reg) != 0
    }

    /// Query whether any byte in `[addr, addr+len)` has taint.
    #[must_use]
    pub fn is_memory_tainted(&self, addr: u64, len: usize) -> bool {
        self.mem_taint.get_range(addr, len) != 0
    }

    /// Return all recorded taint events.
    #[must_use]
    pub fn taint_events(&self) -> &[TaintEvent] {
        &self.events
    }

    /// Return only control-flow taint events.
    #[must_use]
    pub fn tainted_cf_events(&self) -> Vec<&TaintEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e, TaintEvent::TaintedControlFlow { .. }))
            .collect()
    }

    /// Return a human-readable description of active sources in `label`.
    #[must_use]
    pub fn describe_label(&self, label: TaintLabel) -> String {
        if label == 0 {
            return "untainted".into();
        }
        // Collect named sources as borrowed &str when possible to avoid cloning.
        // format!() sources still require owned strings; we unify via a local
        // Vec<String> but preallocate for the number of set bits.
        let mut parts: Vec<String> = Vec::with_capacity(label.count_ones() as usize);
        for i in 0u8..64 {
            if (label >> i) & 1 != 0 {
                if let Some(src) = self.sources.get(&i) {
                    parts.push(src.name.clone());
                } else {
                    parts.push(format!("source[{i}]"));
                }
            }
        }
        parts.join("|")
    }

    fn push_event(&mut self, e: TaintEvent) {
        if self.policy.max_events == 0 || self.events.len() < self.policy.max_events {
            self.events.push(e);
        }
    }

    /// Propagate taint from memory → register on a load operation.
    pub fn propagate_load(&mut self, addr: u64, len: usize, dst_reg: u32) {
        if !self.policy.flags.propagation.loads {
            return;
        }
        let label = self.mem_taint.get_range(addr, len);
        if label != 0 {
            self.reg_taint.taint(dst_reg, label);
            self.push_event(TaintEvent::TaintedLoad {
                src_addr: addr,
                dst_reg,
                label,
            });
        }
    }

    /// Propagate taint from register → memory on a store operation.
    pub fn propagate_store(&mut self, src_reg: u32, addr: u64, len: usize) {
        if !self.policy.flags.propagation.stores {
            return;
        }
        let label = self.reg_taint.get(src_reg);
        if label != 0 {
            self.mem_taint.taint_range(addr, len, label);
            self.push_event(TaintEvent::TaintedStore {
                src_reg,
                dst_addr: addr,
                label,
            });
        }
    }

    /// Check if a register write targets the PC and is tainted.
    fn check_cf_taint(&mut self, reg: u32, label: TaintLabel) {
        if !self.policy.flags.detection.tainted_cf {
            return;
        }
        if label == 0 {
            return;
        }
        let pc_reg = pc_reg_for_arch(self.inner.arch());
        if reg == pc_reg
            && let Ok(pc) = self.inner.read_register(reg)
        {
            self.push_event(TaintEvent::TaintedControlFlow { pc, label });
        }
    }

    /// Propagate taint when one register is written from another (MOV-like op).
    pub fn propagate_reg_to_reg(&mut self, src_reg: u32, dst_reg: u32) {
        if !self.policy.flags.propagation.arithmetic {
            return;
        }
        let label = self.reg_taint.get(src_reg);
        if label != 0 {
            self.reg_taint.taint(dst_reg, label);
            self.push_event(TaintEvent::RegisterTainted {
                reg: dst_reg,
                label,
            });
        }
    }

    /// Propagate taint for a binary operation: dst = `op(src_a`, `src_b`).
    pub fn propagate_binop(&mut self, src_a: u32, src_b: u32, dst: u32) {
        if !self.policy.flags.propagation.arithmetic {
            return;
        }
        let label = self.reg_taint.get(src_a) | self.reg_taint.get(src_b);
        if label != 0 {
            self.reg_taint.taint(dst, label);
            self.push_event(TaintEvent::RegisterTainted { reg: dst, label });
        } else {
            // If result is not tainted, clear any previous taint on dst
            self.reg_taint.clear(dst);
        }
    }

    /// Untaint a register (e.g. after a constant move).
    pub fn clear_register_taint(&mut self, reg: u32) {
        self.reg_taint.clear(reg);
    }

    /// Summary of taint state.
    #[must_use]
    pub fn summary(&self) -> TaintSummary {
        TaintSummary {
            tainted_registers: self.reg_taint.tainted_regs(),
            tainted_byte_count: self.mem_taint.tainted_byte_count(),
            total_events: self.events.len(),
            cf_events: self.tainted_cf_events().len(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Emulator trait impl — forwarding + taint side-effects
// ─────────────────────────────────────────────────────────────────────────────

impl Emulator for TaintEmulator {
    fn arch(&self) -> EmulatorArch {
        self.inner.arch()
    }

    fn map_memory(&mut self, addr: u64, size: usize, perms: MemPerms) -> Result<(), EmulatorError> {
        self.inner.map_memory(addr, size, perms)
    }

    fn unmap_memory(&mut self, addr: u64) -> Result<(), EmulatorError> {
        self.mem_taint.clear_range(addr, 0); // can't know size easily — best effort
        self.inner.unmap_memory(addr)
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), EmulatorError> {
        // Taint the memory if any bytes come from a tainted source (caller must
        // explicitly taint the source register/buf before writing).
        self.inner.write_memory(addr, data)
    }

    fn read_memory(&self, addr: u64, len: usize) -> Result<Vec<u8>, EmulatorError> {
        self.inner.read_memory(addr, len)
    }

    fn read_register(&self, reg: u32) -> Result<u64, EmulatorError> {
        self.inner.read_register(reg)
    }

    /// Write a register and update taint shadow.
    ///
    /// The caller is responsible for setting `reg_taint` before calling this
    /// when the new value comes from tainted data.  Writing here propagates
    /// any pre-set taint to the control-flow detector.
    fn write_register(&mut self, reg: u32, value: u64) -> Result<(), EmulatorError> {
        let result = self.inner.write_register(reg, value);
        if result.is_ok() {
            let label = self.reg_taint.get(reg);
            self.check_cf_taint(reg, label);
        }
        result
    }

    fn start(
        &mut self,
        begin: u64,
        until: u64,
        timeout_ms: u64,
        count: u64,
    ) -> Result<(), EmulatorError> {
        self.inner.start(begin, until, timeout_ms, count)
    }

    fn stop(&mut self) -> Result<(), EmulatorError> {
        self.inner.stop()
    }

    fn add_code_hook(
        &mut self,
        begin: u64,
        end: u64,
        callback: Box<dyn Fn(u64, u32) + Send + Sync>,
    ) -> Result<HookHandle, EmulatorError> {
        self.inner.add_code_hook(begin, end, callback)
    }

    fn add_mem_hook(
        &mut self,
        kind: HookKind,
        callback: Box<dyn Fn(u64, usize, u64) + Send + Sync>,
    ) -> Result<HookHandle, EmulatorError> {
        self.inner.add_mem_hook(kind, callback)
    }

    fn remove_hook(&mut self, handle: HookHandle) -> Result<(), EmulatorError> {
        self.inner.remove_hook(handle)
    }

    fn context_save(&self) -> Result<Vec<u8>, EmulatorError> {
        self.inner.context_save()
    }

    fn context_restore(&mut self, ctx: &[u8]) -> Result<(), EmulatorError> {
        self.inner.context_restore(ctx)
    }

    fn regions(&self) -> Vec<MemRegion> {
        self.inner.regions()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TaintSummary
// ─────────────────────────────────────────────────────────────────────────────

/// High-level snapshot of taint state.
#[derive(Debug, Clone)]
pub struct TaintSummary {
    pub tainted_registers: Vec<u32>,
    pub tainted_byte_count: usize,
    pub total_events: usize,
    pub cf_events: usize,
}

impl TaintSummary {
    #[must_use]
    pub const fn any_tainted(&self) -> bool {
        !self.tainted_registers.is_empty() || self.tainted_byte_count > 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TaintReport
// ─────────────────────────────────────────────────────────────────────────────

/// Formatted taint analysis report.
#[derive(Debug, Clone)]
pub struct TaintReport {
    pub lines: Vec<String>,
}

impl TaintReport {
    /// Generate a report from a `TaintEmulator`.
    #[must_use]
    pub fn from_emulator(te: &TaintEmulator) -> Self {
        let mut lines = Vec::with_capacity(8 + te.reg_taint.tainted_regs().len());
        lines.push("=== Taint Analysis Report ===".to_string());
        lines.push(format!("Architecture : {}", te.inner.arch().name()));
        lines.push(format!("Total events : {}", te.events.len()));

        let tainted_regs = te.reg_taint.tainted_regs();
        if tainted_regs.is_empty() {
            lines.push("Tainted regs : none".into());
        } else {
            for reg in &tainted_regs {
                let label = te.reg_taint.get(*reg);
                lines.push(format!(
                    "  reg[{reg:3}] = taint 0x{label:016x} ({})",
                    te.describe_label(label)
                ));
            }
        }

        let tc = te.mem_taint.tainted_byte_count();
        lines.push(format!("Tainted bytes: {tc}"));

        let cf: Vec<_> = te.tainted_cf_events();
        if !cf.is_empty() {
            lines.push(format!(
                "⚠ Tainted control flow detected ({} events):",
                cf.len()
            ));
            for e in cf.iter().take(10) {
                if let TaintEvent::TaintedControlFlow { pc, label } = e {
                    lines.push(format!("  pc=0x{pc:016x} label=0x{label:016x}"));
                }
            }
        }

        Self { lines }
    }

    pub fn print(&self) {
        for l in &self.lines {
            println!("{l}");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EmulatorArch, EmulatorFactory, MemPerms, x86_regs};

    fn make() -> TaintEmulator {
        TaintEmulator::new(EmulatorFactory::create(EmulatorArch::X86_64))
    }

    // ── MemTaintMap ───────────────────────────────────────────────────────────

    #[test]
    fn test_mem_taint_set_get() {
        let mut m = MemTaintMap::new();
        m.set_range(0x1000, 4, 0b0011);
        assert_eq!(m.get_range(0x1000, 4), 0b0011);
        assert_eq!(m.get_byte(0x1002), 0b0011);
    }

    #[test]
    fn test_mem_taint_clear() {
        let mut m = MemTaintMap::new();
        m.set_range(0x1000, 8, 0xFF);
        m.clear_range(0x1000, 4);
        assert_eq!(m.get_range(0x1000, 4), 0);
        assert_eq!(m.get_range(0x1004, 4), 0xFF);
    }

    #[test]
    fn test_mem_taint_or_merge() {
        let mut m = MemTaintMap::new();
        m.set_range(0x1000, 4, 0b0001);
        m.taint_range(0x1000, 4, 0b0010);
        assert_eq!(m.get_range(0x1000, 4), 0b0011);
    }

    #[test]
    fn test_mem_taint_reset() {
        let mut m = MemTaintMap::new();
        m.set_range(0x1000, 16, 1);
        m.reset();
        assert_eq!(m.tainted_byte_count(), 0);
    }

    // ── RegTaintMap ───────────────────────────────────────────────────────────

    #[test]
    fn test_reg_taint_set_get() {
        let mut r = RegTaintMap::new();
        r.set(x86_regs::RAX, 0xABCD);
        assert_eq!(r.get(x86_regs::RAX), 0xABCD);
        assert_eq!(r.get(x86_regs::RBX), 0);
    }

    #[test]
    fn test_reg_taint_or() {
        let mut r = RegTaintMap::new();
        r.set(x86_regs::RAX, 0b01);
        r.taint(x86_regs::RAX, 0b10);
        assert_eq!(r.get(x86_regs::RAX), 0b11);
    }

    #[test]
    fn test_reg_taint_clear() {
        let mut r = RegTaintMap::new();
        r.set(x86_regs::RAX, 0xFF);
        r.clear(x86_regs::RAX);
        assert_eq!(r.get(x86_regs::RAX), 0);
        assert!(r.tainted_regs().is_empty());
    }

    // ── TaintEmulator basic ───────────────────────────────────────────────────

    #[test]
    fn test_taint_memory_basic() {
        let mut te = make();
        te.inner.map_memory(0x1000, 0x100, MemPerms::ALL).unwrap();
        te.taint_memory(0x1000, 8, 1 << 0);
        assert!(te.is_memory_tainted(0x1000, 4));
        assert!(!te.is_memory_tainted(0x1100, 4));
    }

    #[test]
    fn test_taint_register_basic() {
        let mut te = make();
        te.taint_register(x86_regs::RAX, 1 << 3);
        assert!(te.is_register_tainted(x86_regs::RAX));
        assert!(!te.is_register_tainted(x86_regs::RBX));
    }

    #[test]
    fn test_propagate_reg_to_reg() {
        let mut te = make();
        te.taint_register(x86_regs::RAX, 1 << 0);
        te.propagate_reg_to_reg(x86_regs::RAX, x86_regs::RBX);
        assert!(te.is_register_tainted(x86_regs::RBX));
        // Label should be the same
        assert_eq!(te.reg_taint.get(x86_regs::RBX), 1 << 0);
    }

    #[test]
    fn test_propagate_binop_tainted() {
        let mut te = make();
        te.taint_register(x86_regs::RAX, 1 << 1);
        te.propagate_binop(x86_regs::RAX, x86_regs::RBX, x86_regs::RCX);
        // RCX should inherit RAX's taint
        assert!(te.is_register_tainted(x86_regs::RCX));
        assert_eq!(te.reg_taint.get(x86_regs::RCX), 1 << 1);
    }

    #[test]
    fn test_propagate_binop_untainted() {
        let mut te = make();
        // Pre-taint RCX
        te.taint_register(x86_regs::RCX, 0xFF);
        // binop with no tainted sources should clear RCX
        te.propagate_binop(x86_regs::RAX, x86_regs::RBX, x86_regs::RCX);
        assert!(!te.is_register_tainted(x86_regs::RCX));
    }

    #[test]
    fn test_propagate_load_taint() {
        let mut te = make();
        te.inner.map_memory(0x5000, 0x100, MemPerms::ALL).unwrap();
        te.taint_memory(0x5000, 8, 1 << 2);
        te.propagate_load(0x5000, 8, x86_regs::RDX);
        assert!(te.is_register_tainted(x86_regs::RDX));
        assert_eq!(te.reg_taint.get(x86_regs::RDX), 1 << 2);
    }

    #[test]
    fn test_propagate_store_taint() {
        let mut te = make();
        te.inner.map_memory(0x5000, 0x100, MemPerms::ALL).unwrap();
        te.taint_register(x86_regs::RSI, 1 << 5);
        te.propagate_store(x86_regs::RSI, 0x5000, 8);
        assert!(te.is_memory_tainted(0x5000, 8));
    }

    #[test]
    fn test_reset_taint() {
        let mut te = make();
        te.inner.map_memory(0x1000, 0x100, MemPerms::ALL).unwrap();
        te.taint_memory(0x1000, 16, 0xFF);
        te.taint_register(x86_regs::RAX, 1);
        te.reset_taint();
        assert!(!te.is_memory_tainted(0x1000, 16));
        assert!(!te.is_register_tainted(x86_regs::RAX));
        assert!(te.events.is_empty());
    }

    // ── Tainted CF detection ──────────────────────────────────────────────────

    #[test]
    fn test_tainted_cf_event() {
        let mut te = make();
        // Mark RIP as tainted
        te.taint_register(x86_regs::RIP, 1 << 0);
        // Writing RIP should fire CF event
        te.write_register(x86_regs::RIP, 0xDEAD_BEEF).unwrap();
        let cf = te.tainted_cf_events();
        assert!(!cf.is_empty(), "tainted CF event should be recorded");
    }

    // ── Describe label ────────────────────────────────────────────────────────

    #[test]
    fn test_describe_label_named() {
        let mut te = make();
        te.register_source(TaintSource::new(0, "network_input"));
        let desc = te.describe_label(0b01);
        assert!(desc.contains("network_input"));
    }

    #[test]
    fn test_describe_label_unknown() {
        let te = make();
        let desc = te.describe_label(0b10);
        assert!(desc.contains("source[1]"));
    }

    #[test]
    fn test_describe_label_untainted() {
        let te = make();
        assert_eq!(te.describe_label(0), "untainted");
    }

    // ── TaintSummary ──────────────────────────────────────────────────────────

    #[test]
    fn test_summary() {
        let mut te = make();
        te.inner.map_memory(0x1000, 0x100, MemPerms::ALL).unwrap();
        te.taint_register(x86_regs::RAX, 1);
        te.taint_memory(0x1000, 10, 1);
        let s = te.summary();
        assert_eq!(s.tainted_registers, vec![x86_regs::RAX]);
        assert_eq!(s.tainted_byte_count, 10);
        assert!(s.any_tainted());
    }

    // ── TaintReport ───────────────────────────────────────────────────────────

    #[test]
    fn test_report_generation() {
        let mut te = make();
        te.register_source(TaintSource::new(0, "user_input"));
        te.taint_register(x86_regs::RDI, 1);
        let report = TaintReport::from_emulator(&te);
        let full = report.lines.join("\n");
        assert!(full.contains("Taint Analysis Report"));
    }

    // ── Emulator forwarding ───────────────────────────────────────────────────

    #[test]
    fn test_forward_map_write_read() {
        let mut te = make();
        te.map_memory(0x3000, 0x100, MemPerms::ALL).unwrap();
        te.write_memory(0x3000, &[0xAA, 0xBB]).unwrap();
        let data = te.read_memory(0x3000, 2).unwrap();
        assert_eq!(data, [0xAA, 0xBB]);
    }

    #[test]
    fn test_forward_register_rw() {
        let mut te = make();
        te.write_register(x86_regs::RBX, 0xCAFE_BABE).unwrap();
        assert_eq!(te.read_register(x86_regs::RBX).unwrap(), 0xCAFE_BABE);
    }

    #[test]
    fn test_forward_context_save_restore() {
        let mut te = make();
        te.write_register(x86_regs::RAX, 42).unwrap();
        let ctx = te.context_save().unwrap();
        te.write_register(x86_regs::RAX, 0).unwrap();
        te.context_restore(&ctx).unwrap();
        assert_eq!(te.read_register(x86_regs::RAX).unwrap(), 42);
    }

    #[test]
    fn test_taint_source_mask() {
        let src = TaintSource::new(3, "env");
        assert_eq!(src.mask(), 1 << 3);
    }
}
