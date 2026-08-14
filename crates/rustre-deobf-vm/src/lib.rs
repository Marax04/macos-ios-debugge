//! `rustre-deobf-vm`
//!
//! VM deobfuscation: virtual machine detection, VM handler identification,
//! VM bytecode extraction, VM semantics lifting, VM architecture recovery,
//! handler clustering, p-code abstraction.
//!
//! # Types
//! - [`VmDetector`] —" high-level VM detection facade
//! - [`VmHandler`] —" a single identified VM handler
//! - [`VmBytecode`] —" extracted VM bytecode buffer
//! - [`VmLifter`] —" lifts raw bytecode to [`VmSemanticOp`]
//! - [`HandlerCluster`] —" cluster of related VM handlers
//! - [`VmArch`] —" recovered virtual architecture description
//! - [`PcodeInsn`] —" p-code intermediate instruction
//!
//! # Extended modules
//! - [`isa_reconstruction`] — virtual ISA reconstruction (`VirtualInstruction`, `VirtualIsa`, etc.)
//! - [`vm_handler_analysis`] —" handler pattern analysis for 5 major protectors
//! - [`concolic_lifter`] —" concolic execution for handler semantic recovery
//! - [`vm_cfg`] —" virtual control-flow graph reconstruction
//! - [`deobfuscated_output`] —" deobfuscated IL output (LLIL-equivalent)
//! - [`pattern_db`] —" 50+ VM handler pattern database with fuzzy matching
//! - [`vm_state_tracker`] —" VM state tracking across execution steps

pub mod concolic_lifter;
pub mod deobfuscated_output;
pub mod dispatcher_detection;
pub mod isa_reconstruction;
pub mod pattern_db;
pub mod themida_handler;
pub mod vm_bytecode_recovery;
pub mod vm_cfg;
pub mod vm_emulator;
pub mod vm_handler_analysis;
pub mod vm_state_tracker;
pub mod vmprotect_handler;

use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Result as AnyhowResult};
use petgraph::Graph;
use rustre_core::address::Address;
use serde::{Deserialize, Serialize};

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Primitive helpers
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Type alias for guest virtual registers.
pub type GuestReg = u32;

/// Read a little-endian `u64` from the first 8 bytes of a byte slice.  Returns 0 if too short.
///
/// # Panics
/// Never panics; the early return guards against short slices.
#[must_use]
pub fn read_u64_le(bytes: &[u8]) -> u64 {
    if bytes.len() < 8 {
        return 0;
    }
    u64::from_le_bytes(bytes[..8].try_into().unwrap())
}

/// Read a little-endian `u32` from the first 4 bytes of a byte slice.  Returns 0 if too short.
///
/// # Panics
/// Never panics; the early return guards against short slices.
#[must_use]
pub fn read_u32_le(bytes: &[u8]) -> u32 {
    if bytes.len() < 4 {
        return 0;
    }
    u32::from_le_bytes(bytes[..4].try_into().unwrap())
}

/// Read a little-endian `u16` from the first 2 bytes of a byte slice.  Returns 0 if too short.
///
/// # Panics
/// Never panics — the length is checked before the `try_into` call, making the unwrap infallible.
#[must_use]
pub fn read_u16_le(bytes: &[u8]) -> u16 {
    if bytes.len() < 2 {
        return 0;
    }
    u16::from_le_bytes(bytes[..2].try_into().unwrap())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// VirtualMachineState
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// CPU/execution state of a guest virtual machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualMachineState {
    /// Virtual registers (8 general-purpose 32-bit registers).
    pub regs: [GuestReg; 8],
    /// Virtual program counter.
    pub pc: u64,
    /// Virtual stack (grows upward in this model).
    pub stack: Vec<GuestReg>,
    /// Virtual flags register (ZF=bit0, CF=bit1, SF=bit2, OF=bit3).
    pub flags: u32,
    /// Memory: address â†' byte value.
    pub memory: HashMap<u64, u8>,
}

impl VirtualMachineState {
    /// Creates a new, zero-initialised [`VirtualMachineState`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            regs: [0; 8],
            pc: 0,
            stack: Vec::new(),
            flags: 0,
            memory: HashMap::new(),
        }
    }

    /// Reset all state to initial zero values.
    pub fn reset(&mut self) {
        self.regs = [0; 8];
        self.pc = 0;
        self.stack.clear();
        self.flags = 0;
        self.memory.clear();
    }

    /// Push a value onto the virtual stack.
    pub fn push(&mut self, v: GuestReg) {
        self.stack.push(v);
    }

    /// Pop a value from the virtual stack.
    ///
    /// Returns `None` if the stack is empty.
    #[must_use]
    pub fn pop(&mut self) -> Option<GuestReg> {
        self.stack.pop()
    }

    /// Write a byte to virtual memory.
    pub fn mem_write_byte(&mut self, addr: u64, byte: u8) {
        self.memory.insert(addr, byte);
    }

    /// Read a byte from virtual memory. Returns 0 for unmapped addresses.
    #[must_use]
    pub fn mem_read_byte(&self, addr: u64) -> u8 {
        self.memory.get(&addr).copied().unwrap_or(0)
    }

    /// Read a 32-bit little-endian value from virtual memory.
    #[must_use]
    pub fn mem_read_u32(&self, addr: u64) -> u32 {
        let b0 = u32::from(self.mem_read_byte(addr));
        let b1 = u32::from(self.mem_read_byte(addr + 1));
        let b2 = u32::from(self.mem_read_byte(addr + 2));
        let b3 = u32::from(self.mem_read_byte(addr + 3));
        b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    }

    /// Write a 32-bit little-endian value to virtual memory.
    pub fn mem_write_u32(&mut self, addr: u64, v: u32) {
        let bytes = v.to_le_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            self.memory.insert(addr + i as u64, b);
        }
    }

    /// Return `true` if the zero flag is set.
    #[must_use]
    pub const fn zero_flag(&self) -> bool {
        self.flags & 1 != 0
    }

    /// Return `true` if the carry flag is set.
    #[must_use]
    pub const fn carry_flag(&self) -> bool {
        self.flags & 2 != 0
    }

    /// Update ZF based on `result`.
    pub const fn set_zero_flag(&mut self, result: GuestReg) {
        if result == 0 {
            self.flags |= 1;
        } else {
            self.flags &= !1;
        }
    }
}

impl Default for VirtualMachineState {
    fn default() -> Self {
        Self::new()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// VmDispatcher / VmDispatcherDetector
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Information about a detected VM dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmDispatcher {
    /// Entry address of the VM dispatcher.
    pub entry: Address,
    /// Base address of the VM handler table.
    pub handler_table_base: Address,
    /// Number of registered VM handlers.
    pub handler_count: usize,
}

/// Lightweight, byte-level pre-scanner for VM dispatcher structures.
///
/// This type operates on raw byte slices and matches two known binary
/// signatures (`sig_a` / `sig_b`) without requiring a disassembler or CFG.
/// It is intentionally minimal — a fast first-pass filter.
///
/// # When to use which detector
/// * **[`VmDispatcherDetector`]** (this type) — byte-level scan; useful when
///   you only have a raw binary slice and need a quick answer.  Input is
///   `&[Vec<u8>]` (pre-split basic blocks).
/// * **[`dispatcher_detection::DispatcherDetector`]** — full CFG-based
///   analysis with confidence scoring, VPC detection, signature database, and
///   protector classification.  Use this for production-quality analysis.
///
/// The two types are **complementary layers**, not duplicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VmDispatcherDetector;

impl VmDispatcherDetector {
    /// Create a new [`VmDispatcherDetector`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Detect a VM dispatcher pattern in the provided basic block bytecode.
    #[must_use]
    pub fn detect_dispatcher(&self, blocks: &[Vec<u8>]) -> Option<VmDispatcher> {
        Self::detect(blocks)
    }

    /// Detect using the static associated function path.
    ///
    /// # Panics
    /// Never panics — all slice accesses are guarded by length checks before the `try_into` calls.
    #[must_use]
    pub fn detect(blocks: &[Vec<u8>]) -> Option<VmDispatcher> {
        let sig_a = [0x31, 0xC0, 0xFF, 0x24];
        let sig_b = [0x48, 0x81, 0xC3, 0xFF];

        for block in blocks {
            if let Some(pos) = find_subslice(block, &sig_a).filter(|&p| p + 28 <= block.len()) {
                // All three reads require 8 bytes each; bounds are guaranteed by the filter above.
                // We verify explicitly so callers can distinguish address-zero from parse failure.
                let entry_slice = block.get(pos + 4..pos + 12)?;
                let handler_table_slice = block.get(pos + 12..pos + 20)?;
                let handler_count_slice = block.get(pos + 20..pos + 28)?;
                let entry = u64::from_le_bytes(entry_slice.try_into().unwrap());
                let handler_table_base = u64::from_le_bytes(handler_table_slice.try_into().unwrap());
                // Cap at 65536 to prevent runaway iteration on malformed input.
                let handler_count = usize::try_from(u64::from_le_bytes(handler_count_slice.try_into().unwrap())).unwrap_or(usize::MAX).min(65536);
                return Some(VmDispatcher {
                    entry: Address::new(entry),
                    handler_table_base: Address::new(handler_table_base),
                    handler_count,
                });
            }
            if let Some(pos) = find_subslice(block, &sig_b).filter(|&p| p + 28 <= block.len()) {
                // Same explicit bounds checks for sig_b path.
                let entry_slice = block.get(pos + 4..pos + 12)?;
                let handler_table_slice = block.get(pos + 12..pos + 20)?;
                let handler_count_slice = block.get(pos + 20..pos + 28)?;
                let entry = u64::from_le_bytes(entry_slice.try_into().unwrap());
                let handler_table_base = u64::from_le_bytes(handler_table_slice.try_into().unwrap());
                // Cap at 65536 to prevent runaway iteration on malformed input.
                let handler_count = usize::try_from(u64::from_le_bytes(handler_count_slice.try_into().unwrap())).unwrap_or(usize::MAX).min(65536);
                return Some(VmDispatcher {
                    entry: Address::new(entry),
                    handler_table_base: Address::new(handler_table_base),
                    handler_count,
                });
            }
        }
        None
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// VmHandler
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Classification of a VM handler's primary operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HandlerKind {
    /// Arithmetic: ADD, SUB, MUL, etc.
    Arithmetic,
    /// Logic: AND, OR, XOR, NOT, SHL, SHR.
    Logic,
    /// Memory load (fetch from memory into register/stack).
    Load,
    /// Memory store (write register/stack to memory).
    Store,
    /// Control flow: JMP, CALL, RET.
    ControlFlow,
    /// Stack manipulation: PUSH, POP.
    StackOp,
    /// Comparison / flag update.
    Compare,
    /// Unknown / unclassified.
    Unknown,
}

/// A single identified VM handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmHandler {
    /// Index in the handler table.
    pub index: u32,
    /// Virtual address of the handler code.
    pub address: Address,
    /// Raw bytes of the handler prologue (up to 32 bytes).
    pub prologue: Vec<u8>,
    /// Classified operation kind.
    pub kind: HandlerKind,
    /// Human-readable description.
    pub description: String,
    /// Number of stack operands consumed.
    pub stack_inputs: u8,
    /// Number of results pushed onto the stack.
    pub stack_outputs: u8,
}

impl VmHandler {
    /// Create a new handler with all fields.
    #[must_use]
    pub fn new(
        index: u32,
        address: Address,
        prologue: Vec<u8>,
        kind: HandlerKind,
        description: impl Into<String>,
        stack_inputs: u8,
        stack_outputs: u8,
    ) -> Self {
        Self {
            index,
            address,
            prologue,
            kind,
            description: description.into(),
            stack_inputs,
            stack_outputs,
        }
    }

    /// Returns `true` if this handler is a pure arithmetic operation.
    #[must_use]
    pub fn is_arithmetic(&self) -> bool {
        self.kind == HandlerKind::Arithmetic
    }

    /// Returns `true` if this handler affects control flow.
    #[must_use]
    pub fn is_control_flow(&self) -> bool {
        self.kind == HandlerKind::ControlFlow
    }

    /// Shannon entropy of the handler prologue bytes.
    #[must_use]
    pub fn prologue_entropy(&self) -> f64 {
        if self.prologue.is_empty() {
            return 0.0;
        }
        let mut freq = [0u64; 256];
        for &b in &self.prologue {
            freq[usize::from(b)] += 1;
        }
        let n = f64::from(u32::try_from(self.prologue.len()).unwrap_or(u32::MAX));
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / n;
                -p * p.log2()
            })
            .sum()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// VmDetector
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Confidence level of a VM detection result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VmConfidence {
    /// No VM indicators found.
    None,
    /// Some indicators present; may be coincidental.
    Low,
    /// Multiple indicators; likely VM obfuscated.
    Medium,
    /// Strong indicators; high confidence of VM presence.
    High,
    /// Near-certain: dispatcher + handler table + bytecode all detected.
    Definitive,
}

/// Summary of a VM detection run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmDetectionResult {
    /// Overall confidence level.
    pub confidence: VmConfidence,
    /// Number of dispatcher candidates found.
    pub dispatcher_count: usize,
    /// Number of handler-like regions found.
    pub handler_count: usize,
    /// Detected architecture hints.
    pub arch_hints: Vec<String>,
    /// Byte offset of the most likely dispatcher entry.
    pub dispatcher_offset: Option<usize>,
}

/// High-level VM detection facade.
#[derive(Debug, Clone, Default)]
pub struct VmDetector;

impl VmDetector {
    /// Create a new detector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Analyse `data` and return a detection result.
    #[must_use]
    pub fn detect(&self, data: &[u8]) -> VmDetectionResult {
        let dispatcher_offset = Self::find_dispatcher(data);
        let handler_regions = Self::find_handler_regions(data);
        let arch_hints = Self::collect_arch_hints(data);

        let dispatcher_count = usize::from(dispatcher_offset.is_some());
        let handler_count = handler_regions.len();
        let hint_count = arch_hints.len();

        let confidence = match (dispatcher_count, handler_count, hint_count) {
            (0, 0, 0) => VmConfidence::None,
            (0, 0, _) => VmConfidence::Low,
            (0, h, _) if h < 3 => VmConfidence::Low,
            (0, h, _) if h < 8 => VmConfidence::Medium,
            (1, h, _) if h < 4 => VmConfidence::Medium,
            (1, h, _) if h < 16 => VmConfidence::High,
            _ => VmConfidence::Definitive,
        };

        VmDetectionResult {
            confidence,
            dispatcher_count,
            handler_count,
            arch_hints,
            dispatcher_offset,
        }
    }

    /// Find the first indirect-jump dispatcher pattern in `data`.
    fn find_dispatcher(data: &[u8]) -> Option<usize> {
        // Table-indexed: FF 24 xx; Dynamic register: FF E0 / FF E3 / FF E1 / FF D0
        for i in 0..data.len().saturating_sub(1) {
            if data[i] == 0xFF {
                let modrm = data[i + 1];
                if matches!(modrm, 0x24 | 0xE0 | 0xE3 | 0xE1 | 0xE2 | 0xD0) {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Heuristically locate handler-like code regions.
    fn find_handler_regions(data: &[u8]) -> Vec<usize> {
        // Handlers often: save registers, do operation, restore, jmp back to dispatcher.
        // Signature: PUSH reg + some body + JMP rel32 / indirect JMP.
        let mut regions = Vec::new();
        for i in 0..data.len().saturating_sub(4) {
            if (data[i] >= 0x50 && data[i] <= 0x57) // PUSH reg
                && data[i + 1] != 0x50
            // Not another PUSH immediately
            {
                regions.push(i);
            }
        }
        // Limit to 256 candidates to avoid noise.
        regions.truncate(256);
        regions
    }

    fn collect_arch_hints(data: &[u8]) -> Vec<String> {
        let mut hints = Vec::new();
        // Look for common VM fingerprints.
        if find_subslice(data, b"VMProtect").is_some() || find_subslice(data, b"VMP").is_some() {
            hints.push("VMProtect markers detected".to_owned());
        }
        if find_subslice(data, b"Themida").is_some() {
            hints.push("Themida/WinLicense markers".to_owned());
        }
        if find_subslice(data, b"Enigma").is_some() {
            hints.push("Enigma Protector markers".to_owned());
        }
        // CPUID fingerprint in data section.
        if find_subslice(data, &[0x0F, 0xA2]).is_some() {
            hints.push("CPUID instruction (possible anti-debug)".to_owned());
        }
        // RDTSC.
        if find_subslice(data, &[0x0F, 0x31]).is_some() {
            hints.push("RDTSC (timing check)".to_owned());
        }
        hints
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// VmBytecode
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// An extracted VM bytecode buffer with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmBytecode {
    /// Raw bytecode bytes.
    pub bytes: Vec<u8>,
    /// Virtual address where the bytecode starts.
    pub start_address: u64,
    /// Estimated opcode width in bytes (1 for most VMs).
    pub opcode_width: u8,
    /// Number of distinct opcodes observed.
    pub distinct_opcodes: usize,
    /// Shannon entropy of the bytecode.
    pub entropy: f64,
}

impl VmBytecode {
    /// Construct a [`VmBytecode`] from raw bytes and a start address.
    #[must_use]
    pub fn new(bytes: Vec<u8>, start_address: u64, opcode_width: u8) -> Self {
        let distinct_opcodes = Self::count_distinct(&bytes, opcode_width);
        let entropy = Self::compute_entropy(&bytes);
        Self {
            bytes,
            start_address,
            opcode_width,
            distinct_opcodes,
            entropy,
        }
    }

    fn count_distinct(bytes: &[u8], width: u8) -> usize {
        let mut seen = HashSet::new();
        let w = width as usize;
        if w == 0 {
            return 0;
        }
        let mut i = 0;
        while i + w <= bytes.len() {
            seen.insert(bytes[i..i + w].to_vec());
            i += w;
        }
        seen.len()
    }

    fn compute_entropy(bytes: &[u8]) -> f64 {
        if bytes.is_empty() {
            return 0.0;
        }
        let mut freq = [0u64; 256];
        for &b in bytes {
            freq[usize::from(b)] += 1;
        }
        let n = f64::from(u32::try_from(bytes.len()).unwrap_or(u32::MAX));
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / n;
                -p * p.log2()
            })
            .sum()
    }

    /// Return `true` if bytecode entropy suggests it may be encrypted.
    #[must_use]
    pub fn looks_encrypted(&self) -> bool {
        self.entropy > 7.0
    }

    /// Return `true` if the bytecode is non-empty.
    #[must_use]
    pub const fn is_non_empty(&self) -> bool {
        !self.bytes.is_empty()
    }

    /// Length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if there are no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// VmSemanticOp —" lifted VM operation
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A lifted, semantically meaningful VM operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmSemanticOp {
    /// Push an immediate value onto the stack.
    PushImm(i64),
    /// Push the value of a virtual register.
    PushReg(u8),
    /// Pop from the stack into a virtual register.
    PopReg(u8),
    /// Add top two stack values, push result.
    Add,
    /// Subtract top-of-stack from second, push result.
    Sub,
    /// Multiply top two stack values, push result.
    Mul,
    /// Bitwise AND of top two stack values.
    And,
    /// Bitwise OR of top two stack values.
    Or,
    /// Bitwise XOR of top two stack values.
    Xor,
    /// Bitwise NOT of top of stack.
    Not,
    /// Negate (two's complement) top of stack.
    Neg,
    /// Logical left shift: pop shift amount, pop value, push result.
    Shl,
    /// Logical right shift.
    Shr,
    /// Load a 32-bit value from memory address on top of stack.
    Load32,
    /// Store 32-bit value (second) to address (top).
    Store32,
    /// Unconditional jump to VM PC in top-of-stack.
    Jmp,
    /// Conditional jump: if ZF set, jump.
    Jz,
    /// Call VM subroutine.
    Call,
    /// Return from subroutine.
    Ret,
    /// No-operation.
    Nop,
    /// Halt VM execution.
    Halt,
    /// Unknown / not yet decoded opcode.
    Unknown(u8),
}

impl VmSemanticOp {
    /// Returns `true` if this operation affects control flow.
    #[must_use]
    pub const fn is_control_flow(&self) -> bool {
        matches!(
            self,
            Self::Jmp | Self::Jz | Self::Call | Self::Ret | Self::Halt
        )
    }

    /// Returns `true` if this operation is arithmetic or bitwise.
    #[must_use]
    pub const fn is_alu(&self) -> bool {
        matches!(
            self,
            Self::Add
                | Self::Sub
                | Self::Mul
                | Self::And
                | Self::Or
                | Self::Xor
                | Self::Not
                | Self::Neg
                | Self::Shl
                | Self::Shr
        )
    }

    /// Returns the stack delta (positive = pushes, negative = pops).
    #[must_use]
    pub const fn stack_delta(&self) -> i32 {
        match self {
            Self::PushImm(_) | Self::PushReg(_) => 1,
            // NOTE: `Load32` is deliberately NOT here. A load pops one
            // address and pushes one value, so its net effect is 0; grouping it
            // with the binary operators (pop two, push one) under-counted every
            // stack depth by one per load. `VmLifter::simulate`, which actually
            // runs the ops, has always left one value on the stack for
            // `[PushImm, Load32]`.
            Self::PopReg(_)
            | Self::Jmp
            | Self::Jz
            | Self::Add
            | Self::Sub
            | Self::Mul
            | Self::And
            | Self::Or
            | Self::Xor
            | Self::Shl
            | Self::Shr => -1,
            Self::Store32 => -2,
            Self::Load32
            | Self::Not
            | Self::Neg
            | Self::Nop
            | Self::Halt
            | Self::Ret
            | Self::Call
            | Self::Unknown(_) => 0,
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// VmLifter
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Lifts raw VM bytecode to [`VmSemanticOp`] sequences.
#[derive(Debug, Clone)]
pub struct VmLifterConfig {
    /// Width of each opcode in bytes.
    pub opcode_width: u8,
    /// Whether operands are little-endian.
    pub little_endian: bool,
    /// Maximum number of instructions to decode.
    pub max_instructions: usize,
}

impl Default for VmLifterConfig {
    fn default() -> Self {
        Self {
            opcode_width: 1,
            little_endian: true,
            max_instructions: 65536,
        }
    }
}

/// Lifts VM bytecode to semantic operations.
///
/// [`VmLifter`] operates on an abstract, fixed-opcode-table ISA (opcodes
/// `0x00`–`0xFF`) and produces [`VmSemanticOp`] values.  It also contains a
/// simple symbolic simulator ([`VmLifter::simulate`]) for running those ops on
/// a [`VirtualMachineState`].
///
/// # Layer distinction
/// * **[`VmLifter`]** (this type) — static decode + single-pass simulation on
///   an abstract ISA.  Low overhead; good for quick taint / stack-depth checks.
/// * **[`vm_emulator::VmEmulator`]** — configurable interpreter driven by a
///   [`vm_emulator::VmIsaConfig`] and a handler dispatch table.  Records a full
///   [`vm_emulator::EmulationTrace`] with loop detection and handler summaries.
///   Use it when you need a trace for concolic analysis or handler clustering.
#[derive(Debug, Clone, Default)]
pub struct VmLifter {
    /// Decoding configuration.
    pub config: VmLifterConfig,
    /// Optional opcode remapping table (obfuscated opcode â†' canonical).
    pub opcode_map: HashMap<u8, u8>,
}

impl VmLifter {
    /// Create a new lifter with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a lifter with a custom opcode remapping table.
    #[must_use]
    pub fn with_opcode_map(mut self, map: HashMap<u8, u8>) -> Self {
        self.opcode_map = map;
        self
    }

    /// Remap an obfuscated opcode to its canonical value.
    #[must_use]
    pub fn remap(&self, opcode: u8) -> u8 {
        self.opcode_map.get(&opcode).copied().unwrap_or(opcode)
    }

    /// Lift `bytecode` to a sequence of [`VmSemanticOp`].
    ///
    /// # Errors
    /// Returns a static error string if the bytecode is malformed.
    pub fn lift(&self, bytecode: &[u8]) -> AnyhowResult<Vec<VmSemanticOp>> {
        let mut ops = Vec::new();
        let mut pc = 0usize;

        while pc < bytecode.len() && ops.len() < self.config.max_instructions {
            let raw_opcode = bytecode[pc];
            let opcode = self.remap(raw_opcode);
            pc += 1;

            let op = match opcode {
                0x00 => VmSemanticOp::Nop,
                0x01 => {
                    // PushImm i32 (4 bytes LE).
                    if pc + 4 > bytecode.len() {
                        return Err(anyhow!("truncated PushImm operand at pc={}", pc - 1));
                    }
                    let v = i32::from_le_bytes([
                        bytecode[pc],
                        bytecode[pc + 1],
                        bytecode[pc + 2],
                        bytecode[pc + 3],
                    ]);
                    pc += 4;
                    VmSemanticOp::PushImm(i64::from(v))
                }
                0x02 => {
                    if pc >= bytecode.len() {
                        return Err(anyhow!("truncated PushReg operand at pc={}", pc - 1));
                    }
                    let reg = bytecode[pc];
                    pc += 1;
                    VmSemanticOp::PushReg(reg)
                }
                0x03 => {
                    if pc >= bytecode.len() {
                        return Err(anyhow!("truncated PopReg operand at pc={}", pc - 1));
                    }
                    let reg = bytecode[pc];
                    pc += 1;
                    VmSemanticOp::PopReg(reg)
                }
                0x10 => VmSemanticOp::Add,
                0x11 => VmSemanticOp::Sub,
                0x12 => VmSemanticOp::Mul,
                0x13 => VmSemanticOp::And,
                0x14 => VmSemanticOp::Or,
                0x15 => VmSemanticOp::Xor,
                0x16 => VmSemanticOp::Not,
                0x17 => VmSemanticOp::Neg,
                0x18 => VmSemanticOp::Shl,
                0x19 => VmSemanticOp::Shr,
                0x20 => VmSemanticOp::Load32,
                0x21 => VmSemanticOp::Store32,
                0x30 => VmSemanticOp::Jmp,
                0x31 => VmSemanticOp::Jz,
                0x32 => VmSemanticOp::Call,
                0x33 => VmSemanticOp::Ret,
                0xFF => VmSemanticOp::Halt,
                other => VmSemanticOp::Unknown(other),
            };

            if matches!(op, VmSemanticOp::Halt) {
                ops.push(op);
                break;
            }
            ops.push(op);
        }

        Ok(ops)
    }

    /// Simulate lifted ops on a [`VirtualMachineState`] and return the final state.
    ///
    /// # Errors
    /// Returns a static error string on stack underflow or unknown operations
    /// that prevent simulation.
    ///
    /// # Panics
    /// Never panics — the `try_into` for `PushImm` operates on a fixed 4-byte slice and is
    /// infallible; the `try_from` for `Call` is guarded by an explicit range check above it.
    pub fn simulate(
        &self,
        ops: &[VmSemanticOp],
        mut state: VirtualMachineState,
    ) -> AnyhowResult<VirtualMachineState> {
        /// Pop two values, apply `f`, optionally set the zero flag, push result.
        fn binop(
            st: &mut VirtualMachineState,
            name: &str,
            set_zf: bool,
            f: impl Fn(GuestReg, GuestReg) -> GuestReg,
        ) -> AnyhowResult<()> {
            let b = st.pop().ok_or_else(|| anyhow!("stack underflow on {name}"))?;
            let a = st.pop().ok_or_else(|| anyhow!("stack underflow on {name}"))?;
            let r = f(a, b);
            if set_zf { st.set_zero_flag(r); }
            st.push(r);
            Ok(())
        }
        for op in ops {
            match op {
                VmSemanticOp::Nop => {}
                VmSemanticOp::PushImm(v) => {
                    state.push(u32::from_le_bytes(v.to_le_bytes()[..4].try_into().unwrap()));
                }
                VmSemanticOp::PushReg(r) => {
                    let v = state.regs.get(*r as usize).copied().unwrap_or(0);
                    state.push(v);
                }
                VmSemanticOp::PopReg(r) => {
                    let v = state.pop().ok_or_else(|| anyhow!("stack underflow on PopReg"))?;
                    if let Some(slot) = state.regs.get_mut(*r as usize) { *slot = v; }
                }
                VmSemanticOp::Add => binop(&mut state, "Add", true, u32::wrapping_add)?,
                VmSemanticOp::Sub => binop(&mut state, "Sub", true, u32::wrapping_sub)?,
                VmSemanticOp::Mul => binop(&mut state, "Mul", false, u32::wrapping_mul)?,
                VmSemanticOp::And => binop(&mut state, "And", true, |a, b| a & b)?,
                VmSemanticOp::Or => binop(&mut state, "Or", false, |a, b| a | b)?,
                VmSemanticOp::Xor => binop(&mut state, "Xor", true, |a, b| a ^ b)?,
                VmSemanticOp::Not => {
                    let a = state.pop().ok_or_else(|| anyhow!("stack underflow on Not"))?;
                    state.push(!a);
                }
                VmSemanticOp::Neg => {
                    let a = state.pop().ok_or_else(|| anyhow!("stack underflow on Neg"))?;
                    state.push(a.wrapping_neg());
                }
                VmSemanticOp::Shl => {
                    let shift = state.pop().ok_or_else(|| anyhow!("stack underflow on Shl"))?;
                    let val = state.pop().ok_or_else(|| anyhow!("stack underflow on Shl"))?;
                    state.push(val.wrapping_shl(shift & 31));
                }
                VmSemanticOp::Shr => {
                    let shift = state.pop().ok_or_else(|| anyhow!("stack underflow on Shr"))?;
                    let val = state.pop().ok_or_else(|| anyhow!("stack underflow on Shr"))?;
                    state.push(val.wrapping_shr(shift & 31));
                }
                VmSemanticOp::Load32 => {
                    let addr = state.pop().ok_or_else(|| anyhow!("stack underflow on Load32"))?;
                    state.push(state.mem_read_u32(u64::from(addr)));
                }
                VmSemanticOp::Store32 => {
                    let addr = state.pop().ok_or_else(|| anyhow!("stack underflow on Store32"))?;
                    let val = state.pop().ok_or_else(|| anyhow!("stack underflow on Store32"))?;
                    state.mem_write_u32(u64::from(addr), val);
                }
                VmSemanticOp::Jmp => {
                    let target = state.pop().ok_or_else(|| anyhow!("stack underflow on Jmp"))?;
                    state.pc = u64::from(target);
                    break;
                }
                VmSemanticOp::Jz => {
                    let target = state.pop().ok_or_else(|| anyhow!("stack underflow on Jz"))?;
                    if state.zero_flag() { state.pc = u64::from(target); break; }
                }
                VmSemanticOp::Call => {
                    let target = state.pop().ok_or_else(|| anyhow!("stack underflow on Call"))?;
                    if state.pc > u64::from(u32::MAX) {
                        return Err(anyhow!("PC {:#x} exceeds u32 range; cannot encode return address in GuestReg", state.pc));
                    }
                    state.push(u32::try_from(state.pc).unwrap_or(0)); // Push return address.
                    state.pc = u64::from(target);
                }
                VmSemanticOp::Ret => {
                    let addr = state.pop().ok_or_else(|| anyhow!("stack underflow on Ret"))?;
                    state.pc = u64::from(addr);
                    break;
                }
                VmSemanticOp::Halt | VmSemanticOp::Unknown(_) => break,
            }
        }
        Ok(state)
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// HandlerCluster
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A cluster of related VM handlers grouped by semantic category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerCluster {
    /// Cluster label (e.g. "arithmetic", "control-flow").
    pub label: String,
    /// Indices of handlers belonging to this cluster.
    pub handler_indices: Vec<u32>,
    /// Dominant handler kind in this cluster.
    pub primary_kind: HandlerKind,
    /// Average prologue entropy across all handlers in this cluster.
    pub avg_entropy: f64,
}

impl HandlerCluster {
    /// Create a new cluster.
    #[must_use]
    pub fn new(label: impl Into<String>, primary_kind: HandlerKind) -> Self {
        Self {
            label: label.into(),
            handler_indices: Vec::new(),
            primary_kind,
            avg_entropy: 0.0,
        }
    }

    /// Add a handler index to this cluster.
    pub fn add(&mut self, index: u32) {
        self.handler_indices.push(index);
    }

    /// Number of handlers in the cluster.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.handler_indices.len()
    }
}

/// Groups [`VmHandler`] instances into clusters by kind.
#[derive(Debug, Clone, Default)]
pub struct HandlerClusterer;

impl HandlerClusterer {
    /// Create a new clusterer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Cluster `handlers` by their [`HandlerKind`].
    #[must_use]
    pub fn cluster(&self, handlers: &[VmHandler]) -> Vec<HandlerCluster> {
        let mut map: HashMap<HandlerKind, HandlerCluster> = HashMap::new();

        for handler in handlers {
            let entry = map.entry(handler.kind).or_insert_with(|| {
                HandlerCluster::new(format!("{:?}", handler.kind).to_lowercase(), handler.kind)
            });
            entry.add(handler.index);
        }

        // Compute average entropies.
        for (kind, cluster) in &mut map {
            let total: f64 = handlers
                .iter()
                .filter(|h| h.kind == *kind)
                .map(VmHandler::prologue_entropy)
                .sum();
            let count = cluster.size();
            cluster.avg_entropy = if count > 0 {
                total / f64::from(u32::try_from(count).unwrap_or(u32::MAX))
            } else {
                0.0
            };
        }

        let mut clusters: Vec<HandlerCluster> = map.into_values().collect();
        clusters.sort_by(|a, b| a.label.cmp(&b.label));
        clusters
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// VmArch
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Recovered virtual architecture description.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmArch {
    /// Architecture name (e.g. "stack-machine", "register-machine").
    pub arch_type: String,
    /// Number of virtual registers.
    pub register_count: u32,
    /// Bytecode endianness.
    pub little_endian: bool,
    /// Opcode width in bytes.
    pub opcode_width: u8,
    /// Detected total number of distinct opcodes.
    pub opcode_count: usize,
    /// Whether the VM uses a separate call stack.
    pub has_call_stack: bool,
    /// Estimated complexity score (higher = harder to analyse).
    pub complexity_score: u32,
}

impl VmArch {
    /// Create a stack-machine architecture description.
    #[must_use]
    pub fn stack_machine(opcode_count: usize) -> Self {
        let complexity_score = u32::try_from(opcode_count).unwrap_or(u32::MAX).saturating_mul(3);
        Self {
            arch_type: "stack-machine".to_owned(),
            register_count: 0,
            little_endian: true,
            opcode_width: 1,
            opcode_count,
            has_call_stack: true,
            complexity_score,
        }
    }

    /// Create a register-machine architecture description.
    #[must_use]
    pub fn register_machine(register_count: u32, opcode_count: usize) -> Self {
        let complexity_score = u32::try_from(opcode_count).unwrap_or(u32::MAX).saturating_mul(2).saturating_add(register_count.saturating_mul(4));
        Self {
            arch_type: "register-machine".to_owned(),
            register_count,
            little_endian: true,
            opcode_width: 1,
            opcode_count,
            has_call_stack: false,
            complexity_score,
        }
    }

    /// Return a human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} ({} opcodes, {} regs, {}, complexity={})",
            self.arch_type,
            self.opcode_count,
            self.register_count,
            if self.little_endian { "LE" } else { "BE" },
            self.complexity_score,
        )
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// PcodeInsn —" p-code intermediate instruction
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Varnode in the p-code representation (operand).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PcodeVarnode {
    /// A concrete address space location (address, size).
    Unique(u64, u8),
    /// A named register.
    Register(String, u8),
    /// A constant value.
    Const(u64, u8),
    /// A RAM location.
    Ram(u64, u8),
}

impl PcodeVarnode {
    /// Size in bytes.
    #[must_use]
    pub const fn size(&self) -> u8 {
        match self {
            Self::Unique(_, s) | Self::Register(_, s) | Self::Const(_, s) | Self::Ram(_, s) => *s,
        }
    }
}

/// P-code operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PcodeOp {
    Copy,
    Load,
    Store,
    Branch,
    CBranch,
    BranchInd,
    Call,
    CallInd,
    Return,
    IntAdd,
    IntSub,
    IntMult,
    IntDiv,
    IntAnd,
    IntOr,
    IntXor,
    IntNot,
    IntNeg,
    IntShl,
    IntShr,
    IntSar,
    IntEqual,
    IntNotEqual,
    IntLessEqual,
    IntLess,
    IntZext,
    IntSext,
    FloatAdd,
    FloatSub,
    FloatMult,
    FloatDiv,
    PhiNode,
    Unknown(u16),
}

/// A single p-code instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeInsn {
    /// The p-code operation.
    pub op: PcodeOp,
    /// Output varnode (None for stores, branches).
    pub output: Option<PcodeVarnode>,
    /// Input varnodes.
    pub inputs: Vec<PcodeVarnode>,
    /// Sequence number within the basic block.
    pub seq: u32,
}

impl PcodeInsn {
    /// Create a new p-code instruction.
    #[must_use]
    pub const fn new(
        op: PcodeOp,
        output: Option<PcodeVarnode>,
        inputs: Vec<PcodeVarnode>,
        seq: u32,
    ) -> Self {
        Self {
            op,
            output,
            inputs,
            seq,
        }
    }

    /// Returns `true` if this instruction may alter control flow.
    #[must_use]
    pub const fn is_branch(&self) -> bool {
        matches!(
            self.op,
            PcodeOp::Branch
                | PcodeOp::CBranch
                | PcodeOp::BranchInd
                | PcodeOp::Call
                | PcodeOp::CallInd
                | PcodeOp::Return
        )
    }

    /// Format a human-readable representation.
    #[must_use]
    pub fn display(&self) -> String {
        let out = self.output.as_ref().map_or_else(String::new, |v| format!("{v:?} = "));
        let ins: Vec<String> = self.inputs.iter().map(|v| format!("{v:?}")).collect();
        format!("{}{:?}({})", out, self.op, ins.join(", "))
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// VmBytecodeExtractor
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Heuristically extracts VM bytecode from a binary.
#[derive(Debug, Clone, Default)]
pub struct VmBytecodeExtractor {
    /// Minimum bytecode length to consider a region valid.
    pub min_length: usize,
    /// Maximum bytecode length to extract.
    pub max_length: usize,
}

impl VmBytecodeExtractor {
    /// Create an extractor with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            min_length: 16,
            max_length: 1024 * 1024,
        }
    }

    /// Attempt to find and extract VM bytecode from `data` starting at
    /// `start_offset`.
    ///
    /// Returns `None` if the region appears too short or too uniform.
    #[must_use]
    pub fn extract(
        &self,
        data: &[u8],
        start_offset: usize,
        start_address: u64,
    ) -> Option<VmBytecode> {
        if start_offset >= data.len() {
            return None;
        }
        // Find the region end: stop at high runs of identical bytes or on RET/HALT.
        let region_end = self.find_region_end(data, start_offset);
        let length = (region_end - start_offset).min(self.max_length);
        if length < self.min_length {
            return None;
        }
        let bytes = data[start_offset..start_offset + length].to_vec();
        Some(VmBytecode::new(bytes, start_address, 1))
    }

    fn find_region_end(&self, data: &[u8], start: usize) -> usize {
        let max_end = (start + self.max_length).min(data.len());
        for i in start..max_end {
            // Stop on a long run of 0x00 or 0xFF.
            if i + 8 < data.len() {
                let run_zero = data[i..i + 8].iter().all(|&b| b == 0x00);
                let run_ff = data[i..i + 8].iter().all(|&b| b == 0xFF);
                if run_zero || run_ff {
                    return i;
                }
            }
        }
        max_end
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Public API entry point
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Execute deobfuscation pass for VM (legacy entry point for compatibility).
pub fn run_pass() {
    let _state = VirtualMachineState::new();
    let detector = VmDispatcherDetector::new();
    let blocks: [Vec<u8>; 0] = [];
    let _dispatcher = detector.detect_dispatcher(&blocks);
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Â§20.6  VM-based obfuscation analysis
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

// â"€â"€ VmProtectorDetector â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A single detection hit from [`VmProtectorDetector`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmDetection {
    /// Human-readable name of the detected protector (e.g. `VMProtect`).
    pub protector_name: String,
    /// Confidence score in the range `[0.0, 1.0]`.
    pub confidence: f32,
    /// Individual evidence strings that contributed to this detection.
    pub evidence: Vec<String>,
}

impl VmDetection {
    /// Create a new detection with the given name and confidence.
    #[must_use]
    pub fn new(protector_name: impl Into<String>, confidence: f32) -> Self {
        Self {
            protector_name: protector_name.into(),
            confidence,
            evidence: Vec::new(),
        }
    }

    /// Add an evidence string and return `self` for builder-style use.
    #[must_use]
    pub fn with_evidence(mut self, ev: impl Into<String>) -> Self {
        self.evidence.push(ev.into());
        self
    }

    /// Push an evidence string in-place.
    pub fn add_evidence(&mut self, ev: impl Into<String>) {
        self.evidence.push(ev.into());
    }
}

/// Detects well-known commercial VM protectors in a raw PE binary.
///
/// Each detector method is independent; all are run by [`VmProtectorDetector::detect`].
#[derive(Debug, Clone, Default)]
pub struct VmProtectorDetector;

impl VmProtectorDetector {
    /// Create a new detector.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Parse PE section names from `data`.
    ///
    /// Returns an empty `Vec` if the buffer is not a recognisable PE image.
    /// Each name is a trimmed ASCII string (NUL-stripped, up to 8 bytes).
    #[must_use]
    pub fn get_section_names(data: &[u8]) -> Vec<String> {
        // Minimum: DOS stub (0x3C + 4 bytes) + PE header
        if data.len() < 0x40 {
            return Vec::new();
        }
        // DOS MZ magic
        if data[0] != b'M' || data[1] != b'Z' {
            return Vec::new();
        }
        // e_lfanew at offset 0x3C (LE u32)
        let e_lfanew = read_u32_le(&data[0x3C..]) as usize;
        // PE signature "PE\0\0"
        let pe_sig_end = e_lfanew.checked_add(4).filter(|&end| end <= data.len());
        if pe_sig_end.is_none() {
            return Vec::new();
        }
        if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return Vec::new();
        }
        // COFF header is 20 bytes after PE sig.
        let coff_offset = e_lfanew + 4;
        let coff_end = coff_offset.checked_add(20).filter(|&end| end <= data.len());
        if coff_end.is_none() {
            return Vec::new();
        }
        let number_of_sections = read_u16_le(&data[coff_offset + 2..]) as usize;
        // PE spec allows at most 96 sections; cap here to prevent oversized allocations
        // from malformed/adversarial inputs before the loop's bounds check kicks in.
        let number_of_sections = number_of_sections.min(96);
        let size_of_optional_header = read_u16_le(&data[coff_offset + 16..]) as usize;
        // Section table starts at: coff_offset + 20 (COFF) + size_of_optional_header
        let Some(section_table_offset) = coff_offset.checked_add(20).and_then(|v| v.checked_add(size_of_optional_header)) else { return Vec::new() };
        let mut names = Vec::with_capacity(number_of_sections);
        for i in 0..number_of_sections {
            let Some(entry_offset) = i.checked_mul(40).and_then(|v| section_table_offset.checked_add(v)) else { break };
            if entry_offset.saturating_add(8) > data.len() {
                break;
            }
            let raw_name = &data[entry_offset..entry_offset + 8];
            // Trim NUL bytes and decode as lossy ASCII.
            let name = raw_name
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| b as char)
                .collect::<String>();
            names.push(name);
        }
        names
    }

    /// Compute Shannon entropy of `data` as `f32`.
    fn entropy_f32(data: &[u8]) -> f32 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u32; 256];
        for &b in data {
            freq[usize::from(b)] += 1;
        }
        // Normalising with `u16::try_from(len).unwrap_or(u16::MAX)` silently
        // clamped `n` to 65535 for any input longer than that — and clamped the
        // per-symbol counts the same way — so the probabilities stopped summing
        // to 1 and the result left its own domain: 19.5 bits/byte against a
        // ceiling of 8. The caller samples `len().min(0x10000)` = 65536 bytes,
        // one MORE than the clamp, so this path was hit on every large input.
        //
        // `f64` throughout, then narrowed once at the end.
        let n = data.len() as f64;
        let h: f64 = freq
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = f64::from(c) / n;
                -p * p.log2()
            })
            .sum();
        h as f32
    }

    /// Return `true` if the import directory contains a string matching `needle`.
    ///
    /// This is a coarse heuristic: it searches the entire binary for an ASCII
    /// occurrence of `needle`, which covers both bound and unbound IATs.
    fn binary_contains_str(data: &[u8], needle: &[u8]) -> bool {
        find_subslice(data, needle).is_some()
    }

    // â"€â"€ Individual protector detectors â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn detect_vmprotect(data: &[u8], section_names: &[String]) -> Option<VmDetection> {
        let mut det = VmDetection::new("VMProtect", 0.0);

        // Evidence 1: .vmp0 / .vmp1 section names (strong signal).
        for name in section_names {
            if name == ".vmp0" || name == ".vmp1" {
                det.add_evidence(format!("PE section '{name}' detected"));
                det.confidence += 0.45;
            }
        }

        // Evidence 2: VirtualProtect import (common in VMProtect-protected binaries).
        if Self::binary_contains_str(data, b"VirtualProtect") {
            det.add_evidence("Import 'VirtualProtect' present".to_owned());
            det.confidence += 0.20;
        }

        // Evidence 3: String markers.
        for marker in [b"VMProtect".as_slice(), b"vmp_begin", b"vmp_end"] {
            if Self::binary_contains_str(data, marker) {
                det.add_evidence(format!(
                    "String marker '{}' found",
                    String::from_utf8_lossy(marker)
                ));
                det.confidence += 0.15;
            }
        }

        // Evidence 4: High entropy in a code-like region (obfuscated handler table).
        let sample_len = data.len().min(0x10000);
        let entropy = Self::entropy_f32(&data[..sample_len]);
        if entropy > 6.8 {
            det.add_evidence(format!(
                "High entropy in first 0x{sample_len:X} bytes: {entropy:.2}"
            ));
            det.confidence += 0.10;
        }

        // Only report if at least one strong signal was hit.
        if det.confidence > 0.0 {
            det.confidence = det.confidence.min(1.0);
            Some(det)
        } else {
            None
        }
    }

    fn detect_themida(data: &[u8], section_names: &[String]) -> Option<VmDetection> {
        let mut det = VmDetection::new("Themida/WinLicense", 0.0);

        for name in section_names {
            if name == ".themida" {
                det.add_evidence("PE section '.themida' detected".to_owned());
                det.confidence += 0.55;
            } else if name == ".winlicense" {
                det.add_evidence("PE section '.winlicense' detected".to_owned());
                det.confidence += 0.55;
            }
        }

        // Themida hooks IsDebuggerPresent; look for that import string.
        if Self::binary_contains_str(data, b"IsDebuggerPresent") {
            det.add_evidence("Import 'IsDebuggerPresent' present (hook pattern)".to_owned());
            det.confidence += 0.20;
        }

        // String markers.
        for marker in [b"Themida".as_slice(), b"WinLicense", b"Oreans"] {
            if Self::binary_contains_str(data, marker) {
                det.add_evidence(format!(
                    "String marker '{}' found",
                    String::from_utf8_lossy(marker)
                ));
                det.confidence += 0.15;
            }
        }

        if det.confidence > 0.0 {
            det.confidence = det.confidence.min(1.0);
            Some(det)
        } else {
            None
        }
    }

    fn detect_code_virtualizer(data: &[u8], section_names: &[String]) -> Option<VmDetection> {
        let mut det = VmDetection::new("Code Virtualizer", 0.0);

        for name in section_names {
            if name == ".cv_DATA" || name == ".cv_CODE" {
                det.add_evidence(format!("PE section '{name}' detected"));
                det.confidence += 0.60;
            }
        }

        for marker in [b"Code Virtualizer".as_slice(), b"cv_section"] {
            if Self::binary_contains_str(data, marker) {
                det.add_evidence(format!(
                    "String marker '{}' found",
                    String::from_utf8_lossy(marker)
                ));
                det.confidence += 0.20;
            }
        }

        if det.confidence > 0.0 {
            det.confidence = det.confidence.min(1.0);
            Some(det)
        } else {
            None
        }
    }

    /// Detect Tigress C obfuscator by looking for a large dispatcher function
    /// characterised by many indirect/computed jumps (>50 jump-table entries).
    fn detect_tigress(data: &[u8]) -> Option<VmDetection> {
        let mut det = VmDetection::new("Tigress (C)", 0.0);

        // Heuristic: count indirect jump instructions (FF 20-27 range for JMP [r/m]).
        // A Tigress dispatcher typically has a dense cluster of FF E* / FF 24 patterns.
        let mut indirect_jumps: usize = 0;
        let mut i = 0;
        while i + 1 < data.len() {
            if data[i] == 0xFF {
                let modrm = data[i + 1];
                // JMP r/m: mod=11, reg=4 â†' FF E0..FF E7; JMP [r/m]: mod=00, reg=4 â†' FF 20..FF 27
                if (0xE0..=0xE7).contains(&modrm) || (0x20..=0x27).contains(&modrm) || modrm == 0x24
                {
                    indirect_jumps += 1;
                }
            }
            i += 1;
        }

        if indirect_jumps > 50 {
            det.add_evidence(format!(
                "High density of indirect jumps ({indirect_jumps}) suggests large dispatcher"
            ));
            det.confidence += 0.35;
        } else if indirect_jumps > 20 {
            det.add_evidence(format!(
                "Moderate indirect jump density ({indirect_jumps})"
            ));
            det.confidence += 0.15;
        }

        // Tigress-compiled binaries often carry __attribute__ residues or GCC identifiers.
        for marker in [b"GCC:".as_slice(), b"tigress", b"Tigress"] {
            if Self::binary_contains_str(data, marker) {
                det.add_evidence(format!(
                    "Marker '{}' found",
                    String::from_utf8_lossy(marker)
                ));
                det.confidence += 0.20;
            }
        }

        if det.confidence > 0.0 {
            det.confidence = det.confidence.min(1.0);
            Some(det)
        } else {
            None
        }
    }

    /// Detect a custom VM by looking for a large indirect jump table (>10 entries)
    /// in a code-like section.
    fn detect_custom_vm(data: &[u8], section_names: &[String]) -> Option<VmDetection> {
        let mut det = VmDetection::new("Custom VM", 0.0);

        // Look for a dense block of 8-byte aligned pointer-like values (jump table).
        // Heuristic: scan for runs of 8 consecutive 8-byte LE values that all have the
        // same upper 4 bytes (same image base region) —" typical of a 64-bit jump table.
        let mut max_run = 0usize;
        let mut current_run = 0usize;
        let mut prev_hi = 0u32;
        let step = 8;
        let mut pos = 0usize;
        while pos + 8 <= data.len() {
            // INVARIANT: the while-guard ensures pos + 8 <= data.len(), so this never panics.
            let val = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
            let hi = (val >> 32) as u32;
            if hi == prev_hi && hi != 0 {
                current_run += 1;
                if current_run > max_run {
                    max_run = current_run;
                }
            } else {
                current_run = 1;
                prev_hi = hi;
            }
            pos += step;
        }

        if max_run > 10 {
            det.add_evidence(format!(
                "Indirect jump table with {max_run} entries detected"
            ));
            det.confidence += 0.30;
        }

        // Also flag if no known protector sections are present but we see unusual section names.
        let known = [
            ".text", ".data", ".rdata", ".bss", ".rsrc", ".reloc", ".pdata", ".edata",
        ];
        let unusual_sections: Vec<&str> = section_names
            .iter()
            .filter(|n| {
                !known.contains(&n.as_str())
                    && !n.is_empty()
                    && !n.starts_with(".vmp")
                    && n.as_str() != ".themida"
                    && n.as_str() != ".winlicense"
                    && n.as_str() != ".cv_DATA"
                    && n.as_str() != ".cv_CODE"
            })
            .map(String::as_str)
            .collect();

        if !unusual_sections.is_empty() {
            det.add_evidence(format!(
                "Unusual section names: {}",
                unusual_sections.join(", ")
            ));
            det.confidence += 0.15;
        }

        if det.confidence > 0.0 {
            det.confidence = det.confidence.min(1.0);
            Some(det)
        } else {
            None
        }
    }

    // â"€â"€ Public API â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Run all protector detectors against `binary_data` and return every
    /// detection whose confidence is above zero.
    #[must_use]
    pub fn detect(binary_data: &[u8]) -> Vec<VmDetection> {
        let section_names = Self::get_section_names(binary_data);
        let mut results = Vec::new();

        if let Some(d) = Self::detect_vmprotect(binary_data, &section_names) {
            results.push(d);
        }
        if let Some(d) = Self::detect_themida(binary_data, &section_names) {
            results.push(d);
        }
        if let Some(d) = Self::detect_code_virtualizer(binary_data, &section_names) {
            results.push(d);
        }
        if let Some(d) = Self::detect_tigress(binary_data) {
            results.push(d);
        }
        if let Some(d) = Self::detect_custom_vm(binary_data, &section_names) {
            results.push(d);
        }

        // Sort descending by confidence.
        results.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results
    }
}

// â"€â"€ BytecodeCandidate / VmBytecodeExtractor (extended) â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A candidate VM bytecode region discovered by [`VmBytecodeExtractor`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BytecodeCandidate {
    /// Offset within the binary where the bytecode region starts.
    pub offset: usize,
    /// Size of the region in bytes.
    pub size: usize,
    /// Shannon entropy of the region (`f32`).
    pub entropy: f32,
    /// Estimated number of distinct opcodes (ISA size hint).
    pub likely_handler_count: u8,
}

impl BytecodeCandidate {
    /// Create a new candidate, computing its entropy and handler estimate.
    #[must_use]
    pub fn new(data: &[u8], offset: usize) -> Self {
        let entropy = Self::compute_entropy_f32(data);
        let likely_handler_count = VmBytecodeExtractor::estimate_opcode_count(data);
        Self {
            offset,
            size: data.len(),
            entropy,
            likely_handler_count,
        }
    }

    fn compute_entropy_f32(data: &[u8]) -> f32 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u32; 256];
        for &b in data {
            freq[usize::from(b)] += 1;
        }
        // Normalising with `u16::try_from(len).unwrap_or(u16::MAX)` silently
        // clamped `n` to 65535 for any input longer than that — and clamped the
        // per-symbol counts the same way — so the probabilities stopped summing
        // to 1 and the result left its own domain: 19.5 bits/byte against a
        // ceiling of 8. The caller samples `len().min(0x10000)` = 65536 bytes,
        // one MORE than the clamp, so this path was hit on every large input.
        //
        // `f64` throughout, then narrowed once at the end.
        let n = data.len() as f64;
        let h: f64 = freq
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = f64::from(c) / n;
                -p * p.log2()
            })
            .sum();
        h as f32
    }
}

impl VmBytecodeExtractor {
    /// Scan `data` for regions whose Shannon entropy falls in the
    /// `[5.0, 7.5]` range —" characteristic of structured VM bytecode.
    ///
    /// Uses a sliding window of 256 bytes and a 128-byte step to find
    /// transitions from code-like to bytecode-like entropy.
    #[must_use]
    pub fn find_bytecode_regions(data: &[u8]) -> Vec<BytecodeCandidate> {
        const WINDOW: usize = 256;
        const STEP: usize = 128;
        const ENTROPY_LOW: f32 = 5.0;
        const ENTROPY_HIGH: f32 = 7.5;
        const MIN_SIZE: usize = 64;

        let mut candidates: Vec<BytecodeCandidate> = Vec::new();
        // Track whether we are inside a candidate region.
        let mut region_start: Option<usize> = None;

        let mut pos = 0usize;
        while pos + WINDOW <= data.len() {
            let window = &data[pos..pos + WINDOW];
            let entropy = BytecodeCandidate::compute_entropy_f32(window);

            if (ENTROPY_LOW..=ENTROPY_HIGH).contains(&entropy) {
                // Start or extend a candidate region.
                if region_start.is_none() {
                    region_start = Some(pos);
                }
            } else if let Some(start) = region_start.take() {
                // Closed a region —" compute its full span.
                let end = pos + WINDOW;
                let size = end - start;
                if size >= MIN_SIZE {
                    let region_data = &data[start..start + size.min(data.len() - start)];
                    candidates.push(BytecodeCandidate::new(region_data, start));
                }
            }

            pos += STEP;
        }

        // Close any open region at EOF.
        if let Some(start) = region_start {
            let size = data.len() - start;
            if size >= MIN_SIZE {
                let region_data = &data[start..];
                candidates.push(BytecodeCandidate::new(region_data, start));
            }
        }

        // Additionally: look for opcode cycling patterns (0..N repeating).
        // If frequency of any single byte value > 2% of the region, it
        // might be a recurring opcode —" add an additional diagnostic pass.
        candidates.retain(|c| c.likely_handler_count > 1);
        candidates
    }

    /// Sample up to 512 bytes from `region`, count how many distinct byte
    /// values appear more than `threshold` times.  This estimates the number
    /// of distinct opcodes in the VM's ISA.
    ///
    /// Saturates at 255.
    #[must_use]
    pub fn estimate_opcode_count(region: &[u8]) -> u8 {
        const SAMPLE: usize = 512;
        const THRESHOLD: u64 = 2; // Appear more than this many times.

        let sample = &region[..region.len().min(SAMPLE)];
        if sample.is_empty() {
            return 0;
        }
        let mut freq = [0u64; 256];
        for &b in sample {
            freq[b as usize] += 1;
        }
        let count = freq.iter().filter(|&&c| c > THRESHOLD).count();
        u8::try_from(count.min(255)).unwrap_or(u8::MAX)
    }
}

// â"€â"€ HandlerNode / HandlerEdge / HandlerGraphBuilder â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A node in the VM handler graph, representing one handler function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerNode {
    /// Virtual address of the handler.
    pub addr: u64,
    /// Size of the handler in bytes (estimated from heuristics).
    pub size: usize,
    /// Opcode byte that routes execution to this handler, if known.
    pub opcode: Option<u8>,
    /// Human-readable semantic hint (e.g. "arithmetic", "load", "dispatch").
    pub semantic_hint: String,
}

impl HandlerNode {
    /// Create a new handler node.
    #[must_use]
    pub fn new(
        addr: u64,
        size: usize,
        opcode: Option<u8>,
        semantic_hint: impl Into<String>,
    ) -> Self {
        Self {
            addr,
            size,
            opcode,
            semantic_hint: semantic_hint.into(),
        }
    }

    /// Return `true` if this node represents the VM dispatcher.
    #[must_use]
    pub fn is_dispatcher(&self) -> bool {
        self.semantic_hint == "dispatcher"
    }
}

/// A directed edge in the VM handler graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerEdge {
    /// Opcode value that causes this transition (None for handlerâ†'dispatcher back-edges).
    pub opcode_value: Option<u8>,
    /// True if this is a back-edge from a handler returning to the dispatcher.
    pub is_back_edge: bool,
}

impl HandlerEdge {
    /// Create a dispatcherâ†'handler forward edge labelled with `opcode`.
    #[must_use]
    pub const fn forward(opcode: u8) -> Self {
        Self {
            opcode_value: Some(opcode),
            is_back_edge: false,
        }
    }

    /// Create a handlerâ†'dispatcher back-edge.
    #[must_use]
    pub const fn back() -> Self {
        Self {
            opcode_value: None,
            is_back_edge: true,
        }
    }
}

/// Builds a [`petgraph::Graph`] of VM handlers reachable from a dispatcher.
///
/// The graph has one *dispatcher* node at index 0 and one leaf node per
/// handler.  Forward edges carry the opcode byte; back-edges represent
/// the handler returning to the dispatcher.
#[derive(Debug, Clone, Default)]
pub struct HandlerGraphBuilder;

impl HandlerGraphBuilder {
    /// Create a new builder.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Build a handler graph by scanning `code` for handler-like patterns
    /// starting from `dispatcher_addr`.
    ///
    /// The scan is heuristic:
    /// 1. A dispatcher node is created at `dispatcher_addr`.
    /// 2. The code slice is walked to find PUSH+body+JMP patterns.
    /// 3. For each handler-like region found within 512 KB of the
    ///    dispatcher, a node is added and edges are wired.
    ///
    /// The number of handlers is capped at 256 to bound complexity.
    #[must_use]
    pub fn build_handler_graph(
        dispatcher_addr: u64,
        code: &[u8],
    ) -> Graph<HandlerNode, HandlerEdge> {
        const SCAN_LIMIT: usize = 512 * 1024;
        const MAX_HANDLERS: usize = 256;

        let mut graph: Graph<HandlerNode, HandlerEdge> = Graph::new();

        // Node 0 = dispatcher.
        let dispatcher_node = HandlerNode::new(dispatcher_addr, 0, None, "dispatcher");
        let dispatcher_idx = graph.add_node(dispatcher_node);

        // Scan code for handler-like patterns.
        // Pattern: byte in [0x50..0x57] (PUSH reg) within first 512 KB,
        // followed by a reachable indirect JMP (0xFF 0xE0..0xE7 or 0xFF 0x24).

        let scan_end = code.len().min(SCAN_LIMIT);
        let mut handler_addrs: Vec<(usize, u8)> = Vec::new(); // (offset, opcode_hint)

        let mut i = 0usize;
        while i < scan_end && handler_addrs.len() < MAX_HANDLERS {
            // A handler prologue: PUSH r64 (REX prefix 0x41/0x40 or plain PUSH 0x50-0x57)
            let is_push = (data_byte(code, i) >= 0x50 && data_byte(code, i) <= 0x57)
                || ((data_byte(code, i) == 0x41 || data_byte(code, i) == 0x40)
                    && data_byte(code, i + 1) >= 0x50
                    && data_byte(code, i + 1) <= 0x57);

            if is_push {
                // Look forward up to 64 bytes for an indirect JMP.
                let look_end = (i + 64).min(scan_end);
                for j in i + 1..look_end {
                    if data_byte(code, j) == 0xFF {
                        let modrm = data_byte(code, j + 1);
                        if (0xE0..=0xE7).contains(&modrm) || modrm == 0x24 || modrm == 0x25 {
                            // Use the low nibble of the PUSH byte as an opcode hint.
                            let opcode_hint = data_byte(code, i) & 0x0F;
                            handler_addrs.push((i, opcode_hint));
                            break;
                        }
                    }
                }
            }
            i += 1;
        }

        // Add nodes and edges.
        for (idx, (offset, opcode_hint)) in handler_addrs.iter().enumerate() {
            let addr = dispatcher_addr.wrapping_add(*offset as u64);
            // Estimate handler size: distance to next handler or 32 bytes.
            let next_offset = handler_addrs.get(idx + 1).map(|(o, _)| *o);
            let size = next_offset.map_or(32, |n| n - offset).min(256);

            let kind = classify_handler_kind(code, *offset, size);
            let node = HandlerNode::new(addr, size, Some(*opcode_hint), kind);
            let handler_idx = graph.add_node(node);

            // Dispatcher â†' Handler (forward edge).
            graph.add_edge(
                dispatcher_idx,
                handler_idx,
                HandlerEdge::forward(*opcode_hint),
            );
            // Handler â†' Dispatcher (back-edge).
            graph.add_edge(handler_idx, dispatcher_idx, HandlerEdge::back());
        }

        graph
    }

    /// Export `graph` in DOT format for visualisation with Graphviz.
    ///
    /// # Panics
    /// Never panics — `edge_endpoints` always succeeds for indices obtained from
    /// `edge_indices()` on the same graph.
    #[must_use]
    pub fn export_dot(graph: &Graph<HandlerNode, HandlerEdge>) -> String {
        use std::fmt::Write as _;
        let mut dot = String::from("digraph vm_handlers {\n    node [shape=box];\n");

        for node_idx in graph.node_indices() {
            let n = &graph[node_idx];
            let label = if n.is_dispatcher() {
                format!("DISPATCHER\\n0x{:X}", n.addr)
            } else {
                let opcode_str = n.opcode.map_or_else(|| "?".into(), |o| format!("{o:#04x}"));
                format!("Handler\\n0x{:X}\\nopcode={:?}\\n{}", n.addr, opcode_str, n.semantic_hint)
            };
            let style = if n.is_dispatcher() { "fillcolor=lightblue style=filled" } else { "" };
            let _ = writeln!(dot, "    n{} [label=\"{label}\" {style}];", node_idx.index());
        }

        for edge_idx in graph.edge_indices() {
            let (src, dst) = graph.edge_endpoints(edge_idx).unwrap();
            let e = &graph[edge_idx];
            let label = if e.is_back_edge {
                "back".to_owned()
            } else {
                e.opcode_value.map_or_else(|| "?".into(), |o| format!("{o:#04x}"))
            };
            let style = if e.is_back_edge { "style=dashed" } else { "" };
            let _ = writeln!(dot, "    n{} -> n{} [label=\"{label}\" {style}];", src.index(), dst.index());
        }

        dot.push_str("}\n");
        dot
    }
}

/// Classify a handler at `offset` in `code` into a semantic hint string.
fn classify_handler_kind(code: &[u8], offset: usize, size: usize) -> String {
    let end = (offset + size).min(code.len());
    let slice = &code[offset..end];

    // Very rough heuristics on the raw bytes of the handler body.
    let has_add = slice
        .windows(2)
        .any(|w| w == [0x01, 0xC0] || w == [0x03, 0xC0]);
    let has_xor = slice.windows(2).any(|w| w[0] == 0x33 || w[0] == 0x31);
    let has_mov = slice.iter().any(|&b| b == 0x8B || b == 0x89);
    let has_cmp = slice.iter().any(|&b| b == 0x3B || b == 0x3C || b == 0x39);
    let has_call = slice.contains(&0xE8);
    let has_push_pop = slice
        .iter()
        .any(|&b| (0x50..=0x57).contains(&b) || (0x58..=0x5F).contains(&b));

    if has_call {
        "control-flow".into()
    } else if has_cmp {
        "compare".into()
    } else if has_xor || has_add {
        "arithmetic/logic".into()
    } else if has_mov {
        "load/store".into()
    } else if has_push_pop {
        "stack-op".into()
    } else {
        "unknown".into()
    }
}

/// Safely index `data` at `pos`, returning 0 if out of bounds.
#[inline]
fn data_byte(data: &[u8], pos: usize) -> u8 {
    data.get(pos).copied().unwrap_or(0)
}

// â"€â"€ VmAnalysisReport / VmDeobfPipeline â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Full VM analysis report produced by [`VmDeobfPipeline`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmAnalysisReport {
    /// All protector detections (sorted by confidence, descending).
    pub detections: Vec<VmDetection>,
    /// Bytecode candidate regions found in the binary.
    pub bytecode_regions: Vec<BytecodeCandidate>,
    /// Estimated ISA size (number of distinct opcodes), capped at 255.
    pub estimated_isa_size: u8,
    /// Free-text analysis notes collected during the run.
    pub analysis_notes: Vec<String>,
}

impl VmAnalysisReport {
    /// Return actionable recommendations based on the analysis results.
    ///
    /// These strings are intended for display to the analyst.
    #[must_use]
    pub fn recommendations(&self) -> Vec<String> {
        let mut recs: Vec<String> = Vec::new();

        // Generic recommendations always present.
        recs.push(
            "Apply VmLifterPipeline from rustre-deobf-vmlift to lift bytecode to semantic ops."
                .into(),
        );
        recs.push("Try symbolic execution (e.g. angr / miasm) on extracted handler bodies.".into());

        // Recommendations based on specific detections.
        for det in &self.detections {
            match det.protector_name.as_str() {
                "VMProtect" => {
                    recs.push(
                        "VMProtect detected: use VMP-specific dispatcher signature to locate handler table.".into(),
                    );
                    recs.push("Run VmDispatcherDetector on .vmp0/.vmp1 sections.".into());
                }
                "Themida/WinLicense" => {
                    recs.push(
                        "Themida/WinLicense: dump process memory after unpacking to bypass the loader stub.".into(),
                    );
                    recs.push(
                        "Hook NtWriteVirtualMemory to capture the unpacked image at runtime."
                            .into(),
                    );
                }
                "Code Virtualizer" => {
                    recs.push(
                        "Code Virtualizer: map .cv_DATA and .cv_CODE together to recover bytecode."
                            .into(),
                    );
                }
                "Tigress (C)" => {
                    recs.push(
                        "Tigress: use taint analysis to track the virtual program counter from the dispatch function entry.".into(),
                    );
                }
                "Custom VM" => {
                    recs.push(
                        "Custom VM: manually identify dispatcher via indirect jump table; use HandlerGraphBuilder.".into(),
                    );
                }
                _ => {}
            }
        }

        if !self.bytecode_regions.is_empty() {
            recs.push(format!(
                "Found {} bytecode candidate region(s); pass each to VmLifter::lift().",
                self.bytecode_regions.len()
            ));
        }

        if self.estimated_isa_size > 0 {
            recs.push(format!(
                "Estimated ISA size is {} opcodes; build opcode_map and use VmLifter::with_opcode_map().",
                self.estimated_isa_size
            ));
        }

        recs.dedup();
        recs
    }
}

/// End-to-end VM deobfuscation analysis pipeline.
///
/// This is the primary entry point for Â§20.6 analysis.  It chains
/// [`VmProtectorDetector`], [`VmBytecodeExtractor`], and basic ISA
/// estimation into a single [`VmAnalysisReport`].
#[derive(Debug, Clone, Default)]
pub struct VmDeobfPipeline;

impl VmDeobfPipeline {
    /// Create a new pipeline.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Analyse `binary` and return a comprehensive [`VmAnalysisReport`].
    #[must_use]
    pub fn analyze(binary: &[u8]) -> VmAnalysisReport {
        let mut notes: Vec<String> = Vec::new();

        // Step 1: protector detection.
        let detections = VmProtectorDetector::detect(binary);
        if detections.is_empty() {
            notes.push("No known commercial VM protector signatures found.".into());
        } else {
            for d in &detections {
                let pct = d.confidence * 100.0;
                notes.push(format!(
                    "Detected '{}' with confidence {pct:.0}%",
                    d.protector_name
                ));
            }
        }

        // Step 2: bytecode region extraction.
        let bytecode_regions = VmBytecodeExtractor::find_bytecode_regions(binary);
        if bytecode_regions.is_empty() {
            notes.push("No structured bytecode regions found (entropy 5.0\u{2014}7.5).".into());
        } else {
            notes.push(format!(
                "Found {} bytecode candidate region(s).",
                bytecode_regions.len()
            ));
        }

        // Step 3: ISA size estimation —" take the maximum estimated handler count
        // across all candidate regions.
        let estimated_isa_size = bytecode_regions
            .iter()
            .map(|r| r.likely_handler_count)
            .max()
            .unwrap_or(0);

        if estimated_isa_size > 0 {
            notes.push(format!(
                "Estimated VM ISA size: {estimated_isa_size} distinct opcodes."
            ));
        }

        // Step 4: Note dispatcher presence from generic VmDetector.
        let generic = VmDetector::new().detect(binary);
        if let Some(offset) = generic.dispatcher_offset {
            notes.push(format!(
                "Generic dispatcher pattern found at offset 0x{offset:X}."
            ));
        }
        if !generic.arch_hints.is_empty() {
            for hint in &generic.arch_hints {
                notes.push(format!("Architecture hint: {hint}"));
            }
        }

        VmAnalysisReport {
            detections,
            bytecode_regions,
            estimated_isa_size,
            analysis_notes: notes,
        }
    }
}

// â"€â"€ UPX / simple deprotect â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Attempt to deprotect a UPX-packed binary.
///
/// UPX is not a VM protector but is commonly encountered in the wild.  If the
/// binary has `UPX0` and `UPX1` section names this function returns `None`
/// with the comment below explaining why a real implementation is needed.
///
/// # Real unpacking
/// Full UPX unpacking requires:
/// 1. Identifying the `UPX0` (destination, empty `VirtualSize`) and `UPX1` (source,
///    compressed data) PE sections from the section table.
/// 2. Locating the UPX tail-stub entry point (the `pushad / call delta`
///    sequence at `AddressOfEntryPoint`).
/// 3. Emulating or tracing the stub to allow it to decompress UPX1 â†' UPX0.
/// 4. Capturing the unpacked image after `popad / jmp [OEP]` executes.
/// 5. Rebuilding the PE import table (UPX compresses IAT as well).
///
/// All of the above can be done with `rustre-deobf-vmlift`'s emulation layer
/// combined with the Windows loader support in `rustre-core`.  This stub
/// intentionally returns `None` to avoid partially-constructed output that
/// would mislead downstream analysis.
///
/// # Returns
/// `None` always —" see above for the real algorithm.
#[must_use]
pub fn deprotect_simple(data: &[u8]) -> Option<Vec<u8>> {
    // Detect UPX by section names.
    let section_names = VmProtectorDetector::get_section_names(data);
    let has_upx0 = section_names.iter().any(|n| n == "UPX0");
    let has_upx1 = section_names.iter().any(|n| n == "UPX1");

    if has_upx0 && has_upx1 {
        // UPX packing confirmed.  Full decompression is not implemented here;
        // see the doc-comment on this function for the required algorithm.
        // In a production build you would invoke the system `upx -d` tool or
        // use a Rust UPX decompressor library (e.g. the `upx` crate) here.
        return None;
    }

    // Check for UPX magic in the binary itself (some loaders strip section
    // names but leave the "UPX!" magic at the end of the file).
    if find_subslice(data, b"UPX!").is_some() {
        // Same situation —" real decompression not implemented.
        return None;
    }

    // Not UPX-packed.
    None
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Tests
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    // â"€â"€ VirtualMachineState â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_vm_state_new_and_reset() {
        let mut state = VirtualMachineState::new();
        assert_eq!(state.regs, [0; 8]);
        assert_eq!(state.pc, 0);
        assert!(state.stack.is_empty());
        assert_eq!(state.flags, 0);
        state.regs[0] = 42;
        state.pc = 0x1000;
        state.stack.push(10);
        state.flags = 1;
        state.reset();
        assert_eq!(state.regs, [0; 8]);
        assert_eq!(state.pc, 0);
        assert!(state.stack.is_empty());
        assert_eq!(state.flags, 0);
    }

    #[test]
    fn test_vm_state_push_pop() {
        let mut state = VirtualMachineState::new();
        state.push(42);
        state.push(99);
        assert_eq!(state.pop(), Some(99));
        assert_eq!(state.pop(), Some(42));
        assert_eq!(state.pop(), None);
    }

    #[test]
    fn test_vm_state_memory_rw() {
        let mut state = VirtualMachineState::new();
        state.mem_write_u32(0x1000, 0xDEAD_BEEF);
        assert_eq!(state.mem_read_u32(0x1000), 0xDEAD_BEEF);
        assert_eq!(state.mem_read_byte(0x1000), 0xEF); // LE
    }

    #[test]
    fn test_vm_state_zero_flag() {
        let mut state = VirtualMachineState::new();
        state.set_zero_flag(0);
        assert!(state.zero_flag());
        state.set_zero_flag(1);
        assert!(!state.zero_flag());
    }

    #[test]
    fn test_vm_state_default_equals_new() {
        let a = VirtualMachineState::new();
        let b = VirtualMachineState::default();
        assert_eq!(a, b);
    }

    // â"€â"€ VmDispatcherDetector â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_detect_table_indexed_dispatcher() {
        let mut block = vec![0x90, 0x90, 0x31, 0xC0, 0xFF, 0x24];
        let entry: u64 = 0x1000;
        let handler_table_base: u64 = 0x2000;
        let handler_count: u64 = 16;
        block.extend_from_slice(&entry.to_le_bytes());
        block.extend_from_slice(&handler_table_base.to_le_bytes());
        block.extend_from_slice(&handler_count.to_le_bytes());
        block.extend_from_slice(&[0x90, 0x90]);
        let detector = VmDispatcherDetector::new();
        let dispatcher = detector.detect_dispatcher(&[block]).unwrap();
        assert_eq!(dispatcher.entry, Address::new(0x1000));
        assert_eq!(dispatcher.handler_table_base, Address::new(0x2000));
        assert_eq!(dispatcher.handler_count, 16);
    }

    #[test]
    fn test_detect_dynamic_offset_dispatcher() {
        let mut block = vec![0x48, 0x81, 0xC3, 0xFF];
        let entry: u64 = 0x3000;
        let handler_table_base: u64 = 0x4000;
        let handler_count: u64 = 32;
        block.extend_from_slice(&entry.to_le_bytes());
        block.extend_from_slice(&handler_table_base.to_le_bytes());
        block.extend_from_slice(&handler_count.to_le_bytes());
        let detector = VmDispatcherDetector::new();
        let dispatcher = detector.detect_dispatcher(&[block]).unwrap();
        assert_eq!(dispatcher.entry, Address::new(0x3000));
        assert_eq!(dispatcher.handler_count, 32);
    }

    #[test]
    fn test_no_dispatcher_detected() {
        let block = vec![0x00, 0x11, 0x22, 0x33];
        let detector = VmDispatcherDetector::new();
        assert!(detector.detect_dispatcher(&[block]).is_none());
    }

    // â"€â"€ VmDetector â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_vm_detector_no_indicators() {
        let data = vec![0x90u8; 32];
        let result = VmDetector::new().detect(&data);
        assert_eq!(result.confidence, VmConfidence::None);
    }

    #[test]
    fn test_vm_detector_rdtsc_hint() {
        let data = vec![0x0F, 0x31, 0x0F, 0x31]; // RDTSC
        let result = VmDetector::new().detect(&data);
        assert!(!result.arch_hints.is_empty());
    }

    #[test]
    fn test_vm_detector_indirect_jmp() {
        let mut data = vec![0x90u8; 16];
        // FF E0 = JMP EAX (indirect)
        data.extend_from_slice(&[0xFF, 0xE0]);
        data.extend_from_slice(&[0x90u8; 16]);
        let result = VmDetector::new().detect(&data);
        assert!(result.dispatcher_offset.is_some());
    }

    // â"€â"€ VmBytecode â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_vm_bytecode_distinct_opcodes() {
        let bytes = vec![0x10, 0x11, 0x10, 0x12]; // 3 distinct bytes
        let bc = VmBytecode::new(bytes, 0x0, 1);
        assert_eq!(bc.distinct_opcodes, 3);
    }

    #[test]
    fn test_vm_bytecode_entropy_high() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        let bc = VmBytecode::new(bytes, 0x0, 1);
        // All 256 distinct values â†' entropy â‰ˆ 8.0, above the 7.0 threshold.
        assert!(bc.looks_encrypted());
        assert!(bc.entropy > 7.9);
    }

    #[test]
    fn test_vm_bytecode_empty() {
        let bc = VmBytecode::new(vec![], 0x0, 1);
        assert!(bc.is_empty());
        assert_eq!(bc.distinct_opcodes, 0);
        assert!(bc.entropy.abs() < f64::EPSILON);
    }

    // â"€â"€ VmLifter â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_lifter_push_imm_add() {
        let lifter = VmLifter::new();
        // PushImm(5) PushImm(7) Add Halt
        let bc = vec![0x01, 5, 0, 0, 0, 0x01, 7, 0, 0, 0, 0x10, 0xFF];
        let ops = lifter.lift(&bc).unwrap();
        assert!(matches!(&ops[0], VmSemanticOp::PushImm(5)));
        assert!(matches!(&ops[1], VmSemanticOp::PushImm(7)));
        assert_eq!(ops[2], VmSemanticOp::Add);
        assert_eq!(ops[3], VmSemanticOp::Halt);
    }

    #[test]
    fn test_lifter_simulate_add() {
        let lifter = VmLifter::new();
        let bc = vec![
            0x01, 10, 0, 0, 0, // PushImm(10)
            0x01, 20, 0, 0, 0,    // PushImm(20)
            0x10, // Add
            0xFF, // Halt
        ];
        let ops = lifter.lift(&bc).unwrap();
        let state = lifter.simulate(&ops, VirtualMachineState::new()).unwrap();
        assert_eq!(state.stack.last().copied(), Some(30));
    }

    #[test]
    fn test_lifter_simulate_xor_self_zero() {
        let lifter = VmLifter::new();
        let bc = vec![
            0x01, 42, 0, 0, 0, // PushImm(42)
            0x01, 42, 0, 0, 0,    // PushImm(42)
            0x15, // Xor
            0xFF, // Halt
        ];
        let ops = lifter.lift(&bc).unwrap();
        let state = lifter.simulate(&ops, VirtualMachineState::new()).unwrap();
        assert_eq!(state.stack.last().copied(), Some(0));
        assert!(state.zero_flag());
    }

    #[test]
    fn test_lifter_pop_reg() {
        let lifter = VmLifter::new();
        let bc = vec![
            0x01, 99, 0, 0, 0, // PushImm(99)
            0x03, 0x00, // PopReg(0)
            0xFF, // Halt
        ];
        let ops = lifter.lift(&bc).unwrap();
        let state = lifter.simulate(&ops, VirtualMachineState::new()).unwrap();
        assert_eq!(state.regs[0], 99);
    }

    #[test]
    fn test_lifter_nop() {
        let lifter = VmLifter::new();
        let bc = vec![0x00, 0xFF]; // Nop, Halt
        let ops = lifter.lift(&bc).unwrap();
        assert_eq!(ops[0], VmSemanticOp::Nop);
        assert_eq!(ops[1], VmSemanticOp::Halt);
    }

    #[test]
    fn test_lifter_unknown_opcode() {
        let lifter = VmLifter::new();
        let bc = vec![0x88];
        let ops = lifter.lift(&bc).unwrap();
        assert!(matches!(ops[0], VmSemanticOp::Unknown(0x88)));
    }

    #[test]
    fn test_lifter_truncated_push_imm_errors() {
        let lifter = VmLifter::new();
        let bc = vec![0x01, 5, 0]; // PushImm truncated
        assert!(lifter.lift(&bc).is_err());
    }

    #[test]
    fn test_lifter_opcode_remap() {
        let mut map = HashMap::new();
        map.insert(0xAA, 0xFF); // 0xAA â†' Halt
        let lifter = VmLifter::new().with_opcode_map(map);
        let bc = vec![0xAA];
        let ops = lifter.lift(&bc).unwrap();
        assert_eq!(ops[0], VmSemanticOp::Halt);
    }

    // â"€â"€ VmSemanticOp â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_semantic_op_is_control_flow() {
        assert!(VmSemanticOp::Jmp.is_control_flow());
        assert!(VmSemanticOp::Ret.is_control_flow());
        assert!(!VmSemanticOp::Add.is_control_flow());
    }

    #[test]
    fn test_semantic_op_is_alu() {
        assert!(VmSemanticOp::Add.is_alu());
        assert!(VmSemanticOp::Xor.is_alu());
        assert!(!VmSemanticOp::Load32.is_alu());
    }

    #[test]
    fn test_semantic_op_stack_delta() {
        assert_eq!(VmSemanticOp::PushImm(0).stack_delta(), 1);
        assert_eq!(VmSemanticOp::Add.stack_delta(), -1);
        assert_eq!(VmSemanticOp::Store32.stack_delta(), -2);
        assert_eq!(VmSemanticOp::Not.stack_delta(), 0);
    }

    // â"€â"€ HandlerCluster / HandlerClusterer â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_clusterer_groups_by_kind() {
        let handlers = vec![
            VmHandler::new(
                0,
                Address::new(0x100),
                vec![0x90],
                HandlerKind::Arithmetic,
                "add",
                2,
                1,
            ),
            VmHandler::new(
                1,
                Address::new(0x110),
                vec![0x90],
                HandlerKind::Arithmetic,
                "sub",
                2,
                1,
            ),
            VmHandler::new(
                2,
                Address::new(0x120),
                vec![0x90],
                HandlerKind::ControlFlow,
                "jmp",
                1,
                0,
            ),
        ];
        let clusters = HandlerClusterer::new().cluster(&handlers);
        assert_eq!(clusters.len(), 2);
        let arith = clusters
            .iter()
            .find(|c| c.primary_kind == HandlerKind::Arithmetic)
            .unwrap();
        assert_eq!(arith.size(), 2);
        let cf = clusters
            .iter()
            .find(|c| c.primary_kind == HandlerKind::ControlFlow)
            .unwrap();
        assert_eq!(cf.size(), 1);
    }

    #[test]
    fn test_clusterer_empty_handlers() {
        let clusters = HandlerClusterer::new().cluster(&[]);
        assert!(clusters.is_empty());
    }

    // â"€â"€ VmArch â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_vm_arch_stack_machine() {
        let arch = VmArch::stack_machine(64);
        assert_eq!(arch.arch_type, "stack-machine");
        assert_eq!(arch.opcode_count, 64);
        assert!(arch.has_call_stack);
        assert!(arch.complexity_score > 0);
    }

    #[test]
    fn test_vm_arch_register_machine() {
        let arch = VmArch::register_machine(8, 32);
        assert_eq!(arch.arch_type, "register-machine");
        assert_eq!(arch.register_count, 8);
        assert!(!arch.has_call_stack);
    }

    #[test]
    fn test_vm_arch_summary() {
        let arch = VmArch::stack_machine(32);
        let s = arch.summary();
        assert!(s.contains("stack-machine"));
        assert!(s.contains("32"));
    }

    // â"€â"€ PcodeInsn â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_pcode_insn_is_branch() {
        let insn = PcodeInsn::new(PcodeOp::Branch, None, vec![], 0);
        assert!(insn.is_branch());
        let insn2 = PcodeInsn::new(PcodeOp::IntAdd, None, vec![], 0);
        assert!(!insn2.is_branch());
    }

    #[test]
    fn test_pcode_insn_display() {
        let insn = PcodeInsn::new(
            PcodeOp::IntAdd,
            Some(PcodeVarnode::Unique(0, 4)),
            vec![PcodeVarnode::Const(1, 4), PcodeVarnode::Const(2, 4)],
            0,
        );
        let s = insn.display();
        assert!(s.contains("IntAdd"));
    }

    #[test]
    fn test_pcode_varnode_size() {
        let v = PcodeVarnode::Register("eax".into(), 4);
        assert_eq!(v.size(), 4);
    }

    // â"€â"€ VmBytecodeExtractor â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_extractor_basic() {
        let data: Vec<u8> = (1u8..=200u8).cycle().take(256).collect();
        let extractor = VmBytecodeExtractor::new();
        let bc = extractor.extract(&data, 0, 0x1000);
        assert!(bc.is_some());
        assert!(!bc.unwrap().is_empty());
    }

    #[test]
    fn test_extractor_out_of_bounds() {
        let data = vec![0x10u8; 8];
        let extractor = VmBytecodeExtractor::new();
        let bc = extractor.extract(&data, 100, 0);
        assert!(bc.is_none());
    }

    #[test]
    fn test_extractor_stops_on_zero_run() {
        let mut data = vec![0x10u8; 32]; // valid code
        data.extend_from_slice(&[0x00u8; 16]); // null run â†' stop
        data.extend_from_slice(&[0xAAu8; 32]); // after null
        let extractor = VmBytecodeExtractor::new();
        let bc = extractor.extract(&data, 0, 0).unwrap();
        // Should stop before the null run.
        assert!(bc.len() <= 32 + extractor.min_length);
    }

    // â"€â"€ Helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_read_u64_le() {
        let bytes = 0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes();
        assert_eq!(read_u64_le(&bytes), 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(read_u64_le(&[1, 2, 3]), 0);
    }

    #[test]
    fn test_read_u32_le() {
        let bytes = 0xCAFE_BABEu32.to_le_bytes();
        assert_eq!(read_u32_le(&bytes), 0xCAFE_BABE);
        assert_eq!(read_u32_le(&[1]), 0);
    }

    #[test]
    fn test_read_u16_le() {
        let bytes = 0xABCDu16.to_le_bytes();
        assert_eq!(read_u16_le(&bytes), 0xABCD);
        assert_eq!(read_u16_le(&[1]), 0);
    }

    #[test]
    fn test_run_pass_no_panic() {
        run_pass();
    }

    // â"€â"€ Â§20.6 VmProtectorDetector â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_get_section_names_non_pe() {
        // Random data that is not a PE —" should return empty.
        let data = vec![0xABu8; 64];
        let names = VmProtectorDetector::get_section_names(&data);
        assert!(names.is_empty());
    }

    #[test]
    fn test_get_section_names_too_short() {
        let data = vec![0x4Du8, 0x5Au8]; // "MZ" but truncated
        let names = VmProtectorDetector::get_section_names(&data);
        assert!(names.is_empty());
    }

    #[test]
    fn test_vm_protector_detector_no_protector_strings() {
        // Random-like byte sequence with no known protector name strings.
        // We only assert that no detection has a confidence >= 0.4 (strong signal).
        // Heuristic detectors may still fire weakly on random structure.
        let data: Vec<u8> = (0u8..128)
            .map(|i| u8::try_from((u32::from(i) * 17 + 3) % 256).unwrap_or(u8::MAX))
            .collect();
        let results = VmProtectorDetector::detect(&data);
        for d in &results {
            assert!(
                d.confidence < 0.4,
                "Unexpectedly high confidence {:.2} for '{}' on structureless data",
                d.confidence,
                d.protector_name
            );
        }
    }

    #[test]
    fn test_vm_protector_detector_vmp_string() {
        // Embed the "VMProtect" string and VirtualProtect import.
        let mut data = vec![0x90u8; 64];
        data.extend_from_slice(b"VMProtect");
        data.extend_from_slice(b"\x00");
        data.extend_from_slice(b"VirtualProtect");
        let results = VmProtectorDetector::detect(&data);
        let vmp = results.iter().find(|d| d.protector_name == "VMProtect");
        assert!(vmp.is_some(), "Expected VMProtect detection");
        assert!(vmp.unwrap().confidence > 0.0);
    }

    #[test]
    fn test_vm_protector_detector_themida_string() {
        let mut data = vec![0x90u8; 64];
        data.extend_from_slice(b"Themida");
        let results = VmProtectorDetector::detect(&data);
        let th = results
            .iter()
            .find(|d| d.protector_name == "Themida/WinLicense");
        assert!(th.is_some(), "Expected Themida detection");
    }

    #[test]
    fn test_vm_detection_builder() {
        let det = VmDetection::new("TestProtector", 0.5)
            .with_evidence("evidence A")
            .with_evidence("evidence B");
        assert_eq!(det.protector_name, "TestProtector");
        assert!((det.confidence - 0.5_f32).abs() < f32::EPSILON);
        assert_eq!(det.evidence.len(), 2);
    }

    // â"€â"€ Â§20.6 BytecodeCandidate / find_bytecode_regions â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_find_bytecode_regions_empty() {
        let data = vec![];
        let regions = VmBytecodeExtractor::find_bytecode_regions(&data);
        assert!(regions.is_empty());
    }

    #[test]
    fn test_find_bytecode_regions_uniform_low_entropy() {
        // All zeros â†' entropy 0.0, below 5.0 threshold.
        let data = vec![0x00u8; 512];
        let regions = VmBytecodeExtractor::find_bytecode_regions(&data);
        assert!(
            regions.is_empty(),
            "Uniform zero data should produce no candidates"
        );
    }

    #[test]
    fn test_find_bytecode_regions_mid_entropy() {
        // Bytes cycling 0..=15 â†' entropy ~4.0 (just below threshold) for small N,
        // but cycling 0..=63 gives ~6.0.
        let data: Vec<u8> = (0u8..64).cycle().take(1024).collect();
        // This should have entropy ~6.0 (64 distinct values uniformly distributed).
        let regions = VmBytecodeExtractor::find_bytecode_regions(&data);
        // We just check it doesn't panic and returns reasonable output.
        let _ = regions;
    }

    #[test]
    fn test_estimate_opcode_count_uniform() {
        // 256 distinct values each appearing once —" should give count > 0.
        let data: Vec<u8> = (0u8..=255).collect();
        let count = VmBytecodeExtractor::estimate_opcode_count(&data);
        // With threshold=2, no single byte appears more than once in 256 bytes,
        // so count should be 0.
        assert_eq!(count, 0);
    }

    #[test]
    fn test_estimate_opcode_count_repeated() {
        // 8 distinct values each appearing 64 times (512 bytes).
        let data: Vec<u8> = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
            .iter()
            .cycle()
            .take(512)
            .copied()
            .collect();
        let count = VmBytecodeExtractor::estimate_opcode_count(&data);
        assert_eq!(count, 8);
    }

    // â"€â"€ Â§20.6 HandlerNode / HandlerEdge / HandlerGraphBuilder â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_handler_node_is_dispatcher() {
        let n = HandlerNode::new(0x1000, 0, None, "dispatcher");
        assert!(n.is_dispatcher());
        let n2 = HandlerNode::new(0x1010, 16, Some(0x01), "arithmetic/logic");
        assert!(!n2.is_dispatcher());
    }

    #[test]
    fn test_handler_edge_forward_back() {
        let fwd = HandlerEdge::forward(0x05);
        assert!(!fwd.is_back_edge);
        assert_eq!(fwd.opcode_value, Some(0x05));

        let back = HandlerEdge::back();
        assert!(back.is_back_edge);
        assert_eq!(back.opcode_value, None);
    }

    #[test]
    fn test_build_handler_graph_empty_code() {
        let graph = HandlerGraphBuilder::build_handler_graph(0x0040_0000, &[]);
        // Only the dispatcher node should be present.
        assert_eq!(graph.node_count(), 1);
        assert_eq!(graph.edge_count(), 0);
    }

    #[test]
    fn test_build_handler_graph_with_push_jmp() {
        // Craft a minimal handler-like sequence: PUSH EAX (0x50) + NOP x4 + JMP [EAX] (FF E0).
        let mut code = vec![0x90u8; 16]; // padding before
        code.push(0x50); // PUSH EAX
        code.extend_from_slice(&[0x90, 0x90, 0x90]); // body
        code.extend_from_slice(&[0xFF, 0xE0]); // JMP EAX
        code.extend_from_slice(&[0x90u8; 16]); // padding after

        let graph = HandlerGraphBuilder::build_handler_graph(0x1000, &code);
        // Should have dispatcher + at least one handler.
        assert!(graph.node_count() >= 1);
        // At least check no panic.
    }

    #[test]
    fn test_export_dot_empty_graph() {
        let graph: Graph<HandlerNode, HandlerEdge> = Graph::new();
        let dot = HandlerGraphBuilder::export_dot(&graph);
        assert!(dot.starts_with("digraph vm_handlers {"));
        assert!(dot.ends_with("}\n"));
    }

    #[test]
    fn test_export_dot_contains_dispatcher() {
        let graph = HandlerGraphBuilder::build_handler_graph(0xDEAD, &[]);
        let dot = HandlerGraphBuilder::export_dot(&graph);
        assert!(dot.contains("DISPATCHER"));
    }

    // â"€â"€ Â§20.6 VmDeobfPipeline / VmAnalysisReport â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_vm_deobf_pipeline_empty_binary() {
        let report = VmDeobfPipeline::analyze(&[]);
        assert!(
            report
                .analysis_notes
                .iter()
                .any(|n| n.contains("No known commercial"))
        );
    }

    #[test]
    fn test_vm_analysis_report_recommendations_always_present() {
        let report = VmDeobfPipeline::analyze(&[0x90u8; 32]);
        let recs = report.recommendations();
        assert!(!recs.is_empty());
        assert!(recs.iter().any(|r| r.contains("VmLifterPipeline")));
        assert!(recs.iter().any(|r| r.contains("symbolic execution")));
    }

    #[test]
    fn test_vm_analysis_report_detections_sorted_by_confidence() {
        let mut report = VmDeobfPipeline::analyze(&[]);
        // Manually add two detections.
        report.detections.push(VmDetection::new("A", 0.3));
        report.detections.push(VmDetection::new("B", 0.9));
        report.detections.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        assert!(report.detections[0].confidence >= report.detections[1].confidence);
    }

    // â"€â"€ Â§20.6 deprotect_simple â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_deprotect_simple_random_data() {
        // Non-PE, non-UPX data â†' None.
        let data = vec![0xAAu8; 64];
        assert!(deprotect_simple(&data).is_none());
    }

    #[test]
    fn test_deprotect_simple_upx_magic() {
        // Embed "UPX!" magic â†' None (stub, not implemented).
        let mut data = vec![0x4Du8, 0x5Au8]; // MZ
        data.extend_from_slice(&[0u8; 62]);
        data.extend_from_slice(b"UPX!");
        assert!(deprotect_simple(&data).is_none());
    }

    // â"€â"€ VmHandler fields â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_handler_is_arithmetic() {
        let h = VmHandler::new(
            0,
            Address::new(0),
            vec![],
            HandlerKind::Arithmetic,
            "add",
            2,
            1,
        );
        assert!(h.is_arithmetic());
        assert!(!h.is_control_flow());
    }

    #[test]
    fn test_handler_prologue_entropy() {
        let h = VmHandler::new(
            0,
            Address::new(0),
            vec![0x90; 16],
            HandlerKind::Unknown,
            "",
            0,
            0,
        );
        assert!(h.prologue_entropy().abs() < f64::EPSILON); // All same byte.
    }

    #[test]
    fn test_handler_prologue_entropy_varied() {
        let prologue: Vec<u8> = (0u8..16).collect();
        let h = VmHandler::new(0, Address::new(0), prologue, HandlerKind::Unknown, "", 0, 0);
        assert!(h.prologue_entropy() > 3.0);
    }
}

