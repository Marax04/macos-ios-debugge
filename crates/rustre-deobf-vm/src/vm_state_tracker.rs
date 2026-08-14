//! VM State Tracking During Execution
//!
//! Tracks the evolution of the virtual machine's state as execution advances
//! step-by-step through decoded virtual instructions:
//! - [`VmStateSnapshot`] — a frozen copy of the VM state at one VIP step
//! - [`RegisterFile`] — the virtual register file (up to 16 registers)
//! - [`MemoryDelta`] — a single memory write recorded during a step
//! - [`VmStateTracker`] — accumulates snapshots and computes deltas
//! - [`LoopIterationCounter`] — detects and counts loop iterations

#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap, VecDeque};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from state tracking.
#[derive(Debug, Error)]
pub enum StateTrackerError {
    #[error("register index {index} out of range (max {max})")]
    RegisterOutOfRange { index: u8, max: u8 },

    #[error("snapshot at VIP {vip:#x} already exists")]
    DuplicateSnapshot { vip: u64 },

    #[error("no snapshots have been recorded yet")]
    NoSnapshots,

    #[error("maximum snapshot count {max} exceeded")]
    SnapshotLimitExceeded { max: usize },

    #[error("loop iteration limit {limit} exceeded for block {header:#x}")]
    LoopIterationLimitExceeded { limit: u32, header: u64 },
}

// ─────────────────────────────────────────────────────────────────────────────
// RegisterFile
// ─────────────────────────────────────────────────────────────────────────────

/// Number of virtual registers supported.
pub const MAX_VIRTUAL_REGS: usize = 16;

/// The virtual register file at a single execution step.
///
/// Supports up to 16 virtual registers; unused slots hold 0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterFile {
    /// Register values (index 0 = vr0, …).
    pub regs: [u64; MAX_VIRTUAL_REGS],
    /// Bit mask: bit N is set if register N has been written at least once.
    pub dirty_mask: u16,
    /// Number of logical registers this VM actually uses.
    pub reg_count: u8,
}

impl RegisterFile {
    /// Create a zero-initialised register file for `reg_count` registers.
    #[must_use]
    pub fn new(reg_count: u8) -> Self {
        let reg_count = reg_count.min(u8::try_from(MAX_VIRTUAL_REGS).unwrap_or(u8::MAX));
        Self {
            regs: [0; MAX_VIRTUAL_REGS],
            dirty_mask: 0,
            reg_count,
        }
    }

    /// Read register `idx`.
    ///
    /// # Errors
    /// Returns [`StateTrackerError::RegisterOutOfRange`] if `idx` is out of bounds.
    pub fn read(&self, idx: u8) -> Result<u64, StateTrackerError> {
        if idx as usize >= MAX_VIRTUAL_REGS {
            return Err(StateTrackerError::RegisterOutOfRange {
                index: idx,
                max: u8::try_from(MAX_VIRTUAL_REGS).unwrap_or(u8::MAX) - 1,
            });
        }
        Ok(self.regs[idx as usize])
    }

    /// Write register `idx` with `value`.
    ///
    /// # Errors
    /// Returns [`StateTrackerError::RegisterOutOfRange`] if `idx` is out of bounds.
    pub fn write(&mut self, idx: u8, value: u64) -> Result<(), StateTrackerError> {
        if idx as usize >= MAX_VIRTUAL_REGS {
            return Err(StateTrackerError::RegisterOutOfRange {
                index: idx,
                max: u8::try_from(MAX_VIRTUAL_REGS).unwrap_or(u8::MAX) - 1,
            });
        }
        self.regs[idx as usize] = value;
        self.dirty_mask |= 1 << idx;
        Ok(())
    }

    /// Returns `true` if register `idx` has been written.
    #[must_use]
    pub const fn is_dirty(&self, idx: u8) -> bool {
        (self.dirty_mask >> idx) & 1 == 1
    }

    /// Clear the dirty mask (reuse the register file for the next block).
    pub const fn clear_dirty(&mut self) {
        self.dirty_mask = 0;
    }

    /// Compute the set of indices that differ between `self` and `other`.
    #[must_use]
    pub fn diff(&self, other: &Self) -> Vec<u8> {
        (0..u8::try_from(MAX_VIRTUAL_REGS).unwrap_or(u8::MAX))
            .filter(|&i| self.regs[i as usize] != other.regs[i as usize])
            .collect()
    }

    /// Return a map of (`register_name` → `value`) for all dirty registers.
    ///
    /// Register names use the format `vr{idx}`.
    #[must_use]
    pub fn dirty_registers(&self) -> BTreeMap<String, u64> {
        let mut map = BTreeMap::new();
        for i in 0..u8::try_from(MAX_VIRTUAL_REGS).unwrap_or(u8::MAX) {
            if self.is_dirty(i) {
                map.insert(format!("vr{i}"), self.regs[i as usize]);
            }
        }
        map
    }
}

impl Default for RegisterFile {
    fn default() -> Self {
        Self::new(8)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StackState
// ─────────────────────────────────────────────────────────────────────────────

/// State of the virtual stack at a single execution step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackState {
    /// Stack contents (index 0 = bottom).
    pub values: Vec<u64>,
    /// Current stack depth.
    pub depth: usize,
    /// Maximum depth reached since tracking started.
    pub max_depth: usize,
}

impl StackState {
    /// Create a new empty stack state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            values: Vec::new(),
            depth: 0,
            max_depth: 0,
        }
    }

    /// Push a value onto the stack.
    pub fn push(&mut self, value: u64) {
        self.values.push(value);
        self.depth = self.values.len();
        if self.depth > self.max_depth {
            self.max_depth = self.depth;
        }
    }

    /// Pop a value from the stack. Returns `None` if empty.
    pub fn pop(&mut self) -> Option<u64> {
        let v = self.values.pop();
        self.depth = self.values.len();
        v
    }

    /// Peek at the top-of-stack without removing it.
    #[must_use]
    pub fn peek(&self) -> Option<u64> {
        self.values.last().copied()
    }

    /// Peek at the Nth element from the top (0 = TOS, 1 = NOS, …).
    #[must_use]
    pub fn peek_n(&self, n: usize) -> Option<u64> {
        let len = self.values.len();
        if n >= len {
            return None;
        }
        Some(self.values[len - 1 - n])
    }

    /// Return `true` if the stack is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

impl Default for StackState {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryDelta
// ─────────────────────────────────────────────────────────────────────────────

/// A single memory write recorded during one VM execution step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryDelta {
    /// Virtual address that was written.
    pub address: u64,
    /// Old value (byte) before the write.
    pub old_value: u8,
    /// New value (byte) after the write.
    pub new_value: u8,
    /// VIP of the instruction that caused this write.
    pub caused_by_vip: u64,
}

impl MemoryDelta {
    /// Create a new memory delta record.
    #[must_use]
    pub const fn new(address: u64, old_value: u8, new_value: u8, vip: u64) -> Self {
        Self {
            address,
            old_value,
            new_value,
            caused_by_vip: vip,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmStateSnapshot
// ─────────────────────────────────────────────────────────────────────────────

/// A frozen snapshot of the VM state at a single VIP step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmStateSnapshot {
    /// Virtual instruction pointer at the time of the snapshot.
    pub vip: u64,
    /// Step index (0-based execution count).
    pub step: u64,
    /// Register file at this step.
    pub registers: RegisterFile,
    /// Stack state at this step.
    pub stack: StackState,
    /// Virtual flags register.
    pub flags: u32,
    /// Memory deltas that occurred to produce this state.
    pub memory_deltas: Vec<MemoryDelta>,
    /// Opcode byte that was executed to produce this state.
    pub opcode: u8,
    /// Loop iteration count if inside a loop header (0 if not tracked).
    pub loop_iteration: u32,
}

impl VmStateSnapshot {
    /// Create a new snapshot.
    #[must_use]
    pub const fn new(
        vip: u64,
        step: u64,
        registers: RegisterFile,
        stack: StackState,
        flags: u32,
        opcode: u8,
    ) -> Self {
        Self {
            vip,
            step,
            registers,
            stack,
            flags,
            memory_deltas: Vec::new(),
            opcode,
            loop_iteration: 0,
        }
    }

    /// Add a memory delta.
    pub fn add_delta(&mut self, delta: MemoryDelta) {
        self.memory_deltas.push(delta);
    }

    /// Zero flag.
    #[must_use]
    pub const fn zero_flag(&self) -> bool {
        self.flags & 1 != 0
    }
    /// Carry flag.
    #[must_use]
    pub const fn carry_flag(&self) -> bool {
        self.flags & 2 != 0
    }
    /// Sign flag.
    #[must_use]
    pub const fn sign_flag(&self) -> bool {
        self.flags & 4 != 0
    }
    /// Overflow flag.
    #[must_use]
    pub const fn overflow_flag(&self) -> bool {
        self.flags & 8 != 0
    }

    /// Returns `true` if any memory was written during this step.
    #[must_use]
    pub const fn has_memory_write(&self) -> bool {
        !self.memory_deltas.is_empty()
    }

    /// Returns the stack depth at this step.
    #[must_use]
    pub const fn stack_depth(&self) -> usize {
        self.stack.depth
    }

    /// Format a one-line summary.
    #[must_use]
    pub fn one_line(&self) -> String {
        format!(
            "step={:6} vip={:#010x} opcode={:#04x} stack_depth={:3} flags={:08b}{}",
            self.step,
            self.vip,
            self.opcode,
            self.stack_depth(),
            self.flags,
            if self.has_memory_write() {
                " [MEM_WRITE]"
            } else {
                ""
            },
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopIterationCounter
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks loop iteration counts for detected loop headers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoopIterationCounter {
    /// Map: loop header VIP → iteration count.
    pub counts: HashMap<u64, u32>,
    /// Maximum iterations to allow per loop before raising an error.
    pub max_iterations: u32,
    /// Total loop iterations counted across all loops.
    pub total_iterations: u64,
}

impl LoopIterationCounter {
    /// Create a new counter with a given per-loop limit.
    #[must_use]
    pub fn new(max_iterations: u32) -> Self {
        Self {
            counts: HashMap::new(),
            max_iterations,
            total_iterations: 0,
        }
    }

    /// Record one iteration of the loop with header at `header_vip`.
    ///
    /// # Errors
    /// Returns [`StateTrackerError::LoopIterationLimitExceeded`] if the limit is exceeded.
    pub fn record(&mut self, header_vip: u64) -> Result<u32, StateTrackerError> {
        let count = self.counts.entry(header_vip).or_insert(0);
        *count += 1;
        self.total_iterations += 1;
        if *count > self.max_iterations {
            return Err(StateTrackerError::LoopIterationLimitExceeded {
                limit: self.max_iterations,
                header: header_vip,
            });
        }
        Ok(*count)
    }

    /// Return the iteration count for a given loop header.
    #[must_use]
    pub fn get(&self, header_vip: u64) -> u32 {
        self.counts.get(&header_vip).copied().unwrap_or(0)
    }

    /// Reset all counts.
    pub fn reset(&mut self) {
        self.counts.clear();
        self.total_iterations = 0;
    }

    /// Return all loop headers with their iteration counts, sorted by count descending.
    #[must_use]
    pub fn all_sorted(&self) -> Vec<(u64, u32)> {
        let mut v: Vec<(u64, u32)> = self.counts.iter().map(|(&h, &c)| (h, c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmStateTracker
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the state tracker.
#[derive(Debug, Clone)]
pub struct StateTrackerConfig {
    /// Maximum number of snapshots to retain (ring buffer behaviour beyond this).
    pub max_snapshots: usize,
    /// Maximum loop iterations per header before an error is raised.
    pub max_loop_iterations: u32,
    /// Whether to record memory deltas (may be expensive).
    pub track_memory: bool,
    /// Whether to keep a full ring buffer (true) or only the latest snapshot (false).
    pub ring_buffer: bool,
}

impl Default for StateTrackerConfig {
    fn default() -> Self {
        Self {
            max_snapshots: 100_000,
            max_loop_iterations: 10_000,
            track_memory: true,
            ring_buffer: false,
        }
    }
}

/// Tracks the VM state across all executed steps, recording snapshots and deltas.
#[derive(Debug, Clone)]
pub struct VmStateTracker {
    /// Configuration.
    pub config: StateTrackerConfig,
    /// Recorded snapshots (bounded by `max_snapshots`).
    snapshots: VecDeque<VmStateSnapshot>,
    /// Current register file.
    registers: RegisterFile,
    /// Current stack.
    stack: StackState,
    /// Current flags.
    flags: u32,
    /// Current memory (addr → byte).
    memory: HashMap<u64, u8>,
    /// Step counter.
    step: u64,
    /// Loop iteration counter.
    loop_counter: LoopIterationCounter,
    /// Known loop header VIPs (provided by the CFG loop analysis).
    loop_headers: HashMap<u64, u32>,
    /// Statistics.
    pub stats: TrackerStats,
}

/// Serde helper for `[u32; 256]` arrays (serde does not auto-derive
/// Serialize/Deserialize for arrays larger than 32).
pub mod serde_u32_256 {
    use serde::{Deserialize, Deserializer, Serializer, ser::SerializeTuple};

    /// # Errors
    /// Returns an error if serialization fails.
    pub fn serialize<S: Serializer>(arr: &[u32; 256], ser: S) -> Result<S::Ok, S::Error> {
        let mut tup = ser.serialize_tuple(256)?;
        for v in arr {
            tup.serialize_element(v)?;
        }
        tup.end()
    }

    /// # Errors
    /// Returns an error if deserialization fails.
    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u32; 256], D::Error> {
        let v: Vec<u32> = Vec::deserialize(de)?;
        if v.len() != 256 {
            return Err(serde::de::Error::custom(format!(
                "expected 256 u32 elements, got {}",
                v.len()
            )));
        }
        let mut out = [0u32; 256];
        for (i, x) in v.into_iter().enumerate() {
            out[i] = x;
        }
        Ok(out)
    }
}

/// Statistics collected by the tracker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackerStats {
    /// Total steps executed.
    pub total_steps: u64,
    /// Total snapshots captured.
    pub total_snapshots: u64,
    /// Total memory bytes written.
    pub total_memory_bytes_written: u64,
    /// Total stack pushes.
    pub total_stack_pushes: u64,
    /// Total stack pops.
    pub total_stack_pops: u64,
    /// Maximum stack depth observed.
    pub max_stack_depth: usize,
    /// Number of backward jumps (VIP decreased).
    pub backward_jumps: u64,
    /// Opcode frequency histogram.
    #[serde(with = "serde_u32_256")]
    pub opcode_histogram: [u32; 256],
}

impl Default for TrackerStats {
    fn default() -> Self {
        Self {
            total_steps: 0,
            total_snapshots: 0,
            total_memory_bytes_written: 0,
            total_stack_pushes: 0,
            total_stack_pops: 0,
            max_stack_depth: 0,
            backward_jumps: 0,
            opcode_histogram: [0u32; 256],
        }
    }
}

impl VmStateTracker {
    /// Create a new tracker.
    #[must_use]
    pub fn new(reg_count: u8) -> Self {
        let config = StateTrackerConfig::default();
        let max_iter = config.max_loop_iterations;
        Self {
            config,
            snapshots: VecDeque::new(),
            registers: RegisterFile::new(reg_count),
            stack: StackState::new(),
            flags: 0,
            memory: HashMap::new(),
            step: 0,
            loop_counter: LoopIterationCounter::new(max_iter),
            loop_headers: HashMap::new(),
            stats: TrackerStats::default(),
        }
    }

    /// Create with custom configuration.
    #[must_use]
    pub fn with_config(reg_count: u8, config: StateTrackerConfig) -> Self {
        let max_iter = config.max_loop_iterations;
        Self {
            config,
            snapshots: VecDeque::new(),
            registers: RegisterFile::new(reg_count),
            stack: StackState::new(),
            flags: 0,
            memory: HashMap::new(),
            step: 0,
            loop_counter: LoopIterationCounter::new(max_iter),
            loop_headers: HashMap::new(),
            stats: TrackerStats::default(),
        }
    }

    /// Register known loop headers (VIP → expected iteration count hint).
    pub fn register_loop_headers(&mut self, headers: HashMap<u64, u32>) {
        self.loop_headers = headers;
    }

    /// Write a virtual register.
    ///
    /// # Errors
    /// Returns [`StateTrackerError::RegisterOutOfRange`] if `idx` is out of bounds.
    pub fn write_reg(&mut self, idx: u8, value: u64) -> Result<(), StateTrackerError> {
        self.registers.write(idx, value)
    }

    /// Read a virtual register.
    ///
    /// # Errors
    /// Returns [`StateTrackerError::RegisterOutOfRange`] if `idx` is out of bounds.
    pub fn read_reg(&self, idx: u8) -> Result<u64, StateTrackerError> {
        self.registers.read(idx)
    }

    /// Push a value onto the virtual stack.
    pub fn push(&mut self, value: u64) {
        self.stack.push(value);
        self.stats.total_stack_pushes += 1;
        if self.stack.depth > self.stats.max_stack_depth {
            self.stats.max_stack_depth = self.stack.depth;
        }
    }

    /// Pop a value from the virtual stack.
    pub fn pop(&mut self) -> Option<u64> {
        let v = self.stack.pop();
        if v.is_some() {
            self.stats.total_stack_pops += 1;
        }
        v
    }

    /// Set the virtual flags register.
    pub const fn set_flags(&mut self, flags: u32) {
        self.flags = flags;
    }

    /// Set the zero flag based on a result value.
    pub const fn update_zero_flag(&mut self, result: u64) {
        if result == 0 {
            self.flags |= 1;
        } else {
            self.flags &= !1;
        }
    }

    /// Write a byte to virtual memory.
    pub fn write_mem_byte(&mut self, addr: u64, byte: u8) -> MemoryDelta {
        let old = self.memory.get(&addr).copied().unwrap_or(0);
        self.memory.insert(addr, byte);
        self.stats.total_memory_bytes_written += 1;
        MemoryDelta::new(addr, old, byte, self.step)
    }

    /// Read a byte from virtual memory (0 if unmapped).
    #[must_use]
    pub fn read_mem_byte(&self, addr: u64) -> u8 {
        self.memory.get(&addr).copied().unwrap_or(0)
    }

    /// Read a 32-bit value from virtual memory (LE).
    #[must_use]
    pub fn read_mem_u32(&self, addr: u64) -> u32 {
        let b0 = u32::from(self.read_mem_byte(addr));
        let b1 = u32::from(self.read_mem_byte(addr + 1));
        let b2 = u32::from(self.read_mem_byte(addr + 2));
        let b3 = u32::from(self.read_mem_byte(addr + 3));
        b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    }

    /// Write a 32-bit value to virtual memory (LE). Returns 4 memory deltas.
    pub fn write_mem_u32(&mut self, addr: u64, value: u32) -> [MemoryDelta; 4] {
        let bytes = value.to_le_bytes();
        [
            self.write_mem_byte(addr, bytes[0]),
            self.write_mem_byte(addr + 1, bytes[1]),
            self.write_mem_byte(addr + 2, bytes[2]),
            self.write_mem_byte(addr + 3, bytes[3]),
        ]
    }

    /// Capture a snapshot of the current state at `vip` for opcode `opcode`.
    ///
    /// If `vip` is a known loop header, increments the iteration counter.
    ///
    /// # Errors
    /// Returns [`StateTrackerError::SnapshotLimitExceeded`] if the snapshot limit is reached
    /// and ring-buffer mode is disabled, or [`StateTrackerError::LoopIterationLimitExceeded`]
    /// if a loop header exceeds its iteration limit.
    pub fn snapshot(
        &mut self,
        vip: u64,
        opcode: u8,
        memory_deltas: Vec<MemoryDelta>,
    ) -> Result<(), StateTrackerError> {
        if self.snapshots.len() >= self.config.max_snapshots {
            if self.config.ring_buffer {
                self.snapshots.pop_front();
            } else {
                return Err(StateTrackerError::SnapshotLimitExceeded {
                    max: self.config.max_snapshots,
                });
            }
        }

        let mut snap = VmStateSnapshot::new(
            vip,
            self.step,
            self.registers.clone(),
            self.stack.clone(),
            self.flags,
            opcode,
        );
        for delta in memory_deltas {
            snap.add_delta(delta);
        }

        // Loop header check.
        if self.loop_headers.contains_key(&vip) {
            let count = self.loop_counter.record(vip)?;
            snap.loop_iteration = count;
        }

        // Opcode histogram.
        self.stats.opcode_histogram[opcode as usize] += 1;
        self.stats.total_steps += 1;
        self.stats.total_snapshots += 1;
        self.step += 1;

        self.snapshots.push_back(snap);
        Ok(())
    }

    /// Return the most recent snapshot.
    #[must_use]
    pub fn latest(&self) -> Option<&VmStateSnapshot> {
        self.snapshots.back()
    }

    /// Return all snapshots in recorded order.
    pub fn all_snapshots(&self) -> impl Iterator<Item = &VmStateSnapshot> {
        self.snapshots.iter()
    }

    /// Compute the delta between two consecutive snapshots.
    ///
    /// Returns changed register indices and memory deltas.
    #[must_use]
    pub fn compute_delta(&self, step_a: u64, step_b: u64) -> Option<StateDelta> {
        let snap_a = self.snapshots.iter().find(|s| s.step == step_a)?;
        let snap_b = self.snapshots.iter().find(|s| s.step == step_b)?;
        Some(StateDelta {
            from_step: step_a,
            to_step: step_b,
            changed_regs: snap_a.registers.diff(&snap_b.registers),
            stack_delta: i32::try_from(snap_b.stack.depth).unwrap_or(i32::MAX) - i32::try_from(snap_a.stack.depth).unwrap_or(i32::MAX),
            flags_changed: snap_a.flags != snap_b.flags,
            memory_deltas: snap_b.memory_deltas.clone(),
        })
    }

    /// Compute register liveness: which registers are read before written
    /// across all snapshots.
    #[must_use]
    pub fn compute_liveness(&self) -> RegisterLiveness {
        let mut liveness = RegisterLiveness::default();
        for snap in &self.snapshots {
            for i in 0..u8::try_from(MAX_VIRTUAL_REGS).unwrap_or(u8::MAX) {
                if snap.registers.is_dirty(i) {
                    liveness.ever_written |= 1u16 << i;
                }
            }
        }
        liveness
    }

    /// Count how many steps involved a backward VIP jump.
    #[must_use]
    pub fn count_backward_jumps(&self) -> u64 {
        let mut count = 0u64;
        let mut iter = self.snapshots.iter();
        if let Some(mut prev) = iter.next() {
            for curr in iter {
                if curr.vip < prev.vip {
                    count += 1;
                }
                prev = curr;
            }
        }
        count
    }

    /// Return the most frequently executed opcode.
    #[must_use]
    pub fn most_frequent_opcode(&self) -> Option<u8> {
        let (idx, &count) = self
            .stats
            .opcode_histogram
            .iter()
            .enumerate()
            .max_by_key(|&(_, &c)| c)?;
        if count == 0 { None } else { Some(u8::try_from(idx).unwrap_or(u8::MAX)) }
    }

    /// Return a human-readable statistics summary.
    #[must_use]
    pub fn stats_summary(&self) -> String {
        format!(
            "VmStateTracker: {} steps, {} snapshots, max_stack={}, mem_writes={}",
            self.stats.total_steps,
            self.stats.total_snapshots,
            self.stats.max_stack_depth,
            self.stats.total_memory_bytes_written,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StateDelta / RegisterLiveness
// ─────────────────────────────────────────────────────────────────────────────

/// Delta between two VM state snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDelta {
    /// Step index of the earlier snapshot.
    pub from_step: u64,
    /// Step index of the later snapshot.
    pub to_step: u64,
    /// Register indices that changed.
    pub changed_regs: Vec<u8>,
    /// Stack depth change.
    pub stack_delta: i32,
    /// Whether the flags register changed.
    pub flags_changed: bool,
    /// Memory deltas in the later snapshot.
    pub memory_deltas: Vec<MemoryDelta>,
}

impl StateDelta {
    /// Returns `true` if nothing changed between the two snapshots.
    #[must_use]
    pub const fn is_identity(&self) -> bool {
        self.changed_regs.is_empty()
            && self.stack_delta == 0
            && !self.flags_changed
            && self.memory_deltas.is_empty()
    }
}

/// Register liveness information computed across a trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisterLiveness {
    /// Bitmask: bit N is set if register N was ever written.
    pub ever_written: u16,
}

impl RegisterLiveness {
    /// Returns `true` if register `idx` was ever written.
    #[must_use]
    pub const fn was_written(&self, idx: u8) -> bool {
        (self.ever_written >> idx) & 1 == 1
    }

    /// Returns all register indices that were ever written.
    #[must_use]
    pub fn written_registers(&self) -> Vec<u8> {
        (0..16u8).filter(|&i| self.was_written(i)).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tracker() -> VmStateTracker {
        VmStateTracker::new(8)
    }

    #[test]
    fn test_register_file_read_write() {
        let mut rf = RegisterFile::new(8);
        rf.write(0, 0xDEAD).unwrap();
        assert_eq!(rf.read(0).unwrap(), 0xDEAD);
        assert!(rf.is_dirty(0));
        assert!(!rf.is_dirty(1));
    }

    #[test]
    fn test_register_file_out_of_range() {
        let mut rf = RegisterFile::new(8);
        assert!(rf.write(255, 42).is_err());
        assert!(rf.read(200).is_err());
    }

    #[test]
    fn test_register_file_diff() {
        let mut rf1 = RegisterFile::new(8);
        let mut rf2 = RegisterFile::new(8);
        rf1.write(0, 10).unwrap();
        rf2.write(0, 20).unwrap();
        let diff = rf1.diff(&rf2);
        assert_eq!(diff, vec![0]);
    }

    #[test]
    fn test_register_file_dirty_registers() {
        let mut rf = RegisterFile::new(8);
        rf.write(3, 0xBEEF).unwrap();
        rf.write(5, 0xCAFE).unwrap();
        let dirty = rf.dirty_registers();
        assert_eq!(dirty.len(), 2);
        assert!(dirty.contains_key("vr3"));
        assert!(dirty.contains_key("vr5"));
    }

    #[test]
    fn test_stack_state_push_pop_peek() {
        let mut s = StackState::new();
        s.push(10);
        s.push(20);
        s.push(30);
        assert_eq!(s.depth, 3);
        assert_eq!(s.peek(), Some(30));
        assert_eq!(s.peek_n(1), Some(20));
        assert_eq!(s.pop(), Some(30));
        assert_eq!(s.depth, 2);
    }

    #[test]
    fn test_stack_state_empty_pop() {
        let mut s = StackState::new();
        assert_eq!(s.pop(), None);
    }

    #[test]
    fn test_memory_delta_new() {
        let d = MemoryDelta::new(0x1000, 0x00, 0xFF, 0x500);
        assert_eq!(d.address, 0x1000);
        assert_eq!(d.old_value, 0x00);
        assert_eq!(d.new_value, 0xFF);
    }

    #[test]
    fn test_vm_state_snapshot_flags() {
        let snap = VmStateSnapshot::new(
            0x100,
            0,
            RegisterFile::new(8),
            StackState::new(),
            0b0101,
            0x10,
        );
        assert!(snap.zero_flag());
        assert!(!snap.carry_flag());
        assert!(snap.sign_flag());
        assert!(!snap.overflow_flag());
    }

    #[test]
    fn test_vm_state_snapshot_one_line() {
        let snap = VmStateSnapshot::new(0x200, 5, RegisterFile::new(4), StackState::new(), 0, 0xAA);
        let line = snap.one_line();
        assert!(line.contains("0x200") || line.contains("200"));
        assert!(line.contains("0xaa") || line.contains("aa"));
    }

    #[test]
    fn test_vm_state_tracker_write_read_reg() {
        let mut tracker = make_tracker();
        tracker.write_reg(3, 0xABCD).unwrap();
        assert_eq!(tracker.read_reg(3).unwrap(), 0xABCD);
    }

    #[test]
    fn test_vm_state_tracker_push_pop() {
        let mut tracker = make_tracker();
        tracker.push(42);
        tracker.push(99);
        assert_eq!(tracker.pop(), Some(99));
        assert_eq!(tracker.stats.total_stack_pushes, 2);
        assert_eq!(tracker.stats.total_stack_pops, 1);
    }

    #[test]
    fn test_vm_state_tracker_memory_rw() {
        let mut tracker = make_tracker();
        let delta = tracker.write_mem_byte(0x1000, 0xAB);
        assert_eq!(delta.old_value, 0x00);
        assert_eq!(delta.new_value, 0xAB);
        assert_eq!(tracker.read_mem_byte(0x1000), 0xAB);
    }

    #[test]
    fn test_vm_state_tracker_write_read_u32() {
        let mut tracker = make_tracker();
        tracker.write_mem_u32(0x2000, 0xDEAD_BEEF);
        assert_eq!(tracker.read_mem_u32(0x2000), 0xDEAD_BEEF);
    }

    #[test]
    fn test_vm_state_tracker_snapshot_and_latest() {
        let mut tracker = make_tracker();
        tracker.snapshot(0x100, 0x10, vec![]).unwrap();
        tracker.snapshot(0x101, 0x11, vec![]).unwrap();
        let latest = tracker.latest().unwrap();
        assert_eq!(latest.vip, 0x101);
        assert_eq!(tracker.stats.total_snapshots, 2);
    }

    #[test]
    fn test_vm_state_tracker_snapshot_limit() {
        let config = StateTrackerConfig {
            max_snapshots: 3,
            ..Default::default()
        };
        let mut tracker = VmStateTracker::with_config(8, config);
        for i in 0u64..3 {
            tracker.snapshot(i, 0, vec![]).unwrap();
        }
        let result = tracker.snapshot(3, 0, vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_vm_state_tracker_ring_buffer() {
        let config = StateTrackerConfig {
            max_snapshots: 3,
            ring_buffer: true,
            ..Default::default()
        };
        let mut tracker = VmStateTracker::with_config(8, config);
        for i in 0u64..5 {
            tracker.snapshot(i, 0, vec![]).unwrap();
        }
        // Ring buffer: only last 3 snapshots kept.
        
        assert_eq!(tracker.all_snapshots().count(), 3);
    }

    #[test]
    fn test_vm_state_tracker_compute_delta() {
        let mut tracker = make_tracker();
        tracker.snapshot(0x100, 0x00, vec![]).unwrap();
        tracker.write_reg(0, 42).unwrap();
        tracker.snapshot(0x101, 0x01, vec![]).unwrap();
        // Note: snapshot captures registers at time of call, so step 0 sees default reg.
        let delta = tracker.compute_delta(0, 1);
        assert!(delta.is_some());
    }

    #[test]
    fn test_loop_iteration_counter_record_and_limit() {
        let mut counter = LoopIterationCounter::new(3);
        counter.record(0x1000).unwrap();
        counter.record(0x1000).unwrap();
        counter.record(0x1000).unwrap();
        assert_eq!(counter.get(0x1000), 3);
        assert!(counter.record(0x1000).is_err());
    }

    #[test]
    fn test_loop_iteration_counter_reset() {
        let mut counter = LoopIterationCounter::new(100);
        counter.record(0x100).unwrap();
        counter.record(0x200).unwrap();
        counter.reset();
        assert_eq!(counter.get(0x100), 0);
        assert_eq!(counter.total_iterations, 0);
    }

    #[test]
    fn test_loop_iteration_counter_all_sorted() {
        let mut counter = LoopIterationCounter::new(100);
        for _ in 0..5 {
            counter.record(0x100).unwrap();
        }
        for _ in 0..3 {
            counter.record(0x200).unwrap();
        }
        let sorted = counter.all_sorted();
        assert_eq!(sorted[0].0, 0x100);
        assert_eq!(sorted[0].1, 5);
    }

    #[test]
    fn test_state_delta_is_identity() {
        let d = StateDelta {
            from_step: 0,
            to_step: 1,
            changed_regs: vec![],
            stack_delta: 0,
            flags_changed: false,
            memory_deltas: vec![],
        };
        assert!(d.is_identity());
    }

    #[test]
    fn test_register_liveness_was_written() {
        let liveness = RegisterLiveness {
            ever_written: 0b0000_0000_0001_0010,
        };
        assert!(liveness.was_written(1));
        assert!(liveness.was_written(4));
        assert!(!liveness.was_written(0));
        let written = liveness.written_registers();
        assert!(written.contains(&1));
        assert!(written.contains(&4));
    }

    #[test]
    fn test_tracker_most_frequent_opcode() {
        let mut tracker = make_tracker();
        for _ in 0..5 {
            tracker.snapshot(0x100, 0x10, vec![]).unwrap();
        }
        for _ in 0..3 {
            tracker.snapshot(0x101, 0x20, vec![]).unwrap();
        }
        assert_eq!(tracker.most_frequent_opcode(), Some(0x10));
    }

    #[test]
    fn test_tracker_stats_summary() {
        let mut tracker = make_tracker();
        tracker.push(1);
        tracker.snapshot(0x100, 0x00, vec![]).unwrap();
        let summary = tracker.stats_summary();
        assert!(summary.contains("VmStateTracker"));
        assert!(summary.contains("1 steps"));
    }
}
