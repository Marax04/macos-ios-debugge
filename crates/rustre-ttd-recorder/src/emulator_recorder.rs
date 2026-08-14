//! Emulator-based execution trace recorder.
//!
//! Records the execution trace from a software emulator (modelled on Unicorn).
//! Each emulated step produces a `RecordedStep` that captures register deltas,
//! memory deltas, and a log entry.  The recorder manages a `StepLog` and
//! provides replay and diff utilities.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─── Register names ───────────────────────────────────────────────────────────

/// A register name (e.g. `"rax"`, `"rip"`).
pub type RegName = String;

// ─── RegisterDelta ────────────────────────────────────────────────────────────

/// The change in a register value during one emulated step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterDelta {
    /// Register name.
    pub name: RegName,
    /// Value before the step.
    pub before: u64,
    /// Value after the step.
    pub after: u64,
}

impl RegisterDelta {
    #[must_use]
    pub fn new(name: impl Into<String>, before: u64, after: u64) -> Self {
        Self {
            name: name.into(),
            before,
            after,
        }
    }

    /// Return `true` if the register actually changed.
    #[must_use]
    pub const fn changed(&self) -> bool {
        self.before != self.after
    }
}

// ─── MemoryDelta ─────────────────────────────────────────────────────────────

/// The change in a memory region during one emulated step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryDelta {
    /// Start address of the modified region.
    pub address: u64,
    /// Byte values before the step.
    pub before: Vec<u8>,
    /// Byte values after the step.
    pub after: Vec<u8>,
    /// Whether this was a read (false) or write (true).
    pub is_write: bool,
}

impl MemoryDelta {
    #[must_use]
    pub const fn write(address: u64, before: Vec<u8>, after: Vec<u8>) -> Self {
        Self {
            address,
            before,
            after,
            is_write: true,
        }
    }

    #[must_use]
    pub fn read(address: u64, value: Vec<u8>) -> Self {
        Self {
            address,
            before: value.clone(),
            after: value,
            is_write: false,
        }
    }

    /// Number of bytes affected.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.after.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.after.is_empty()
    }
}

// ─── RecordedStep ─────────────────────────────────────────────────────────────

/// One fully-recorded emulator step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedStep {
    /// Step sequence number (0-based).
    pub seq: u64,
    /// Program counter before the step.
    pub pc: u64,
    /// Raw bytes of the executed instruction.
    pub insn_bytes: Vec<u8>,
    /// Human-readable disassembly (optional, may be empty).
    pub disasm: String,
    /// Register deltas: only registers that changed are included.
    pub register_deltas: Vec<RegisterDelta>,
    /// Memory deltas: only locations that changed are included.
    pub memory_deltas: Vec<MemoryDelta>,
    /// Monotonic emulator timestamp (instruction count).
    pub timestamp: u64,
}

impl RecordedStep {
    #[must_use]
    pub const fn new(seq: u64, pc: u64, insn_bytes: Vec<u8>, timestamp: u64) -> Self {
        Self {
            seq,
            pc,
            insn_bytes,
            disasm: String::new(),
            register_deltas: Vec::new(),
            memory_deltas: Vec::new(),
            timestamp,
        }
    }

    /// Return the delta for a named register, if any.
    #[must_use]
    pub fn reg_delta(&self, name: &str) -> Option<&RegisterDelta> {
        self.register_deltas.iter().find(|d| d.name == name)
    }

    /// Whether any register changed.
    #[must_use]
    pub fn any_reg_changed(&self) -> bool {
        self.register_deltas.iter().any(RegisterDelta::changed)
    }

    /// Whether any memory was written.
    #[must_use]
    pub fn any_mem_write(&self) -> bool {
        self.memory_deltas.iter().any(|d| d.is_write)
    }
}

// ─── StepLog ──────────────────────────────────────────────────────────────────

/// An ordered log of all recorded steps.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct StepLog {
    steps: Vec<RecordedStep>,
}

impl StepLog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a step.
    pub fn push(&mut self, step: RecordedStep) {
        self.steps.push(step);
    }

    /// Total number of steps.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.steps.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Return step by index.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&RecordedStep> {
        self.steps.get(index)
    }

    /// Return all steps that executed at `pc`.
    #[must_use]
    pub fn steps_at_pc(&self, pc: u64) -> Vec<&RecordedStep> {
        self.steps.iter().filter(|s| s.pc == pc).collect()
    }

    /// Return all steps that wrote to any memory address.
    #[must_use]
    pub fn steps_with_mem_write(&self) -> Vec<&RecordedStep> {
        self.steps.iter().filter(|s| s.any_mem_write()).collect()
    }

    /// Return all PCs visited (deduped, in order of first visit).
    #[must_use]
    pub fn visited_pcs(&self) -> Vec<u64> {
        // O(n) via a HashSet for membership; the previous Vec::contains made
        // this O(n²) which dominates on long traces.
        let mut seen_set: std::collections::HashSet<u64> =
            std::collections::HashSet::with_capacity(self.steps.len());
        let mut seen = Vec::with_capacity(self.steps.len());
        for s in &self.steps {
            if seen_set.insert(s.pc) {
                seen.push(s.pc);
            }
        }
        seen
    }

    /// PC coverage: number of distinct PCs visited.
    #[must_use]
    pub fn pc_coverage(&self) -> usize {
        self.visited_pcs().len()
    }

    /// All steps in order.
    #[must_use]
    pub fn all(&self) -> &[RecordedStep] {
        &self.steps
    }

    /// Slice of steps in the range `[from_seq, to_seq)`.
    #[must_use]
    pub fn slice(&self, from_seq: u64, to_seq: u64) -> Vec<&RecordedStep> {
        self.steps
            .iter()
            .filter(|s| s.seq >= from_seq && s.seq < to_seq)
            .collect()
    }
}

// ─── EmulatorState ────────────────────────────────────────────────────────────

/// A snapshot of the emulator register state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmulatorState {
    pub regs: HashMap<RegName, u64>,
    pub memory: HashMap<u64, u8>,
}

impl EmulatorState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_reg(&mut self, name: impl Into<String>, value: u64) {
        self.regs.insert(name.into(), value);
    }

    #[must_use]
    pub fn get_reg(&self, name: &str) -> u64 {
        self.regs.get(name).copied().unwrap_or(0)
    }

    pub fn write_byte(&mut self, addr: u64, byte: u8) {
        self.memory.insert(addr, byte);
    }

    #[must_use]
    pub fn read_byte(&self, addr: u64) -> u8 {
        self.memory.get(&addr).copied().unwrap_or(0)
    }

    /// Compute register deltas relative to `other`.
    #[must_use]
    pub fn reg_deltas_from(&self, other: &Self) -> Vec<RegisterDelta> {
        let mut deltas = Vec::with_capacity(self.regs.len());
        for (name, &after) in &self.regs {
            let before = other.regs.get(name).copied().unwrap_or(0);
            if before != after {
                deltas.push(RegisterDelta::new(name.clone(), before, after));
            }
        }
        deltas
    }
}

// ─── EmulatorRecorder ─────────────────────────────────────────────────────────

/// Records execution trace from an emulator, producing a [`StepLog`].
#[derive(Debug)]
pub struct EmulatorRecorder {
    log: StepLog,
    current_state: EmulatorState,
    next_seq: u64,
    /// Whether recording is active.
    pub active: bool,
    /// Maximum steps to record (0 = unlimited).
    pub max_steps: u64,
}

impl Default for EmulatorRecorder {
    fn default() -> Self {
        Self::new()
    }
}

impl EmulatorRecorder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            log: StepLog::new(),
            current_state: EmulatorState::new(),
            next_seq: 0,
            active: false,
            max_steps: 0,
        }
    }

    /// Start recording.
    pub const fn start(&mut self) {
        self.active = true;
    }

    /// Stop recording.
    pub const fn stop(&mut self) {
        self.active = false;
    }

    /// Pre-populate the emulator register state.
    pub fn set_reg(&mut self, name: impl Into<String>, value: u64) {
        self.current_state.set_reg(name, value);
    }

    /// Write a byte into the emulator memory snapshot.
    pub fn write_byte(&mut self, addr: u64, byte: u8) {
        self.current_state.write_byte(addr, byte);
    }

    /// Record a single emulator step.
    ///
    /// `pc` is the address being executed, `insn_bytes` the raw instruction.
    /// `new_regs` contains the full register file *after* execution.
    /// `mem_writes` is a list of `(addr, old_bytes, new_bytes)`.
    pub fn record_step(
        &mut self,
        pc: u64,
        insn_bytes: Vec<u8>,
        disasm: impl Into<String>,
        new_regs: HashMap<String, u64>,
        mem_writes: Vec<(u64, Vec<u8>, Vec<u8>)>,
    ) -> u64 {
        if !self.active {
            return self.next_seq;
        }
        if self.max_steps > 0 && self.next_seq >= self.max_steps {
            self.active = false;
            return self.next_seq;
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        let ts = seq;

        // Build new state and compute deltas
        let mut new_state = self.current_state.clone();
        for (name, val) in new_regs {
            new_state.set_reg(name, val);
        }
        let reg_deltas = new_state.reg_deltas_from(&self.current_state);

        let memory_deltas: Vec<MemoryDelta> = mem_writes
            .into_iter()
            .map(|(addr, before, after)| MemoryDelta::write(addr, before, after))
            .collect();

        // Apply memory writes to state
        for d in &memory_deltas {
            for (i, &b) in d.after.iter().enumerate() {
                new_state.write_byte(d.address + u64::try_from(i).unwrap_or(u64::MAX), b);
            }
        }

        let mut step = RecordedStep::new(seq, pc, insn_bytes, ts);
        step.disasm = disasm.into();
        step.register_deltas = reg_deltas;
        step.memory_deltas = memory_deltas;

        self.current_state = new_state;
        self.log.push(step);
        seq
    }

    /// Access the step log.
    #[must_use]
    pub const fn log(&self) -> &StepLog {
        &self.log
    }

    /// Total steps recorded.
    #[must_use]
    pub fn step_count(&self) -> u64 {
        u64::try_from(self.log.len()).unwrap_or(u64::MAX)
    }

    /// Take ownership of the log (consumes recorder).
    #[must_use]
    pub fn into_log(self) -> StepLog {
        self.log
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // --- RegisterDelta ---

    #[test]
    fn reg_delta_changed_when_different() {
        let d = RegisterDelta::new("rax", 0, 1);
        assert!(d.changed());
    }

    #[test]
    fn reg_delta_not_changed_when_same() {
        let d = RegisterDelta::new("rax", 5, 5);
        assert!(!d.changed());
    }

    // --- MemoryDelta ---

    #[test]
    fn memory_delta_write_flag() {
        let d = MemoryDelta::write(0x1000, vec![0], vec![1]);
        assert!(d.is_write);
    }

    #[test]
    fn memory_delta_read_flag() {
        let d = MemoryDelta::read(0x1000, vec![0xAA]);
        assert!(!d.is_write);
    }

    #[test]
    fn memory_delta_len() {
        let d = MemoryDelta::write(0, vec![0, 0], vec![1, 2]);
        assert_eq!(d.len(), 2);
    }

    // --- RecordedStep ---

    #[test]
    fn step_reg_delta_found() {
        let mut s = RecordedStep::new(0, 0x1000, vec![0x90], 0);
        s.register_deltas.push(RegisterDelta::new("rax", 0, 42));
        assert!(s.reg_delta("rax").is_some());
        assert_eq!(s.reg_delta("rax").unwrap().after, 42);
    }

    #[test]
    fn step_reg_delta_not_found() {
        let s = RecordedStep::new(0, 0, vec![], 0);
        assert!(s.reg_delta("rbx").is_none());
    }

    #[test]
    fn step_any_reg_changed() {
        let mut s = RecordedStep::new(0, 0, vec![], 0);
        s.register_deltas
            .push(RegisterDelta::new("rip", 0x1000, 0x1001));
        assert!(s.any_reg_changed());
    }

    #[test]
    fn step_no_mem_write() {
        let s = RecordedStep::new(0, 0, vec![], 0);
        assert!(!s.any_mem_write());
    }

    // --- StepLog ---

    #[test]
    fn step_log_push_and_len() {
        let mut log = StepLog::new();
        log.push(RecordedStep::new(0, 0x1000, vec![0x90], 0));
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn step_log_steps_at_pc() {
        let mut log = StepLog::new();
        log.push(RecordedStep::new(0, 0x1000, vec![], 0));
        log.push(RecordedStep::new(1, 0x1002, vec![], 1));
        log.push(RecordedStep::new(2, 0x1000, vec![], 2));
        assert_eq!(log.steps_at_pc(0x1000).len(), 2);
    }

    #[test]
    fn step_log_visited_pcs_deduped() {
        let mut log = StepLog::new();
        log.push(RecordedStep::new(0, 0xA, vec![], 0));
        log.push(RecordedStep::new(1, 0xB, vec![], 1));
        log.push(RecordedStep::new(2, 0xA, vec![], 2));
        assert_eq!(log.visited_pcs().len(), 2);
    }

    #[test]
    fn step_log_pc_coverage() {
        let mut log = StepLog::new();
        log.push(RecordedStep::new(0, 1, vec![], 0));
        log.push(RecordedStep::new(1, 2, vec![], 1));
        log.push(RecordedStep::new(2, 1, vec![], 2));
        assert_eq!(log.pc_coverage(), 2);
    }

    #[test]
    fn step_log_slice() {
        let mut log = StepLog::new();
        for i in 0..5u64 {
            log.push(RecordedStep::new(i, 0, vec![], i));
        }
        let s = log.slice(1, 4);
        assert_eq!(s.len(), 3);
        assert_eq!(s[0].seq, 1);
    }

    // --- EmulatorState ---

    #[test]
    fn emulator_state_reg_default_zero() {
        let s = EmulatorState::new();
        assert_eq!(s.get_reg("rax"), 0);
    }

    #[test]
    fn emulator_state_reg_write_read() {
        let mut s = EmulatorState::new();
        s.set_reg("rbx", 0xDEAD);
        assert_eq!(s.get_reg("rbx"), 0xDEAD);
    }

    #[test]
    fn emulator_state_memory_write_read() {
        let mut s = EmulatorState::new();
        s.write_byte(0x1000, 0xAB);
        assert_eq!(s.read_byte(0x1000), 0xAB);
    }

    #[test]
    fn emulator_state_reg_deltas() {
        let mut before = EmulatorState::new();
        before.set_reg("rax", 0);
        let mut after = EmulatorState::new();
        after.set_reg("rax", 42);
        let deltas = after.reg_deltas_from(&before);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].after, 42);
    }

    // --- EmulatorRecorder ---

    #[test]
    fn recorder_start_stop() {
        let mut r = EmulatorRecorder::new();
        assert!(!r.active);
        r.start();
        assert!(r.active);
        r.stop();
        assert!(!r.active);
    }

    #[test]
    fn recorder_record_step_while_active() {
        let mut r = EmulatorRecorder::new();
        r.start();
        let mut regs = HashMap::new();
        regs.insert("rip".into(), 0x1001u64);
        r.record_step(0x1000, vec![0x90], "nop", regs, vec![]);
        assert_eq!(r.step_count(), 1);
    }

    #[test]
    fn recorder_no_step_when_inactive() {
        let mut r = EmulatorRecorder::new();
        r.record_step(0, vec![], "", HashMap::new(), vec![]);
        assert_eq!(r.step_count(), 0);
    }

    #[test]
    fn recorder_max_steps_enforced() {
        let mut r = EmulatorRecorder::new();
        r.max_steps = 2;
        r.start();
        for i in 0..5 {
            let mut regs = HashMap::new();
            regs.insert("rip".into(), i + 1);
            r.record_step(i, vec![], "", regs, vec![]);
        }
        assert_eq!(r.step_count(), 2);
        assert!(!r.active);
    }

    #[test]
    fn recorder_mem_write_applied() {
        let mut r = EmulatorRecorder::new();
        r.start();
        let mem = vec![(0x2000u64, vec![0u8], vec![0xBEu8])];
        r.record_step(0x1000, vec![], "mov", HashMap::new(), mem);
        assert_eq!(r.current_state.read_byte(0x2000), 0xBE);
    }

    #[test]
    fn recorder_into_log() {
        let mut r = EmulatorRecorder::new();
        r.start();
        r.record_step(0, vec![], "", HashMap::new(), vec![]);
        let log = r.into_log();
        assert_eq!(log.len(), 1);
    }
}
