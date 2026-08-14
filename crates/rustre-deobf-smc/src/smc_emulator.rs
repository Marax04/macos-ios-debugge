/// SMC emulator: step through write events to emulate self-modifying code and capture
/// the final executable payload state at each interesting point.
///
/// This is a lightweight, architecture-neutral simulation layer. It does not execute
/// native instructions — instead it replays the sequence of memory writes recorded
/// during dynamic analysis and provides a snapshot of memory at any step.
use std::collections::{BTreeMap, HashMap, VecDeque};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EmulatorError {
    #[error("step index {0} is out of range (total steps: {1})")]
    StepOutOfRange(usize, usize),
    #[error("no steps recorded")]
    NoSteps,
    #[error("address {0:#x} was never written")]
    UnwrittenAddress(u64),
    #[error("capture at step {0} conflicts with existing capture")]
    DuplicateCapture(usize),
    #[error("maximum step count {0} exceeded")]
    StepLimitExceeded(usize),
}

// ---------------------------------------------------------------------------
// EmulationWrite — a single memory write in the trace
// ---------------------------------------------------------------------------

/// One memory-write event in the emulation trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulationWrite {
    /// Address being written.
    pub target_addr: u64,
    /// Byte value written.
    pub value: u8,
    /// Program counter of the writing instruction.
    pub write_pc: u64,
    /// Logical step index (insertion order within this emulator).
    pub step: usize,
}

// ---------------------------------------------------------------------------
// EmulationStep — snapshot of register-like state at one point in the trace
// ---------------------------------------------------------------------------

/// A lightweight register state recorded alongside a write step.
/// Fields match common x86/x86-64 conventions; unused fields are zero.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmulationStep {
    pub step: usize,
    pub pc: u64,
    pub sp: u64,
    pub flags: u64,
    /// General-purpose registers: [rax, rbx, rcx, rdx, rsi, rdi, r8..r15].
    pub gprs: [u64; 16],
    /// Annotation attached at this step (e.g. decryption round label).
    pub annotation: Option<String>,
}

impl EmulationStep {
    #[must_use] 
    pub fn new(step: usize, pc: u64) -> Self {
        Self { step, pc, ..Default::default() }
    }

    #[must_use]
    pub fn with_annotation(mut self, s: impl Into<String>) -> Self {
        self.annotation = Some(s.into());
        self
    }
}

// ---------------------------------------------------------------------------
// PayloadCapture — snapshot of memory at a specific step
// ---------------------------------------------------------------------------

/// A named capture of the memory state at a given step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadCapture {
    /// Step index at which this capture was taken.
    pub step: usize,
    /// Human-readable label (e.g. "`after_decrypt_round_3`").
    pub label: String,
    /// Memory snapshot: address → value.
    pub memory: BTreeMap<u64, u8>,
    /// The step's register state, if available.
    pub regs: Option<EmulationStep>,
}

impl PayloadCapture {
    /// Read a byte from this capture. Returns `None` if never written.
    #[must_use] 
    pub fn read(&self, addr: u64) -> Option<u8> {
        self.memory.get(&addr).copied()
    }

    /// Extract a contiguous byte slice starting at `base`, length `len`.
    /// Unwritten bytes are filled with `fill`.
    #[must_use] 
    pub fn extract(&self, base: u64, len: usize, fill: u8) -> Vec<u8> {
        (0..len)
            .map(|i| self.memory.get(&base.wrapping_add(i as u64)).copied().unwrap_or(fill))
            .collect()
    }

    /// Number of bytes in this capture.
    #[must_use] 
    pub fn len(&self) -> usize {
        self.memory.len()
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.memory.is_empty()
    }
}

// ---------------------------------------------------------------------------
// EmulatorConfig
// ---------------------------------------------------------------------------

/// Configuration for `SmcEmulator`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulatorConfig {
    /// Maximum number of steps to accept before returning `StepLimitExceeded`.
    pub max_steps: usize,
    /// If `true`, overwriting an address that was never written is not an error.
    pub allow_unwritten_overwrite: bool,
    /// Contiguous region gap threshold for final-state region detection.
    pub gap_threshold: u64,
}

impl Default for EmulatorConfig {
    fn default() -> Self {
        Self {
            max_steps: 10_000_000,
            allow_unwritten_overwrite: true,
            gap_threshold: 64,
        }
    }
}

// ---------------------------------------------------------------------------
// EmulatorStats
// ---------------------------------------------------------------------------

/// Runtime statistics accumulated during emulation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmulatorStats {
    pub total_writes: u64,
    pub unique_addresses: u64,
    pub overwrites: u64,
    pub captures_taken: u64,
    pub distinct_write_pcs: u64,
}

// ---------------------------------------------------------------------------
// FinalRegion — a contiguous block in the final memory state
// ---------------------------------------------------------------------------

/// A contiguous block of bytes in the final emulated memory state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalRegion {
    pub base: u64,
    pub bytes: Vec<u8>,
}

impl FinalRegion {
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    #[must_use] 
    pub const fn end(&self) -> u64 {
        self.base.saturating_add(self.bytes.len() as u64)
    }
}

// ---------------------------------------------------------------------------
// SmcEmulator — main engine
// ---------------------------------------------------------------------------

/// Steps through a recorded sequence of memory writes, maintaining live memory state
/// and allowing captures at arbitrary points.
pub struct SmcEmulator {
    config: EmulatorConfig,
    /// Ordered write trace.
    writes: Vec<EmulationWrite>,
    /// Optional register snapshots keyed by step index.
    reg_snapshots: HashMap<usize, EmulationStep>,
    /// Named capture requests: step → label.
    capture_requests: HashMap<usize, String>,
    /// Captures taken, sorted by step.
    captures: Vec<PayloadCapture>,
    stats: EmulatorStats,
    write_pcs: HashMap<u64, u64>,
    /// Live memory state after all applied writes.
    memory: BTreeMap<u64, u8>,
    /// Addresses that have been written to at least once (for overwrite detection).
    seen_addrs: std::collections::HashSet<u64>,
    /// Pending write queue for streaming step-by-step replay.
    replay_cursor: usize,
}

impl SmcEmulator {
    #[must_use] 
    pub fn new(config: EmulatorConfig) -> Self {
        Self {
            config,
            writes: Vec::new(),
            reg_snapshots: HashMap::new(),
            capture_requests: HashMap::new(),
            captures: Vec::new(),
            stats: EmulatorStats::default(),
            write_pcs: HashMap::new(),
            memory: BTreeMap::new(),
            seen_addrs: std::collections::HashSet::new(),
            replay_cursor: 0,
        }
    }

    // ------------------------------------------------------------------
    // Input: feeding writes and register snapshots
    // ------------------------------------------------------------------

    /// Record a write at the given step. Steps must be added in ascending step order.
    ///
    /// # Errors
    /// Returns [`EmulatorError::StepLimitExceeded`] if the step limit is reached.
    pub fn push_write(
        &mut self,
        target_addr: u64,
        value: u8,
        write_pc: u64,
    ) -> Result<(), EmulatorError> {
        let step = self.writes.len();
        if step >= self.config.max_steps {
            return Err(EmulatorError::StepLimitExceeded(self.config.max_steps));
        }
        if self.seen_addrs.insert(target_addr) {
            self.stats.unique_addresses += 1;
        } else {
            self.stats.overwrites += 1;
        }
        *self.write_pcs.entry(write_pc).or_insert(0) += 1;
        self.writes.push(EmulationWrite { target_addr, value, write_pc, step });
        self.stats.total_writes += 1;
        Ok(())
    }

    /// Bulk-push writes from an iterator of `(target_addr, value, write_pc)`.
    ///
    /// # Errors
    /// Returns an error if any individual write fails (see [`Self::push_write`]).
    pub fn push_writes<I>(&mut self, iter: I) -> Result<(), EmulatorError>
    where
        I: IntoIterator<Item = (u64, u8, u64)>,
    {
        for (a, v, pc) in iter {
            self.push_write(a, v, pc)?;
        }
        Ok(())
    }

    /// Associate a register snapshot with a particular step index.
    pub fn attach_regs(&mut self, regs: EmulationStep) {
        self.reg_snapshots.insert(regs.step, regs);
    }

    /// Request a named memory capture to be taken after step `step`.
    ///
    /// # Errors
    /// Returns [`EmulatorError::DuplicateCapture`] if a capture for `step` was already requested.
    pub fn request_capture(
        &mut self,
        step: usize,
        label: impl Into<String>,
    ) -> Result<(), EmulatorError> {
        if self.capture_requests.contains_key(&step) {
            return Err(EmulatorError::DuplicateCapture(step));
        }
        self.capture_requests.insert(step, label.into());
        Ok(())
    }

    // ------------------------------------------------------------------
    // Replay
    // ------------------------------------------------------------------

    /// Apply all writes in order, taking captures at requested steps.
    /// Returns a reference to the captures taken.
    ///
    /// # Errors
    /// Returns [`EmulatorError::NoSteps`] if no writes have been pushed.
    pub fn run_full(&mut self) -> Result<&[PayloadCapture], EmulatorError> {
        if self.writes.is_empty() {
            return Err(EmulatorError::NoSteps);
        }

        self.memory.clear();
        self.captures.clear();
        self.replay_cursor = 0;

        for write in &self.writes {
            self.memory.insert(write.target_addr, write.value);
            if let Some(label) = self.capture_requests.get(&write.step) {
                let regs = self.reg_snapshots.get(&write.step).cloned();
                let capture = PayloadCapture {
                    step: write.step,
                    label: label.clone(),
                    memory: self.memory.clone(),
                    regs,
                };
                self.captures.push(capture);
                self.stats.captures_taken += 1;
            }
        }

        self.replay_cursor = self.writes.len();
        Ok(&self.captures)
    }

    /// Step the emulator forward by exactly one write. Returns the write applied,
    /// or `None` if all writes have been replayed.
    pub fn step_once(&mut self) -> Option<&EmulationWrite> {
        if self.replay_cursor >= self.writes.len() {
            return None;
        }
        let write = &self.writes[self.replay_cursor];
        self.memory.insert(write.target_addr, write.value);

        if let Some(label) = self.capture_requests.get(&write.step) {
            let regs = self.reg_snapshots.get(&write.step).cloned();
            self.captures.push(PayloadCapture {
                step: write.step,
                label: label.clone(),
                memory: self.memory.clone(),
                regs,
            });
            self.stats.captures_taken += 1;
        }

        self.replay_cursor += 1;
        Some(&self.writes[self.replay_cursor - 1])
    }

    /// Step forward until the write PC matches `target_pc`. Returns the number of
    /// steps advanced, or `None` if `target_pc` was not found.
    pub fn step_until_pc(&mut self, target_pc: u64) -> Option<usize> {
        let start = self.replay_cursor;
        loop {
            match self.step_once() {
                None => return None,
                Some(w) if w.write_pc == target_pc => {
                    return Some(self.replay_cursor - start);
                }
                _ => {}
            }
        }
    }

    /// Reset the replay cursor to the beginning without clearing the write log.
    pub fn reset_replay(&mut self) {
        self.memory.clear();
        self.captures.clear();
        self.replay_cursor = 0;
    }

    // ------------------------------------------------------------------
    // Memory access
    // ------------------------------------------------------------------

    /// Read the current (live) memory state at `addr`.
    #[must_use] 
    pub fn read_byte(&self, addr: u64) -> Option<u8> {
        self.memory.get(&addr).copied()
    }

    /// Extract a contiguous slice from the live memory state.
    #[must_use] 
    pub fn read_range(&self, base: u64, len: usize, fill: u8) -> Vec<u8> {
        (0..len)
            .map(|i| self.memory.get(&base.wrapping_add(i as u64)).copied().unwrap_or(fill))
            .collect()
    }

    /// Take an explicit capture of the current live state with the given label.
    pub fn capture_now(&mut self, label: impl Into<String>) -> PayloadCapture {
        let step = self.replay_cursor.saturating_sub(1);
        let regs = self.reg_snapshots.get(&step).cloned();
        let cap = PayloadCapture {
            step,
            label: label.into(),
            memory: self.memory.clone(),
            regs,
        };
        self.captures.push(cap.clone());
        self.stats.captures_taken += 1;
        cap
    }

    // ------------------------------------------------------------------
    // Final state analysis
    // ------------------------------------------------------------------

    /// Return the final memory state as contiguous `FinalRegion`s.
    #[must_use] 
    pub fn final_regions(&self) -> Vec<FinalRegion> {
        if self.memory.is_empty() {
            return Vec::new();
        }
        let addrs: Vec<u64> = self.memory.keys().copied().collect();
        let mut regions: Vec<FinalRegion> = Vec::new();
        let mut base = addrs[0];
        let mut bytes = vec![self.memory[&addrs[0]]];

        for &addr in &addrs[1..] {
            let expected = base.wrapping_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
            if addr.saturating_sub(expected) <= self.config.gap_threshold {
                // Fill any gap within threshold.
                let gap = usize::try_from(addr - expected).unwrap_or(usize::MAX);
                bytes.extend(std::iter::repeat_n(0xCC, gap));
                bytes.push(self.memory[&addr]);
            } else {
                regions.push(FinalRegion { base, bytes });
                base = addr;
                bytes = vec![self.memory[&addr]];
            }
        }
        regions.push(FinalRegion { base, bytes });
        regions
    }

    /// Retrieve all taken captures, sorted by step.
    #[must_use] 
    pub fn captures(&self) -> &[PayloadCapture] {
        &self.captures
    }

    /// Find a capture by label.
    #[must_use] 
    pub fn capture_by_label(&self, label: &str) -> Option<&PayloadCapture> {
        self.captures.iter().find(|c| c.label == label)
    }

    /// Find the capture closest to but not exceeding `step`.
    #[must_use] 
    pub fn capture_at_or_before(&self, step: usize) -> Option<&PayloadCapture> {
        self.captures.iter().rev().find(|c| c.step <= step)
    }

    /// Statistics.
    #[must_use] 
    pub fn stats(&self) -> EmulatorStats {
        EmulatorStats {
            total_writes: self.stats.total_writes,
            unique_addresses: self.stats.unique_addresses,
            overwrites: self.stats.overwrites,
            captures_taken: self.stats.captures_taken,
            distinct_write_pcs: self.write_pcs.len() as u64,
        }
    }

    /// How many steps have been applied so far (streaming replay).
    #[must_use] 
    pub const fn replay_cursor(&self) -> usize {
        self.replay_cursor
    }

    /// Total write count.
    #[must_use] 
    pub const fn total_writes(&self) -> usize {
        self.writes.len()
    }

    /// Number of unique addresses ever written.
    #[must_use] 
    pub fn unique_address_count(&self) -> usize {
        self.memory.len()
    }
}

// ---------------------------------------------------------------------------
// Diff between two PayloadCaptures
// ---------------------------------------------------------------------------

/// A single differing byte between two captures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureDiff {
    pub addr: u64,
    pub before: Option<u8>,
    pub after: Option<u8>,
}

/// Compute the diff between two `PayloadCapture` instances.
#[must_use] 
pub fn diff_captures(before: &PayloadCapture, after: &PayloadCapture) -> Vec<CaptureDiff> {
    let mut diffs = Vec::new();

    // Addresses only in `before`.
    for (&addr, &val) in &before.memory {
        match after.memory.get(&addr) {
            Some(&av) if av != val => diffs.push(CaptureDiff {
                addr,
                before: Some(val),
                after: Some(av),
            }),
            None => diffs.push(CaptureDiff { addr, before: Some(val), after: None }),
            _ => {}
        }
    }

    // Addresses only in `after`.
    for (&addr, &val) in &after.memory {
        if !before.memory.contains_key(&addr) {
            diffs.push(CaptureDiff { addr, before: None, after: Some(val) });
        }
    }

    diffs.sort_by_key(|d| d.addr);
    diffs
}

// ---------------------------------------------------------------------------
// Decryption-round detector
// ---------------------------------------------------------------------------

/// Detect periodic patterns in writes that suggest a repeating decryption loop.
///
/// Returns a `Vec<(round_number, start_step, end_step)>` where each tuple marks
/// one decryption round detected by a repeating stride in write addresses.
#[must_use] 
pub fn detect_decrypt_rounds(
    writes: &[EmulationWrite],
    min_round_len: usize,
) -> Vec<(usize, usize, usize)> {
    if writes.len() < min_round_len * 2 {
        return Vec::new();
    }

    // Find the most common write-address stride.
    let mut stride_count: HashMap<u64, usize> = HashMap::new();
    for pair in writes.windows(2) {
        let stride = pair[1].target_addr.wrapping_sub(pair[0].target_addr);
        if stride > 0 && stride <= 16 {
            *stride_count.entry(stride).or_insert(0) += 1;
        }
    }

    let Some((&dominant_stride, _)) = stride_count.iter().max_by_key(|&(_, &c)| c) else { return Vec::new() };

    // Segment the write trace into runs matching the dominant stride.
    let mut rounds = Vec::new();
    let mut round_start = 0usize;
    let mut round_num = 0usize;
    let mut run_len = 1usize;

    for i in 1..writes.len() {
        let stride = writes[i].target_addr.wrapping_sub(writes[i - 1].target_addr);
        if stride == dominant_stride {
            run_len += 1;
        } else {
            if run_len >= min_round_len {
                rounds.push((round_num, round_start, i - 1));
                round_num += 1;
            }
            round_start = i;
            run_len = 1;
        }
    }
    if run_len >= min_round_len {
        rounds.push((round_num, round_start, writes.len() - 1));
    }

    rounds
}

// ---------------------------------------------------------------------------
// Streaming capture builder — convenience wrapper for feeding events from a queue
// ---------------------------------------------------------------------------

/// A `VecDeque`-backed source that drains into `SmcEmulator::push_write`.
pub struct StreamingEmulator {
    inner: SmcEmulator,
    pending: VecDeque<(u64, u8, u64)>,
}

impl StreamingEmulator {
    #[must_use] 
    pub fn new(config: EmulatorConfig) -> Self {
        Self { inner: SmcEmulator::new(config), pending: VecDeque::new() }
    }

    pub fn enqueue(&mut self, target_addr: u64, value: u8, write_pc: u64) {
        self.pending.push_back((target_addr, value, write_pc));
    }

    /// Drain up to `n` pending writes into the emulator.
    ///
    /// # Errors
    /// Returns an error if any write fails (see [`SmcEmulator::push_write`]).
    pub fn drain(&mut self, n: usize) -> Result<usize, EmulatorError> {
        let mut applied = 0;
        while applied < n {
            match self.pending.pop_front() {
                None => break,
                Some((a, v, pc)) => {
                    self.inner.push_write(a, v, pc)?;
                    applied += 1;
                }
            }
        }
        Ok(applied)
    }

    /// Drain all pending writes.
    ///
    /// # Errors
    /// Returns an error if any write fails (see [`Self::drain`]).
    pub fn drain_all(&mut self) -> Result<usize, EmulatorError> {
        self.drain(self.pending.len())
    }

    #[must_use] 
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    #[must_use] 
    pub const fn emulator(&self) -> &SmcEmulator {
        &self.inner
    }

    pub const fn emulator_mut(&mut self) -> &mut SmcEmulator {
        &mut self.inner
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn build_simple_emulator() -> SmcEmulator {
        let mut emu = SmcEmulator::new(EmulatorConfig::default());
        for i in 0u64..8 {
            emu.push_write(0x1000 + i, i as u8, 0xDEAD).unwrap();
        }
        emu
    }

    #[test]
    fn test_run_full_populates_memory() {
        let mut emu = build_simple_emulator();
        emu.run_full().unwrap();
        for i in 0u64..8 {
            assert_eq!(emu.read_byte(0x1000 + i), Some(i as u8));
        }
    }

    #[test]
    fn test_captures_taken_at_requested_steps() {
        let mut emu = build_simple_emulator();
        emu.request_capture(3, "mid").unwrap();
        emu.request_capture(7, "end").unwrap();
        emu.run_full().unwrap();
        assert_eq!(emu.captures().len(), 2);
        assert_eq!(emu.captures()[0].label, "mid");
        assert_eq!(emu.captures()[1].label, "end");
    }

    #[test]
    fn test_duplicate_capture_error() {
        let mut emu = build_simple_emulator();
        emu.request_capture(2, "a").unwrap();
        assert!(matches!(
            emu.request_capture(2, "b"),
            Err(EmulatorError::DuplicateCapture(2))
        ));
    }

    #[test]
    fn test_step_once_replay() {
        let mut emu = build_simple_emulator();
        // Step through 4 writes manually.
        for _ in 0..4 {
            let w = emu.step_once().unwrap();
            assert!(w.step < 4);
        }
        assert_eq!(emu.replay_cursor(), 4);
    }

    #[test]
    fn test_final_regions_single() {
        let mut emu = SmcEmulator::new(EmulatorConfig::default());
        emu.push_writes(vec![(0x500, 0xAA, 0), (0x501, 0xBB, 0), (0x502, 0xCC, 0)]).unwrap();
        emu.run_full().unwrap();
        let regions = emu.final_regions();
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].base, 0x500);
        assert_eq!(regions[0].bytes, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_final_regions_multiple() {
        let mut emu = SmcEmulator::new(EmulatorConfig::default());
        emu.push_write(0x100, 0x01, 0).unwrap();
        emu.push_write(0x200, 0x02, 0).unwrap(); // 256-byte gap → new region
        emu.run_full().unwrap();
        let regions = emu.final_regions();
        assert_eq!(regions.len(), 2);
    }

    #[test]
    fn test_diff_captures() {
        let mut emu = SmcEmulator::new(EmulatorConfig::default());
        emu.push_write(0x300, 0x11, 0).unwrap();
        emu.request_capture(0, "before").unwrap();
        emu.push_write(0x300, 0x22, 0).unwrap();
        emu.request_capture(1, "after").unwrap();
        emu.run_full().unwrap();
        let caps = emu.captures();
        let diffs = diff_captures(&caps[0], &caps[1]);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].addr, 0x300);
        assert_eq!(diffs[0].before, Some(0x11));
        assert_eq!(diffs[0].after, Some(0x22));
    }

    #[test]
    fn test_detect_decrypt_rounds() {
        // Build a write trace with two obvious rounds: 0..16 then 0x100..0x110
        let mut writes = Vec::new();
        for i in 0u64..16 {
            writes.push(EmulationWrite { target_addr: i, value: 0, write_pc: 0, step: i as usize });
        }
        for i in 0u64..16 {
            writes.push(EmulationWrite {
                target_addr: 0x100 + i,
                value: 0,
                write_pc: 0,
                step: 16 + i as usize,
            });
        }
        let rounds = detect_decrypt_rounds(&writes, 8);
        assert!(!rounds.is_empty());
    }

    #[test]
    fn test_streaming_emulator() {
        let mut stream = StreamingEmulator::new(EmulatorConfig::default());
        stream.enqueue(0xA00, 0xDE, 0);
        stream.enqueue(0xA01, 0xAD, 0);
        assert_eq!(stream.pending_count(), 2);
        let applied = stream.drain_all().unwrap();
        assert_eq!(applied, 2);
        assert_eq!(stream.pending_count(), 0);
        stream.emulator_mut().run_full().unwrap();
        assert_eq!(stream.emulator().read_byte(0xA00), Some(0xDE));
    }

    #[test]
    fn test_no_steps_error() {
        let mut emu = SmcEmulator::new(EmulatorConfig::default());
        assert!(matches!(emu.run_full(), Err(EmulatorError::NoSteps)));
    }

    #[test]
    fn test_overwrite_tracking() {
        let mut emu = SmcEmulator::new(EmulatorConfig::default());
        emu.push_write(0x600, 0x01, 0).unwrap();
        emu.push_write(0x600, 0x02, 0).unwrap(); // overwrite
        emu.run_full().unwrap();
        assert_eq!(emu.stats().overwrites, 1);
        assert_eq!(emu.read_byte(0x600), Some(0x02));
    }
}
