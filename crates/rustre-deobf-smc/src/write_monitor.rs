//! `write_monitor` — Monitor code-section writes for SMC detection.
//!
//! Tracks every write to an executable memory region, correlates write
//! sources with subsequent execute-from-same-address events, identifies
//! decryption loops, and records key-candidate constants.

use std::collections::{HashMap, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// WriteEvent
// ─────────────────────────────────────────────────────────────────────────────

/// A single observed write to an executable region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteEvent {
    /// Address that was written to.
    pub dest_addr: u64,
    /// Number of bytes written.
    pub size: usize,
    /// Bytes written (up to 16 bytes stored; longer writes are truncated here).
    pub bytes: Vec<u8>,
    /// Program counter of the writing instruction.
    pub writer_pc: u64,
    /// Sequential event number (monotonically increasing).
    pub seq: u64,
    /// CPU tick / instruction count at the time of the write.
    pub tick: u64,
}

impl WriteEvent {
    /// Build a new write event.
    #[must_use]
    pub fn new(dest_addr: u64, bytes: &[u8], writer_pc: u64, seq: u64, tick: u64) -> Self {
        let stored: Vec<u8> = bytes.iter().take(16).copied().collect();
        Self { dest_addr, size: bytes.len(), bytes: stored, writer_pc, seq, tick }
    }

    /// Returns `true` when the written bytes consist of a single repeated value.
    #[must_use]
    pub fn is_uniform(&self) -> bool {
        self.bytes.windows(2).all(|w| w[0] == w[1])
    }
}

impl fmt::Display for WriteEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[seq={} tick={} pc={:#x}] write {} byte(s) -> {:#x}",
            self.seq, self.tick, self.writer_pc, self.size, self.dest_addr
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CodeWrite
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated write to a contiguous code range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeWrite {
    /// Start address of the modified code region.
    pub region_start: u64,
    /// Exclusive end address.
    pub region_end: u64,
    /// All raw write events that touched this region, in order.
    pub events: Vec<WriteEvent>,
    /// Byte map: offset within the region → last-written byte.
    pub byte_map: Vec<u8>,
    /// Whether this region was executed after being written.
    pub executed_after_write: bool,
    /// First PC that executed from this region after a write.
    pub first_exec_pc: Option<u64>,
}

impl CodeWrite {
    /// Create an empty `CodeWrite` covering `[start, end)`.
    #[must_use]
    pub fn new(region_start: u64, region_end: u64) -> Self {
        let len = usize::try_from(region_end - region_start).unwrap_or(usize::MAX);
        Self {
            region_start,
            region_end,
            events: Vec::new(),
            byte_map: vec![0u8; len],
            executed_after_write: false,
            first_exec_pc: None,
        }
    }

    /// Record a write event, updating the byte map.
    pub fn apply_event(&mut self, ev: WriteEvent) {
        let offset = usize::try_from(ev.dest_addr.saturating_sub(self.region_start)).unwrap_or(usize::MAX);
        for (i, &b) in ev.bytes.iter().enumerate() {
            let idx = offset + i;
            if idx < self.byte_map.len() {
                self.byte_map[idx] = b;
            }
        }
        self.events.push(ev);
    }

    /// Number of bytes that have been written at least once.
    #[must_use]
    pub fn coverage(&self) -> usize {
        self.byte_map.iter().filter(|&&b| b != 0).count()
    }

    /// Returns a slice of the reconstructed bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.byte_map
    }

    /// Size of the region in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        usize::try_from(self.region_end - self.region_start).unwrap_or(usize::MAX)
    }
}

impl fmt::Display for CodeWrite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CodeWrite [{:#x}–{:#x}] events={} executed={}",
            self.region_start,
            self.region_end,
            self.events.len(),
            self.executed_after_write
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DecryptionLoop
// ─────────────────────────────────────────────────────────────────────────────

/// A detected decryption loop: a tight loop that writes to a code region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionLoop {
    /// Address of the loop entry (first instruction of the back-edge target).
    pub loop_entry: u64,
    /// Address of the loop back-edge instruction.
    pub loop_back: u64,
    /// Estimated number of iterations observed.
    pub iteration_count: u64,
    /// Addresses in the code section written by this loop.
    pub target_range: (u64, u64),
    /// Key candidates extracted from within the loop body.
    pub key_candidates: Vec<KeyCandidate>,
    /// Whether the loop modifies itself (double SMC).
    pub self_modifying: bool,
    /// First tick the loop was entered.
    pub first_tick: u64,
    /// Last tick the loop was observed.
    pub last_tick: u64,
}

impl DecryptionLoop {
    /// Construct a new loop descriptor.
    #[must_use]
    pub const fn new(
        loop_entry: u64,
        loop_back: u64,
        target_range: (u64, u64),
        first_tick: u64,
    ) -> Self {
        Self {
            loop_entry,
            loop_back,
            iteration_count: 0,
            target_range,
            key_candidates: Vec::new(),
            self_modifying: false,
            first_tick,
            last_tick: first_tick,
        }
    }

    /// Register another iteration.
    pub const fn tick_iteration(&mut self, tick: u64) {
        self.iteration_count += 1;
        self.last_tick = tick;
    }

    /// Approximate loop body size in instruction bytes.
    #[must_use]
    pub const fn span(&self) -> u64 {
        self.loop_back.saturating_sub(self.loop_entry)
    }
}

impl fmt::Display for DecryptionLoop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DecryptionLoop entry={:#x} back={:#x} iters={} target=[{:#x},{:#x}]",
            self.loop_entry,
            self.loop_back,
            self.iteration_count,
            self.target_range.0,
            self.target_range.1
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KeyCandidate
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of a key-candidate constant found in a decryption loop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyKind {
    /// XOR constant (e.g. `xor al, 0x42`).
    XorConst,
    /// ADD constant (e.g. `add al, 0x11`).
    AddConst,
    /// SUB constant (e.g. `sub al, 0x07`).
    SubConst,
    /// Rolling / accumulating key.
    Rolling,
    /// Register value used as key (index by name string).
    Register(String),
    /// Memory-derived key (loaded from an address).
    MemoryDerived(u64),
}

/// A candidate decryption key extracted from a write+execute pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyCandidate {
    /// Kind of operation the key is used with.
    pub kind: KeyKind,
    /// The raw constant value (for XOR/ADD/SUB kinds).
    pub value: u64,
    /// Size in bits of the operation (8, 16, 32, 64).
    pub operand_bits: u32,
    /// Instruction address where this constant appeared.
    pub insn_addr: u64,
    /// Confidence score in [0.0, 1.0].
    pub confidence: f32,
}

impl KeyCandidate {
    /// Create an XOR key candidate.
    #[must_use]
    pub const fn xor(value: u64, operand_bits: u32, insn_addr: u64, confidence: f32) -> Self {
        Self { kind: KeyKind::XorConst, value, operand_bits, insn_addr, confidence }
    }

    /// Create an ADD key candidate.
    #[must_use]
    pub const fn add(value: u64, operand_bits: u32, insn_addr: u64, confidence: f32) -> Self {
        Self { kind: KeyKind::AddConst, value, operand_bits, insn_addr, confidence }
    }

    /// Create a SUB key candidate.
    #[must_use]
    pub const fn sub(value: u64, operand_bits: u32, insn_addr: u64, confidence: f32) -> Self {
        Self { kind: KeyKind::SubConst, value, operand_bits, insn_addr, confidence }
    }

    /// Returns `true` if this is a byte-width XOR with a non-trivial constant.
    #[must_use]
    pub const fn is_byte_xor(&self) -> bool {
        matches!(self.kind, KeyKind::XorConst) && self.operand_bits == 8 && self.value != 0
    }
}

impl fmt::Display for KeyCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?}({:#x}, {}bit) @ {:#x} conf={:.2}",
            self.kind, self.value, self.operand_bits, self.insn_addr, self.confidence
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WriteMonitor internals
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the write monitor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteMonitorConfig {
    /// Maximum number of write events to retain in the ring buffer.
    pub ring_capacity: usize,
    /// Minimum number of writes to the same region before classifying as SMC.
    pub smc_write_threshold: usize,
    /// Window size (in writes) for loop detection heuristic.
    pub loop_window: usize,
    /// If `true`, track writes even outside known executable regions.
    pub track_all_writes: bool,
}

impl Default for WriteMonitorConfig {
    fn default() -> Self {
        Self {
            ring_capacity: 65536,
            smc_write_threshold: 4,
            loop_window: 16,
            track_all_writes: false,
        }
    }
}

/// Statistics collected by the write monitor.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WriteMonitorStats {
    pub total_write_events: u64,
    pub writes_to_exec_regions: u64,
    pub unique_writer_pcs: u64,
    pub decryption_loops_detected: u64,
    pub key_candidates_found: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// WriteMonitor
// ─────────────────────────────────────────────────────────────────────────────

/// Core monitor: tracks all writes to executable memory regions.
pub struct WriteMonitor {
    /// Configuration.
    pub config: WriteMonitorConfig,
    /// Known executable regions: `(start, end)`.
    executable_regions: Vec<(u64, u64)>,
    /// Aggregated code writes keyed by region start.
    pub code_writes: HashMap<u64, CodeWrite>,
    /// Detected decryption loops.
    pub decryption_loops: Vec<DecryptionLoop>,
    /// Recent write events (ring buffer).
    recent_events: VecDeque<WriteEvent>,
    /// All unique writer PCs seen so far.
    writer_pcs: HashMap<u64, u64>,
    /// Sequential counter for events.
    seq_counter: u64,
    /// Statistics.
    pub stats: WriteMonitorStats,
}

impl WriteMonitor {
    /// Create a new monitor with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(WriteMonitorConfig::default())
    }

    /// Create a monitor with explicit configuration.
    #[must_use]
    pub fn with_config(config: WriteMonitorConfig) -> Self {
        Self {
            config,
            executable_regions: Vec::new(),
            code_writes: HashMap::new(),
            decryption_loops: Vec::new(),
            recent_events: VecDeque::new(),
            writer_pcs: HashMap::new(),
            seq_counter: 0,
            stats: WriteMonitorStats::default(),
        }
    }

    /// Register an executable memory region `[start, end)`.
    ///
    /// # Panics
    ///
    /// Panics if `end <= start`.
    pub fn add_exec_region(&mut self, start: u64, end: u64) {
        assert!(end > start, "region end must be greater than start");
        // Merge overlapping regions.
        self.executable_regions.push((start, end));
        self.executable_regions.sort_by_key(|r| r.0);
        // Ensure a CodeWrite exists for this region.
        self.code_writes.entry(start).or_insert_with(|| CodeWrite::new(start, end));
    }

    /// Remove an executable region (e.g. after unmap).
    pub fn remove_exec_region(&mut self, start: u64) {
        self.executable_regions.retain(|r| r.0 != start);
        self.code_writes.remove(&start);
    }

    /// Returns `true` if `addr` falls inside any registered executable region.
    #[must_use]
    pub fn is_executable(&self, addr: u64) -> bool {
        self.executable_regions.iter().any(|&(s, e)| addr >= s && addr < e)
    }

    /// Find the region key (start address) that owns `addr`, if any.
    fn region_for(&self, addr: u64) -> Option<u64> {
        for &(s, e) in &self.executable_regions {
            if addr >= s && addr < e {
                return Some(s);
            }
        }
        None
    }

    /// Record a memory write from `writer_pc` to `[dest, dest+size)`.
    ///
    /// Call this from a memory-write hook in the emulator.
    pub fn on_write(&mut self, dest_addr: u64, bytes: &[u8], writer_pc: u64, tick: u64) {
        self.seq_counter += 1;
        let seq = self.seq_counter;
        self.stats.total_write_events += 1;

        let ev = WriteEvent::new(dest_addr, bytes, writer_pc, seq, tick);

        // Maintain ring buffer.
        if self.recent_events.len() >= self.config.ring_capacity {
            self.recent_events.pop_front();
        }
        self.recent_events.push_back(ev.clone());

        // Track writer PCs.
        *self.writer_pcs.entry(writer_pc).or_insert(0) += 1;

        let in_exec = self.is_executable(dest_addr);
        if in_exec {
            self.stats.writes_to_exec_regions += 1;
        }

        if in_exec || self.config.track_all_writes {
            if let Some(region_key) = self.region_for(dest_addr)
                && let Some(cw) = self.code_writes.get_mut(&region_key)
            {
                cw.apply_event(ev);
            }
            // Try to detect a loop pattern.
            self.try_detect_loop(writer_pc, dest_addr, tick);
        }

        self.stats.unique_writer_pcs = u64::try_from(self.writer_pcs.len()).unwrap_or(u64::MAX);
    }

    /// Notify the monitor that execution reached `exec_pc`.
    ///
    /// Marks any code write region that covers `exec_pc` as "executed after write".
    pub fn on_execute(&mut self, exec_pc: u64) {
        if let Some(region_key) = self.region_for(exec_pc)
            && let Some(cw) = self.code_writes.get_mut(&region_key)
            && !cw.events.is_empty()
            && !cw.executed_after_write
        {
            cw.executed_after_write = true;
            cw.first_exec_pc = Some(exec_pc);
        }
    }

    /// Heuristic: detect decryption loop if the same PC wrote to the code section
    /// many times within the recent-event window.
    fn try_detect_loop(&mut self, writer_pc: u64, dest_addr: u64, tick: u64) {
        let window = self.config.loop_window;
        let threshold = self.config.smc_write_threshold;

        // Count writes from the same PC in the recent window.
        let count = self
            .recent_events
            .iter()
            .rev()
            .take(window)
            .filter(|e| e.writer_pc == writer_pc && self.is_executable(e.dest_addr))
            .count();

        if count < threshold {
            return;
        }

        // Check if we already have a loop for this PC.
        if self.decryption_loops.iter().any(|l| l.loop_entry == writer_pc) {
            // Update iteration count on existing loop.
            if let Some(l) = self.decryption_loops.iter_mut().find(|l| l.loop_entry == writer_pc) {
                l.tick_iteration(tick);
            }
            return;
        }

        // Find target range from recent events of this PC.
        let targets: Vec<u64> = self
            .recent_events
            .iter()
            .rev()
            .take(window)
            .filter(|e| e.writer_pc == writer_pc)
            .map(|e| e.dest_addr)
            .collect();

        let min_addr = targets.iter().copied().min().unwrap_or(dest_addr);
        let max_addr = targets.iter().copied().max().unwrap_or(dest_addr);

        let mut lp = DecryptionLoop::new(writer_pc, writer_pc, (min_addr, max_addr + 1), tick);
        lp.iteration_count = count as u64;
        self.decryption_loops.push(lp);
        self.stats.decryption_loops_detected += 1;
    }

    /// Inject key candidates extracted externally (e.g. from disassembly of the loop body).
    pub fn add_key_candidate(&mut self, loop_entry: u64, candidate: KeyCandidate) {
        if let Some(lp) = self.decryption_loops.iter_mut().find(|l| l.loop_entry == loop_entry) {
            lp.key_candidates.push(candidate);
            self.stats.key_candidates_found += 1;
        }
    }

    /// Return all code writes that were executed after being modified.
    #[must_use]
    pub fn executed_writes(&self) -> Vec<&CodeWrite> {
        self.code_writes.values().filter(|cw| cw.executed_after_write).collect()
    }

    /// Return all detected decryption loops sorted by iteration count (descending).
    #[must_use]
    pub fn ranked_loops(&self) -> Vec<&DecryptionLoop> {
        let mut loops: Vec<&DecryptionLoop> = self.decryption_loops.iter().collect();
        loops.sort_by(|a, b| b.iteration_count.cmp(&a.iteration_count));
        loops
    }

    /// Drain all recent events from the ring buffer and return them.
    pub fn drain_events(&mut self) -> Vec<WriteEvent> {
        self.recent_events.drain(..).collect()
    }

    /// Return a summary of all writer PCs sorted by write frequency.
    #[must_use]
    pub fn top_writers(&self, n: usize) -> Vec<(u64, u64)> {
        let mut sorted: Vec<(u64, u64)> = self.writer_pcs.iter().map(|(&pc, &c)| (pc, c)).collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(n);
        sorted
    }

    /// Clear all accumulated state, keeping configuration and registered regions.
    pub fn reset(&mut self) {
        self.code_writes.clear();
        self.decryption_loops.clear();
        self.recent_events.clear();
        self.writer_pcs.clear();
        self.seq_counter = 0;
        self.stats = WriteMonitorStats::default();
        // Recreate empty CodeWrite entries for existing regions.
        let regions: Vec<(u64, u64)> = self.executable_regions.clone();
        for (s, e) in regions {
            self.code_writes.insert(s, CodeWrite::new(s, e));
        }
    }

    /// Snapshot current stats.
    #[must_use]
    pub const fn stats(&self) -> &WriteMonitorStats {
        &self.stats
    }
}

impl Default for WriteMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for WriteMonitor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WriteMonitor [exec_regions={} code_writes={} loops={} total_events={}]",
            self.executable_regions.len(),
            self.code_writes.len(),
            self.decryption_loops.len(),
            self.stats.total_write_events
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_monitor() -> WriteMonitor {
        let mut m = WriteMonitor::new();
        m.add_exec_region(0x1000, 0x2000);
        m
    }

    #[test]
    fn test_write_to_exec_region_tracked() {
        let mut m = make_monitor();
        m.on_write(0x1010, &[0xaa, 0xbb], 0x500, 1);
        assert_eq!(m.stats.writes_to_exec_regions, 1);
        let cw = m.code_writes.get(&0x1000).unwrap();
        assert_eq!(cw.byte_map[0x10], 0xaa);
        assert_eq!(cw.byte_map[0x11], 0xbb);
    }

    #[test]
    fn test_execute_marks_code_write() {
        let mut m = make_monitor();
        m.on_write(0x1100, &[0x90], 0x600, 1);
        m.on_execute(0x1100);
        let cw = m.code_writes.get(&0x1000).unwrap();
        assert!(cw.executed_after_write);
        assert_eq!(cw.first_exec_pc, Some(0x1100));
    }

    #[test]
    fn test_loop_detection() {
        let mut m = WriteMonitor::with_config(WriteMonitorConfig {
            smc_write_threshold: 3,
            loop_window: 8,
            ..Default::default()
        });
        m.add_exec_region(0x4000, 0x5000);
        for i in 0..5u64 {
            m.on_write(0x4000 + i, &[0xcc], 0x200, i + 1);
        }
        assert!(!m.decryption_loops.is_empty());
        assert_eq!(m.decryption_loops[0].loop_entry, 0x200);
    }

    #[test]
    fn test_key_candidate_xor() {
        let kc = KeyCandidate::xor(0x42, 8, 0x1234, 0.9);
        assert!(kc.is_byte_xor());
        assert_eq!(kc.value, 0x42);
    }

    #[test]
    fn test_write_event_display() {
        let ev = WriteEvent::new(0xdead_beef, &[1, 2, 3], 0xcafe, 7, 100);
        let s = format!("{ev}");
        assert!(s.contains("0xdeadbeef"));
    }

    #[test]
    fn test_reset_clears_state() {
        let mut m = make_monitor();
        m.on_write(0x1000, &[0xff], 0x300, 1);
        m.reset();
        assert_eq!(m.stats.total_write_events, 0);
        assert!(m.code_writes.get(&0x1000).unwrap().events.is_empty());
    }

    #[test]
    fn test_top_writers() {
        let mut m = make_monitor();
        m.on_write(0x1000, &[0x01], 0xaaa, 1);
        m.on_write(0x1001, &[0x02], 0xaaa, 2);
        m.on_write(0x1002, &[0x03], 0xbbb, 3);
        let top = m.top_writers(2);
        assert_eq!(top[0].0, 0xaaa);
        assert_eq!(top[0].1, 2);
    }

    #[test]
    fn test_non_exec_write_not_tracked_by_default() {
        let mut m = make_monitor();
        m.on_write(0x9000, &[0xff], 0x400, 1);
        assert_eq!(m.stats.writes_to_exec_regions, 0);
    }

    #[test]
    fn test_code_write_coverage() {
        let mut cw = CodeWrite::new(0x0, 0x10);
        let ev = WriteEvent::new(0x4, &[0xaa, 0xbb], 0x100, 1, 1);
        cw.apply_event(ev);
        assert_eq!(cw.coverage(), 2);
    }
}
