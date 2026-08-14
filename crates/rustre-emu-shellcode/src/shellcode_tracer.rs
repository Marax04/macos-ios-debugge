//! Instruction-level tracing, coverage bitmap, basic block recording, and
//! taint tracking for shellcode execution analysis.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// ── Coverage bitmap ───────────────────────────────────────────────────────────

/// A bit-per-address coverage bitmap for tracking which addresses were executed.
///
/// Addresses outside the tracked range are silently ignored.
#[derive(Debug, Clone)]
pub struct CoverageBitmap {
    /// Base address of the tracked range.
    base: u64,
    /// Number of bytes in the range.
    range: usize,
    /// Underlying bit array: bit `(addr - base)` is set when `addr` was executed.
    bits: Vec<u64>,
}

impl CoverageBitmap {
    /// Create a bitmap tracking `range` addresses starting at `base`.
    #[must_use]
    pub fn new(base: u64, range: usize) -> Self {
        let words = (range + 63) / 64;
        Self { base, range, bits: vec![0u64; words] }
    }

    /// Mark `addr` as covered.
    pub fn mark(&mut self, addr: u64) {
        if let Some(bit_idx) = addr.checked_sub(self.base).map(|d| d as usize) {
            if bit_idx < self.range {
                let word = bit_idx / 64;
                let bit = bit_idx % 64;
                self.bits[word] |= 1u64 << bit;
            }
        }
    }

    /// Return `true` if `addr` has been covered.
    #[must_use]
    pub fn is_covered(&self, addr: u64) -> bool {
        match addr.checked_sub(self.base).map(|d| d as usize) {
            Some(bit_idx) if bit_idx < self.range => {
                let word = bit_idx / 64;
                let bit = bit_idx % 64;
                (self.bits[word] >> bit) & 1 == 1
            }
            _ => false,
        }
    }

    /// Number of covered addresses.
    #[must_use]
    pub fn covered_count(&self) -> usize {
        self.bits.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Coverage percentage (0.0 – 100.0).
    #[must_use]
    pub fn coverage_pct(&self) -> f64 {
        if self.range == 0 { return 100.0; }
        (self.covered_count() as f64 / self.range as f64) * 100.0
    }

    /// Merge `other` into `self` (bitwise OR).
    pub fn merge(&mut self, other: &CoverageBitmap) {
        for (a, b) in self.bits.iter_mut().zip(other.bits.iter()) {
            *a |= b;
        }
    }

    /// Base address of this bitmap.
    #[must_use]
    pub const fn base(&self) -> u64 { self.base }

    /// Tracked range in bytes.
    #[must_use]
    pub const fn range(&self) -> usize { self.range }
}

// ── Basic block ───────────────────────────────────────────────────────────────

/// A recorded basic block from the execution trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    /// Start address.
    pub start: u64,
    /// Exclusive end address (start of the next block / branch target).
    pub end: u64,
    /// Number of times this block was entered.
    pub hit_count: u64,
    /// Addresses of instructions within the block.
    pub instructions: Vec<u64>,
    /// Successor addresses (branch targets / fall-through).
    pub successors: Vec<u64>,
}

impl BasicBlock {
    #[must_use]
    pub fn new(start: u64) -> Self {
        Self {
            start,
            end: start,
            hit_count: 0,
            instructions: Vec::new(),
            successors: Vec::new(),
        }
    }

    #[must_use]
    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    #[must_use]
    pub fn byte_size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

/// Records and maintains the basic block graph derived from an execution trace.
#[derive(Debug, Default)]
pub struct BasicBlockRecorder {
    blocks: HashMap<u64, BasicBlock>,
    /// Current basic block start address during recording.
    current_start: Option<u64>,
    /// Addresses in the current partial block.
    current_instrs: Vec<u64>,
}

impl BasicBlockRecorder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one instruction at `pc` with byte `size`.
    ///
    /// Heuristically ends the current block when a control-flow instruction
    /// (identified by opcode in `opcode_hint`) is encountered.
    pub fn record_instruction(&mut self, pc: u64, size: usize, opcode_hint: u8) {
        if self.current_start.is_none() {
            self.current_start = Some(pc);
        }
        self.current_instrs.push(pc);

        // End block on RET (0xC3/0xCB), JMP (0xE9/0xEB/0xFF), INT3 (0xCC)
        let is_terminator = matches!(opcode_hint, 0xC3 | 0xCB | 0xE9 | 0xEB | 0xFF | 0xCC | 0x74 | 0x75 | 0xF4);
        if is_terminator {
            self.flush_block(pc + size as u64);
        }
    }

    /// Force-close the current partial block at `end_addr`.
    pub fn flush_block(&mut self, end_addr: u64) {
        if let Some(start) = self.current_start.take() {
            let instrs = std::mem::take(&mut self.current_instrs);
            let block = self.blocks.entry(start).or_insert_with(|| BasicBlock::new(start));
            block.end = end_addr;
            block.hit_count += 1;
            if block.instructions.is_empty() {
                block.instructions = instrs;
            }
        }
    }

    /// All recorded basic blocks.
    #[must_use]
    pub fn blocks(&self) -> &HashMap<u64, BasicBlock> {
        &self.blocks
    }

    /// Number of unique basic blocks seen.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// The hottest basic block (most hit count).
    #[must_use]
    pub fn hottest_block(&self) -> Option<&BasicBlock> {
        // `blocks` is a HashMap, so iteration order is not reproducible: ties on
        // `hit_count` must be broken on the start address, or the answer changes
        // between runs on the same trace.
        self.blocks
            .values()
            .max_by(|a, b| a.hit_count.cmp(&b.hit_count).then(b.start.cmp(&a.start)))
    }

    /// Total instruction execution count across all blocks.
    #[must_use]
    pub fn total_instruction_executions(&self) -> u64 {
        self.blocks.values().map(|b| b.hit_count * b.instructions.len() as u64).sum()
    }
}

// ── Taint tracking ────────────────────────────────────────────────────────────

/// A taint label identifying the origin of a tainted value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaintLabel {
    /// Byte index in the original shellcode input.
    InputByte(usize),
    /// A derived taint from a bitwise operation.
    Derived { from: Box<TaintLabel>, operation: String },
    /// Taint from a memory read at a given address.
    MemoryRead(u64),
    /// Taint injected by the emulation harness for API return values.
    ApiReturn(String),
}

/// One byte of taint state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaintByte {
    pub tainted: bool,
    pub labels: Vec<TaintLabel>,
}

impl TaintByte {
    #[must_use]
    pub fn clean() -> Self {
        Self { tainted: false, labels: Vec::new() }
    }

    #[must_use]
    pub fn from_input(byte_index: usize) -> Self {
        Self {
            tainted: true,
            labels: vec![TaintLabel::InputByte(byte_index)],
        }
    }

    pub fn add_label(&mut self, label: TaintLabel) {
        self.tainted = true;
        if !self.labels.contains(&label) {
            self.labels.push(label);
        }
    }
}

/// A simple register taint map for x86/x86-64 (by register id).
#[derive(Debug, Default)]
pub struct RegisterTaintMap {
    map: HashMap<u32, TaintByte>,
}

impl RegisterTaintMap {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    pub fn set(&mut self, reg_id: u32, taint: TaintByte) {
        self.map.insert(reg_id, taint);
    }

    #[must_use]
    pub fn get(&self, reg_id: u32) -> &TaintByte {
        self.map.get(&reg_id).unwrap_or(&CLEAN_TAINT_BYTE)
    }

    pub fn clear(&mut self, reg_id: u32) {
        self.map.insert(reg_id, TaintByte::clean());
    }

    #[must_use]
    pub fn tainted_registers(&self) -> Vec<u32> {
        self.map.iter().filter(|(_, t)| t.tainted).map(|(id, _)| *id).collect()
    }
}

static CLEAN_TAINT_BYTE: TaintByte = TaintByte { tainted: false, labels: Vec::new() };

/// Memory taint map — per-byte taint state for virtual addresses.
#[derive(Debug, Default)]
pub struct MemoryTaintMap {
    map: HashMap<u64, TaintByte>,
}

impl MemoryTaintMap {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Mark `len` bytes starting at `addr` as tainted with a single label.
    pub fn taint_range(&mut self, addr: u64, len: usize, label: TaintLabel) {
        for i in 0..len as u64 {
            let entry = self.map.entry(addr + i).or_insert_with(TaintByte::clean);
            entry.add_label(label.clone());
        }
    }

    /// Taint each byte of the shellcode input buffer.
    pub fn taint_input(&mut self, base_addr: u64, input: &[u8]) {
        for (i, _) in input.iter().enumerate() {
            let addr = base_addr + i as u64;
            self.map.insert(addr, TaintByte::from_input(i));
        }
    }

    pub fn clear_range(&mut self, addr: u64, len: usize) {
        for i in 0..len as u64 {
            self.map.remove(&(addr + i));
        }
    }

    #[must_use]
    pub fn is_tainted(&self, addr: u64) -> bool {
        self.map.get(&addr).map_or(false, |t| t.tainted)
    }

    #[must_use]
    pub fn get(&self, addr: u64) -> &TaintByte {
        self.map.get(&addr).unwrap_or(&CLEAN_TAINT_BYTE)
    }

    /// Number of tainted bytes.
    #[must_use]
    pub fn tainted_byte_count(&self) -> usize {
        self.map.values().filter(|t| t.tainted).count()
    }

    /// Collect all unique input byte indices that influenced the given address.
    #[must_use]
    pub fn input_bytes_for(&self, addr: u64) -> Vec<usize> {
        let mut result = Vec::new();
        if let Some(tb) = self.map.get(&addr) {
            for label in &tb.labels {
                if let TaintLabel::InputByte(idx) = label {
                    result.push(*idx);
                }
            }
        }
        result
    }
}

// ── Trace event ───────────────────────────────────────────────────────────────

/// The type of a trace event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TraceEventKind {
    Instruction { pc: u64, opcode_byte: u8, size: u8 },
    MemRead  { addr: u64, size: u8, value: u64 },
    MemWrite { addr: u64, size: u8, value: u64 },
    ApiCall  { name: String, args: Vec<u64>, ret: u64 },
    Exception { kind: String, addr: u64 },
    RegChange { reg_id: u32, old_val: u64, new_val: u64 },
}

/// A timestamped trace event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    /// Monotonically increasing event number.
    pub seq: u64,
    /// Event data.
    pub kind: TraceEventKind,
}

/// Configurable instruction-level tracer.
#[derive(Debug)]
pub struct ShellcodeTracer {
    /// Coverage bitmap (address → executed flag).
    pub coverage: CoverageBitmap,
    /// Basic block recorder.
    pub blocks: BasicBlockRecorder,
    /// Memory taint map.
    pub mem_taint: MemoryTaintMap,
    /// Register taint map.
    pub reg_taint: RegisterTaintMap,
    /// Sequential event log.
    pub events: Vec<TraceEvent>,
    /// Whether to record all events (may be verbose).
    pub record_events: bool,
    /// Per-address hit counts.
    hit_counts: HashMap<u64, u64>,
    /// Event sequence counter.
    seq: u64,
    /// Maximum events to record (0 = unlimited).
    max_events: usize,
}

impl ShellcodeTracer {
    /// Create a tracer for shellcode at `[base, base + range)`.
    #[must_use]
    pub fn new(base: u64, range: usize) -> Self {
        Self {
            coverage: CoverageBitmap::new(base, range),
            blocks: BasicBlockRecorder::new(),
            mem_taint: MemoryTaintMap::new(),
            reg_taint: RegisterTaintMap::new(),
            events: Vec::new(),
            record_events: true,
            hit_counts: HashMap::new(),
            seq: 0,
            max_events: 1_000_000,
        }
    }

    /// Set the maximum number of events to store.
    pub fn set_max_events(&mut self, max: usize) {
        self.max_events = max;
    }

    /// Seed the memory taint map with the original shellcode bytes.
    pub fn seed_input_taint(&mut self, base: u64, shellcode: &[u8]) {
        self.mem_taint.taint_input(base, shellcode);
    }

    // ── Recording callbacks ───────────────────────────────────────────────────

    /// Record an instruction execution.
    pub fn on_instruction(&mut self, pc: u64, opcode_byte: u8, size: u8) {
        self.coverage.mark(pc);
        *self.hit_counts.entry(pc).or_insert(0) += 1;
        self.blocks.record_instruction(pc, size as usize, opcode_byte);
        self.push_event(TraceEventKind::Instruction { pc, opcode_byte, size });
    }

    /// Record a memory read.
    pub fn on_mem_read(&mut self, addr: u64, size: u8, value: u64) {
        self.push_event(TraceEventKind::MemRead { addr, size, value });
    }

    /// Record a memory write.  Clears taint on written bytes (clean store).
    pub fn on_mem_write(&mut self, addr: u64, size: u8, value: u64) {
        self.mem_taint.clear_range(addr, size as usize);
        self.push_event(TraceEventKind::MemWrite { addr, size, value });
    }

    /// Record an API call.
    pub fn on_api_call(&mut self, name: impl Into<String>, args: Vec<u64>, ret: u64) {
        let name = name.into();
        // Taint the return value in RAX (reg_id 0 in our convention)
        let mut tb = TaintByte::clean();
        tb.add_label(TaintLabel::ApiReturn(name.clone()));
        self.reg_taint.set(0, tb);
        self.push_event(TraceEventKind::ApiCall { name, args, ret });
    }

    /// Record an exception or fault.
    pub fn on_exception(&mut self, kind: impl Into<String>, addr: u64) {
        self.blocks.flush_block(addr);
        self.push_event(TraceEventKind::Exception { kind: kind.into(), addr });
    }

    /// Record a register value change.
    pub fn on_reg_change(&mut self, reg_id: u32, old_val: u64, new_val: u64) {
        self.push_event(TraceEventKind::RegChange { reg_id, old_val, new_val });
    }

    // ── Query methods ─────────────────────────────────────────────────────────

    /// Hit count for a specific address.
    #[must_use]
    pub fn hit_count(&self, addr: u64) -> u64 {
        self.hit_counts.get(&addr).copied().unwrap_or(0)
    }

    /// Total instructions recorded.
    #[must_use]
    pub fn total_instructions(&self) -> u64 {
        self.hit_counts.values().sum()
    }

    /// Per-address hit counts sorted by frequency (hottest first).
    #[must_use]
    pub fn hot_addresses(&self) -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> = self.hit_counts.iter().map(|(&a, &c)| (a, c)).collect();
        // Collected from a HashMap: without the address tie-break, equally hot
        // addresses come out in a different order on every run.
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v
    }

    /// All addresses executed at least `min_hits` times.
    #[must_use]
    pub fn addresses_with_min_hits(&self, min_hits: u64) -> Vec<u64> {
        self.hit_counts.iter()
            .filter(|&(_, &c)| c >= min_hits)
            .map(|(&a, _)| a)
            .collect()
    }

    /// True if any tainted bytes from the input influenced `addr`.
    #[must_use]
    pub fn is_tainted_by_input(&self, addr: u64) -> bool {
        !self.mem_taint.input_bytes_for(addr).is_empty()
    }

    /// Compute a summary of this trace.
    #[must_use]
    pub fn summary(&self) -> TraceSummary {
        let instructions_executed = self.total_instructions();
        let unique_pcs = self.hit_counts.len() as u64;
        let covered_bytes = self.coverage.covered_count() as u64;
        let basic_blocks = self.blocks.block_count() as u64;
        let tainted_bytes = self.mem_taint.tainted_byte_count() as u64;
        let api_calls = self.events.iter().filter(|e| matches!(e.kind, TraceEventKind::ApiCall { .. })).count() as u64;
        let mem_reads = self.events.iter().filter(|e| matches!(e.kind, TraceEventKind::MemRead { .. })).count() as u64;
        let mem_writes = self.events.iter().filter(|e| matches!(e.kind, TraceEventKind::MemWrite { .. })).count() as u64;

        TraceSummary {
            instructions_executed,
            unique_pcs,
            covered_bytes,
            basic_blocks,
            tainted_bytes,
            api_calls,
            mem_reads,
            mem_writes,
        }
    }

    fn push_event(&mut self, kind: TraceEventKind) {
        if !self.record_events { return; }
        if self.max_events > 0 && self.events.len() >= self.max_events { return; }
        let seq = self.seq;
        self.seq += 1;
        self.events.push(TraceEvent { seq, kind });
    }
}

/// A compact summary of a completed trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSummary {
    pub instructions_executed: u64,
    pub unique_pcs: u64,
    pub covered_bytes: u64,
    pub basic_blocks: u64,
    pub tainted_bytes: u64,
    pub api_calls: u64,
    pub mem_reads: u64,
    pub mem_writes: u64,
}

// ── Trace diff ────────────────────────────────────────────────────────────────

/// Differences between two trace summaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDiff {
    pub new_instructions: i64,
    pub new_unique_pcs: i64,
    pub new_basic_blocks: i64,
    pub new_api_calls: i64,
}

impl TraceDiff {
    #[must_use]
    pub fn compute(before: &TraceSummary, after: &TraceSummary) -> Self {
        Self {
            new_instructions: after.instructions_executed as i64 - before.instructions_executed as i64,
            new_unique_pcs: after.unique_pcs as i64 - before.unique_pcs as i64,
            new_basic_blocks: after.basic_blocks as i64 - before.basic_blocks as i64,
            new_api_calls: after.api_calls as i64 - before.api_calls as i64,
        }
    }

    #[must_use]
    pub fn is_interesting(&self) -> bool {
        self.new_unique_pcs > 0 || self.new_basic_blocks > 0 || self.new_api_calls > 0
    }
}

// ── Corpus-guided taint oracle ────────────────────────────────────────────────

/// Checks whether a given input byte index influenced any API call or memory
/// write to an interesting region (stack, heap).
#[derive(Debug)]
pub struct TaintOracle<'a> {
    tracer: &'a ShellcodeTracer,
    stack_range: (u64, u64),
    heap_range: (u64, u64),
}

impl<'a> TaintOracle<'a> {
    #[must_use]
    pub fn new(tracer: &'a ShellcodeTracer, stack_range: (u64, u64), heap_range: (u64, u64)) -> Self {
        Self { tracer, stack_range, heap_range }
    }

    /// True if input byte `idx` influenced any API call argument.
    #[must_use]
    pub fn influenced_api_call(&self, input_byte_idx: usize) -> bool {
        for event in &self.tracer.events {
            if let TraceEventKind::ApiCall { args, .. } = &event.kind {
                for &arg in args {
                    if self.tracer.mem_taint
                        .input_bytes_for(arg)
                        .contains(&input_byte_idx)
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// True if input byte `idx` influenced any write to the stack.
    #[must_use]
    pub fn influenced_stack_write(&self, input_byte_idx: usize) -> bool {
        let (sbase, send) = self.stack_range;
        for event in &self.tracer.events {
            if let TraceEventKind::MemWrite { addr, .. } = event.kind {
                if addr >= sbase && addr < send {
                    if self.tracer.mem_taint.input_bytes_for(addr).contains(&input_byte_idx) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// True if input byte `idx` influenced any heap write.
    #[must_use]
    pub fn influenced_heap_write(&self, input_byte_idx: usize) -> bool {
        let (hbase, hend) = self.heap_range;
        for event in &self.tracer.events {
            if let TraceEventKind::MemWrite { addr, .. } = event.kind {
                if addr >= hbase && addr < hend {
                    if self.tracer.mem_taint.input_bytes_for(addr).contains(&input_byte_idx) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_bitmap_basic() {
        let mut bm = CoverageBitmap::new(0x1000, 256);
        assert!(!bm.is_covered(0x1000));
        bm.mark(0x1000);
        assert!(bm.is_covered(0x1000));
        assert!(!bm.is_covered(0x1001));
        assert_eq!(bm.covered_count(), 1);
    }

    #[test]
    fn coverage_bitmap_out_of_range() {
        let mut bm = CoverageBitmap::new(0x1000, 256);
        bm.mark(0x2000); // out of range, silently ignored
        assert_eq!(bm.covered_count(), 0);
    }

    #[test]
    fn coverage_bitmap_merge() {
        let mut a = CoverageBitmap::new(0x1000, 64);
        let mut b = CoverageBitmap::new(0x1000, 64);
        a.mark(0x1000);
        b.mark(0x1001);
        a.merge(&b);
        assert!(a.is_covered(0x1000));
        assert!(a.is_covered(0x1001));
    }

    #[test]
    fn basic_block_recorder() {
        let mut rec = BasicBlockRecorder::new();
        rec.record_instruction(0x1000, 1, 0x90); // NOP
        rec.record_instruction(0x1001, 1, 0x90); // NOP
        rec.record_instruction(0x1002, 1, 0xC3); // RET — ends block
        rec.flush_block(0x1003);
        assert!(rec.block_count() >= 1);
    }

    #[test]
    fn basic_block_hit_count() {
        let mut rec = BasicBlockRecorder::new();
        for _ in 0..5 {
            rec.record_instruction(0x1000, 1, 0x90);
            rec.record_instruction(0x1001, 1, 0xC3);
        }
        let bb = rec.blocks().get(&0x1000).unwrap();
        assert_eq!(bb.hit_count, 5);
    }

    #[test]
    fn taint_map_input() {
        let mut map = MemoryTaintMap::new();
        map.taint_input(0x1000, &[0xAA, 0xBB, 0xCC]);
        assert!(map.is_tainted(0x1000));
        assert!(map.is_tainted(0x1001));
        assert!(map.is_tainted(0x1002));
        assert!(!map.is_tainted(0x1003));
        assert_eq!(map.input_bytes_for(0x1001), vec![1]);
    }

    #[test]
    fn taint_map_clear() {
        let mut map = MemoryTaintMap::new();
        map.taint_input(0x1000, &[1, 2]);
        map.clear_range(0x1000, 1);
        assert!(!map.is_tainted(0x1000));
        assert!(map.is_tainted(0x1001));
    }

    #[test]
    fn tracer_records_instructions() {
        let mut tracer = ShellcodeTracer::new(0x1000, 64);
        tracer.on_instruction(0x1000, 0x90, 1);
        tracer.on_instruction(0x1001, 0xF4, 1);
        assert_eq!(tracer.total_instructions(), 2);
        assert_eq!(tracer.hit_count(0x1000), 1);
    }

    #[test]
    fn tracer_coverage() {
        let mut tracer = ShellcodeTracer::new(0x1000, 64);
        tracer.on_instruction(0x1000, 0x90, 1);
        tracer.on_instruction(0x1005, 0x90, 1);
        assert_eq!(tracer.coverage.covered_count(), 2);
    }

    #[test]
    fn tracer_taint_propagation() {
        let mut tracer = ShellcodeTracer::new(0x1000, 64);
        tracer.seed_input_taint(0x1000, &[0xAA, 0xBB]);
        assert!(tracer.is_tainted_by_input(0x1000));
        assert!(tracer.is_tainted_by_input(0x1001));
        assert!(!tracer.is_tainted_by_input(0x1002));
    }

    #[test]
    fn tracer_summary() {
        let mut tracer = ShellcodeTracer::new(0x1000, 256);
        tracer.on_instruction(0x1000, 0x90, 1);
        tracer.on_mem_write(0x2000, 4, 0xDEAD);
        tracer.on_api_call("VirtualAlloc", vec![0, 0x1000, 0x40], 0x3000);
        let s = tracer.summary();
        assert_eq!(s.instructions_executed, 1);
        assert_eq!(s.mem_writes, 1);
        assert_eq!(s.api_calls, 1);
    }

    #[test]
    fn trace_diff() {
        let before = TraceSummary {
            instructions_executed: 10, unique_pcs: 5, covered_bytes: 5,
            basic_blocks: 2, tainted_bytes: 0, api_calls: 0, mem_reads: 0, mem_writes: 0,
        };
        let after = TraceSummary {
            instructions_executed: 20, unique_pcs: 10, covered_bytes: 10,
            basic_blocks: 4, tainted_bytes: 0, api_calls: 2, mem_reads: 0, mem_writes: 0,
        };
        let diff = TraceDiff::compute(&before, &after);
        assert_eq!(diff.new_unique_pcs, 5);
        assert!(diff.is_interesting());
    }

    #[test]
    fn hot_addresses_sorted() {
        let mut tracer = ShellcodeTracer::new(0x1000, 256);
        for _ in 0..10 { tracer.on_instruction(0x1000, 0x90, 1); }
        for _ in 0..3  { tracer.on_instruction(0x1001, 0x90, 1); }
        let hot = tracer.hot_addresses();
        assert_eq!(hot[0].0, 0x1000);
        assert_eq!(hot[0].1, 10);
    }
}
