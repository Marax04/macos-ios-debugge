//! TTD trace index — fast O(log n) query over recorded trace events.
//!
//! Builds in-memory sorted indexes over a [`TtdTrace`] so that callers can ask:
//!
//! * "At what positions did `rax` hold value `0x1234`?"
//! * "When was address `0x7fff_1234` written?"
//! * "Give me all positions of `CreateFile` calls."
//!
//! The index is organized into four sub-indexes:
//! 1. **Register index** — `(reg_name, value) → sorted Vec<Position>`.
//! 2. **Memory write index** — `address → sorted Vec<Position>`.
//! 3. **Memory read index** — `address → sorted Vec<Position>`.
//! 4. **Syscall/call index** — `call_name → sorted Vec<Position>`.
//!
//! All position vectors are kept sorted so binary-search range queries run in O(log n).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ── Position type (re-exported from parent) ───────────────────────────────────

/// A lightweight (sequence, step) cursor into the trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Position {
    pub sequence: u64,
    pub step: u32,
}

impl Position {
    pub const ZERO: Self = Self { sequence: 0, step: 0 };

    #[must_use] 
    pub const fn new(sequence: u64, step: u32) -> Self {
        Self { sequence, step }
    }
}

impl std::fmt::Display for Position {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.sequence, self.step)
    }
}

// ── Trace event (simplified for indexing) ────────────────────────────────────

/// Minimal event record used for index construction.
/// The full trace format is handled by `TtdTrace` and `TtdSession`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEvent {
    pub position: Position,
    pub kind: IndexEventKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IndexEventKind {
    /// A register was set to a value.
    RegisterWrite {
        register: String,
        value: u64,
    },
    /// Memory at `address` was written with `value` (up to 8 bytes).
    MemoryWrite {
        address: u64,
        value: u64,
        size: u8,
    },
    /// Memory at `address` was read.
    MemoryRead {
        address: u64,
        size: u8,
    },
    /// A call was made (system call or imported function).
    Call {
        target_name: String,
        target_address: u64,
    },
    /// Thread switch event.
    ThreadSwitch {
        from_tid: u32,
        to_tid: u32,
    },
    /// Exception event.
    Exception {
        code: u32,
        address: u64,
    },
}

// ── Query range ───────────────────────────────────────────────────────────────

/// A position range for queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PositionRange {
    pub start: Position,
    pub end: Position,
}

impl PositionRange {
    #[must_use] 
    pub const fn new(start: Position, end: Position) -> Self {
        Self { start, end }
    }

    #[must_use] 
    pub const fn from_start(start: Position) -> Self {
        Self {
            start,
            end: Position::new(u64::MAX, u32::MAX),
        }
    }

    #[must_use] 
    pub const fn full() -> Self {
        Self {
            start: Position::ZERO,
            end: Position::new(u64::MAX, u32::MAX),
        }
    }

    #[must_use] 
    pub fn contains(&self, pos: &Position) -> bool {
        pos >= &self.start && pos <= &self.end
    }
}

// ── Register index ────────────────────────────────────────────────────────────

/// Sorted index: `(register_name, value) → Vec<Position>` (ascending).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RegisterIndex {
    /// Map from (register, value) → sorted positions
    entries: HashMap<(String, u64), Vec<Position>>,
    /// Map from register → all (value, position) pairs for range queries
    by_register: HashMap<String, Vec<(u64, Position)>>,
}

impl RegisterIndex {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, register: impl Into<String>, value: u64, pos: Position) {
        let reg = register.into();
        self.entries
            .entry((reg.clone(), value))
            .or_default()
            .push(pos);
        self.by_register
            .entry(reg)
            .or_default()
            .push((value, pos));
    }

    /// Sort all internal vectors. Must be called after bulk insert before querying.
    pub fn finalize(&mut self) {
        for v in self.entries.values_mut() {
            v.sort();
        }
        for v in self.by_register.values_mut() {
            v.sort_by_key(|(_, p)| *p);
        }
    }

    /// All positions where `register == value`.
    #[must_use] 
    pub fn query_exact(&self, register: &str, value: u64) -> &[Position] {
        self.entries
            .get(&(register.to_string(), value))
            .map_or(&[][..], |v| v.as_slice())
    }

    /// Positions in a position range where `register == value`.
    #[must_use] 
    pub fn query_in_range(&self, register: &str, value: u64, range: PositionRange) -> Vec<Position> {
        let all = self.query_exact(register, value);
        // Binary search bounds
        let lo = all.partition_point(|p| p < &range.start);
        let hi = all.partition_point(|p| p <= &range.end);
        all[lo..hi].to_vec()
    }

    /// First position where `register == value`.
    #[must_use] 
    pub fn first_occurrence(&self, register: &str, value: u64) -> Option<Position> {
        self.query_exact(register, value).first().copied()
    }

    /// First position where `register == value` at or after `from`.
    #[must_use] 
    pub fn first_after(&self, register: &str, value: u64, from: Position) -> Option<Position> {
        let all = self.query_exact(register, value);
        let idx = all.partition_point(|p| p < &from);
        all.get(idx).copied()
    }

    /// All distinct values observed for a register.
    #[must_use] 
    pub fn distinct_values(&self, register: &str) -> Vec<u64> {
        let mut vals: Vec<u64> = self
            .entries
            .keys()
            .filter(|(r, _)| r == register)
            .map(|(_, v)| *v)
            .collect();
        vals.sort_unstable();
        vals.dedup();
        vals
    }
}

// ── Memory index ──────────────────────────────────────────────────────────────

/// Sorted index: `address → Vec<Position>` for memory accesses.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MemoryAccessIndex {
    /// address → sorted write positions
    writes: HashMap<u64, Vec<Position>>,
    /// address → sorted read positions
    reads: HashMap<u64, Vec<Position>>,
}

impl MemoryAccessIndex {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_write(&mut self, address: u64, pos: Position) {
        self.writes.entry(address).or_default().push(pos);
    }

    pub fn insert_read(&mut self, address: u64, pos: Position) {
        self.reads.entry(address).or_default().push(pos);
    }

    pub fn finalize(&mut self) {
        for v in self.writes.values_mut() { v.sort(); }
        for v in self.reads.values_mut() { v.sort(); }
    }

    #[must_use] 
    pub fn writes_to(&self, address: u64) -> &[Position] {
        self.writes.get(&address).map_or(&[][..], |v| v.as_slice())
    }

    #[must_use] 
    pub fn reads_from(&self, address: u64) -> &[Position] {
        self.reads.get(&address).map_or(&[][..], |v| v.as_slice())
    }

    /// First write to `address` at or after `from`.
    #[must_use] 
    pub fn first_write_after(&self, address: u64, from: Position) -> Option<Position> {
        let all = self.writes_to(address);
        let idx = all.partition_point(|p| p < &from);
        all.get(idx).copied()
    }

    /// All writes in an address range `[addr_lo, addr_hi]` within a position range.
    #[must_use] 
    pub fn writes_in_region(
        &self,
        addr_lo: u64,
        addr_hi: u64,
        pos_range: PositionRange,
    ) -> Vec<(u64, Position)> {
        let mut results = Vec::new();
        for (&addr, positions) in &self.writes {
            if addr < addr_lo || addr > addr_hi {
                continue;
            }
            let lo = positions.partition_point(|p| p < &pos_range.start);
            let hi = positions.partition_point(|p| p <= &pos_range.end);
            for &pos in &positions[lo..hi] {
                results.push((addr, pos));
            }
        }
        results.sort_by_key(|(_, p)| *p);
        results
    }
}

// ── Call index ────────────────────────────────────────────────────────────────

/// Sorted index: `call_name → Vec<Position>`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CallIndex {
    by_name: HashMap<String, Vec<Position>>,
    by_address: HashMap<u64, Vec<Position>>,
}

impl CallIndex {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, name: impl Into<String>, address: u64, pos: Position) {
        let name = name.into();
        self.by_name.entry(name).or_default().push(pos);
        self.by_address.entry(address).or_default().push(pos);
    }

    pub fn finalize(&mut self) {
        for v in self.by_name.values_mut() { v.sort(); }
        for v in self.by_address.values_mut() { v.sort(); }
    }

    #[must_use] 
    pub fn calls_to(&self, name: &str) -> &[Position] {
        self.by_name.get(name).map_or(&[][..], |v| v.as_slice())
    }

    #[must_use] 
    pub fn calls_to_address(&self, address: u64) -> &[Position] {
        self.by_address.get(&address).map_or(&[][..], |v| v.as_slice())
    }

    #[must_use] 
    pub fn first_call(&self, name: &str) -> Option<Position> {
        self.calls_to(name).first().copied()
    }

    #[must_use] 
    pub fn calls_in_range(&self, name: &str, range: PositionRange) -> Vec<Position> {
        let all = self.calls_to(name);
        let lo = all.partition_point(|p| p < &range.start);
        let hi = all.partition_point(|p| p <= &range.end);
        all[lo..hi].to_vec()
    }

    #[must_use] 
    pub fn all_call_names(&self) -> Vec<&str> {
        self.by_name.keys().map(std::string::String::as_str).collect()
    }
}

// ── Thread switch index ───────────────────────────────────────────────────────

/// Index of thread switch events.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ThreadSwitchIndex {
    switches: Vec<(Position, u32, u32)>, // (position, from_tid, to_tid)
}

impl ThreadSwitchIndex {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, pos: Position, from_tid: u32, to_tid: u32) {
        self.switches.push((pos, from_tid, to_tid));
    }

    pub fn finalize(&mut self) {
        self.switches.sort_by_key(|(p, _, _)| *p);
    }

    /// Active thread at position `pos` (last thread switch before `pos`).
    #[must_use] 
    pub fn active_thread_at(&self, pos: Position) -> Option<u32> {
        let idx = self.switches.partition_point(|(p, _, _)| p <= &pos);
        if idx == 0 { None } else { Some(self.switches[idx - 1].2) }
    }

    /// All positions where we switched to thread `tid`.
    #[must_use] 
    pub fn switches_to(&self, tid: u32) -> Vec<Position> {
        self.switches
            .iter()
            .filter(|(_, _, to)| *to == tid)
            .map(|(p, _, _)| *p)
            .collect()
    }
}

// ── Full TTD index ────────────────────────────────────────────────────────────

/// Combined index for fast O(log n) queries across all event kinds.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TtdIndex {
    pub registers: RegisterIndex,
    pub memory: MemoryAccessIndex,
    pub calls: CallIndex,
    pub threads: ThreadSwitchIndex,
    pub total_events: usize,
}

impl TtdIndex {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest a single [`IndexEvent`].
    pub fn ingest(&mut self, event: IndexEvent) {
        self.total_events += 1;
        let pos = event.position;
        match event.kind {
            IndexEventKind::RegisterWrite { register, value } => {
                self.registers.insert(register, value, pos);
            }
            IndexEventKind::MemoryWrite { address, .. } => {
                self.memory.insert_write(address, pos);
            }
            IndexEventKind::MemoryRead { address, .. } => {
                self.memory.insert_read(address, pos);
            }
            IndexEventKind::Call { target_name, target_address } => {
                self.calls.insert(target_name, target_address, pos);
            }
            IndexEventKind::ThreadSwitch { from_tid, to_tid } => {
                self.threads.insert(pos, from_tid, to_tid);
            }
            IndexEventKind::Exception { .. } => {}
        }
    }

    /// Ingest a batch of events and finalize all indexes.
    #[must_use] 
    pub fn build_from_events(events: Vec<IndexEvent>) -> Self {
        let mut idx = Self::new();
        for ev in events {
            idx.ingest(ev);
        }
        idx.finalize();
        idx
    }

    /// Finalize all sub-indexes (sort vectors). Must be called after bulk ingest.
    pub fn finalize(&mut self) {
        self.registers.finalize();
        self.memory.finalize();
        self.calls.finalize();
        self.threads.finalize();
    }

    // ── High-level query helpers ──────────────────────────────────────────

    /// "When did rax equal 0x1234?" — returns sorted positions.
    #[must_use] 
    pub fn when_register_equals(&self, reg: &str, value: u64) -> &[Position] {
        self.registers.query_exact(reg, value)
    }

    /// "When was address 0x7fff... written?" — returns sorted positions.
    #[must_use] 
    pub fn when_address_written(&self, address: u64) -> &[Position] {
        self.memory.writes_to(address)
    }

    /// "All calls to `CreateFile`" — returns sorted positions.
    #[must_use] 
    pub fn all_calls_to(&self, name: &str) -> &[Position] {
        self.calls.calls_to(name)
    }

    /// Index statistics.
    #[must_use] 
    pub fn stats(&self) -> IndexStats {
        IndexStats {
            total_events: self.total_events,
            unique_register_value_pairs: self.registers.entries.len(),
            unique_addresses_written: self.memory.writes.len(),
            unique_addresses_read: self.memory.reads.len(),
            unique_call_targets: self.calls.by_name.len(),
            thread_switches: self.threads.switches.len(),
        }
    }
}

/// Summary statistics for a built index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexStats {
    pub total_events: usize,
    pub unique_register_value_pairs: usize,
    pub unique_addresses_written: usize,
    pub unique_addresses_read: usize,
    pub unique_call_targets: usize,
    pub thread_switches: usize,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn p(seq: u64, step: u32) -> Position { Position::new(seq, step) }

    fn sample_events() -> Vec<IndexEvent> {
        vec![
            IndexEvent { position: p(0, 0), kind: IndexEventKind::RegisterWrite { register: "rax".into(), value: 0x1234 } },
            IndexEvent { position: p(1, 0), kind: IndexEventKind::RegisterWrite { register: "rax".into(), value: 0x5678 } },
            IndexEvent { position: p(2, 0), kind: IndexEventKind::RegisterWrite { register: "rax".into(), value: 0x1234 } },
            IndexEvent { position: p(3, 0), kind: IndexEventKind::MemoryWrite { address: 0x7fff_0000, value: 0xAA, size: 1 } },
            IndexEvent { position: p(4, 0), kind: IndexEventKind::Call { target_name: "CreateFile".into(), target_address: 0x7c80_0000 } },
            IndexEvent { position: p(5, 0), kind: IndexEventKind::Call { target_name: "CreateFile".into(), target_address: 0x7c80_0000 } },
            IndexEvent { position: p(6, 0), kind: IndexEventKind::ThreadSwitch { from_tid: 1, to_tid: 2 } },
        ]
    }

    #[test]
    fn register_index_exact() {
        let idx = TtdIndex::build_from_events(sample_events());
        let positions = idx.when_register_equals("rax", 0x1234);
        assert_eq!(positions, &[p(0, 0), p(2, 0)]);
    }

    #[test]
    fn register_index_range_query() {
        let idx = TtdIndex::build_from_events(sample_events());
        let range = PositionRange::new(p(1, 0), p(3, 0));
        let positions = idx.registers.query_in_range("rax", 0x1234, range);
        assert_eq!(positions, vec![p(2, 0)]);
    }

    #[test]
    fn memory_write_index() {
        let idx = TtdIndex::build_from_events(sample_events());
        let pos = idx.when_address_written(0x7fff_0000);
        assert_eq!(pos, &[p(3, 0)]);
    }

    #[test]
    fn call_index() {
        let idx = TtdIndex::build_from_events(sample_events());
        let calls = idx.all_calls_to("CreateFile");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], p(4, 0));
        assert_eq!(calls[1], p(5, 0));
    }

    #[test]
    fn thread_switch_active() {
        let idx = TtdIndex::build_from_events(sample_events());
        let active = idx.threads.active_thread_at(p(10, 0));
        assert_eq!(active, Some(2));
    }

    #[test]
    fn first_after() {
        let idx = TtdIndex::build_from_events(sample_events());
        let first = idx.registers.first_after("rax", 0x1234, p(1, 0));
        assert_eq!(first, Some(p(2, 0)));
    }

    #[test]
    fn stats_counts() {
        let idx = TtdIndex::build_from_events(sample_events());
        let stats = idx.stats();
        assert_eq!(stats.total_events, 7);
        assert_eq!(stats.unique_call_targets, 1);
        assert_eq!(stats.thread_switches, 1);
    }

    #[test]
    fn memory_region_query() {
        let mut idx = TtdIndex::new();
        for addr in [0x7fff_0000_u64, 0x7fff_0004, 0x7fff_0008, 0x8000_0000] {
            idx.ingest(IndexEvent {
                position: p(addr, 0),
                kind: IndexEventKind::MemoryWrite { address: addr, value: 0, size: 4 },
            });
        }
        idx.finalize();
        let region = idx.memory.writes_in_region(0x7fff_0000, 0x7fff_ffff, PositionRange::full());
        assert_eq!(region.len(), 3, "should find 3 writes in 0x7fff region");
    }
}
