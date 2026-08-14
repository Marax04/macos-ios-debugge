//! `rustre-trace` — multi-dimensional trace index.
//!
//! Provides fast lookups over large execution traces by building several
//! specialised indices simultaneously.
//!
//! # Structs
//! - [`PcIndex`]       — PC address → sorted list of trace positions
//! - [`FunctionIndex`] — function entry → entry positions (CALL events)
//! - [`MemIndex`]      — memory address → access positions + kinds
//! - [`ThreadIndex`]   — thread id → sorted trace positions
//! - [`ApiIndex`]      — syscall / API number → trace positions
//! - [`TraceIndexer`]  — builds and queries all five indices together

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{TraceEvent, TraceRecord, TraceSession};

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from the trace indexer.
#[derive(Debug, Error)]
pub enum IndexError {
    #[error("index not built")]
    NotBuilt,
    #[error("sequence number {0} out of range")]
    SeqOutOfRange(u64),
    #[error("address {0:#x} not found in index")]
    AddressNotFound(u64),
    #[error("function address {0:#x} has no entries")]
    FunctionNotFound(u64),
    #[error("thread {0} not found")]
    ThreadNotFound(u32),
    #[error("syscall {0} not found")]
    SyscallNotFound(u64),
}

// ─────────────────────────────────────────────────────────────────────────────
// AccessKind
// ─────────────────────────────────────────────────────────────────────────────

/// Whether a memory access is a read or write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum MemAccessKind {
    Read,
    Write,
}

impl std::fmt::Display for MemAccessKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read => write!(f, "read"),
            Self::Write => write!(f, "write"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IndexEntry helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A single indexed trace position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TracePos {
    /// Sequence number of the record.
    pub seq: u64,
    /// Thread that produced this record.
    pub tid: u32,
}

impl TracePos {
    #[must_use]
    pub const fn new(seq: u64, tid: u32) -> Self {
        Self { seq, tid }
    }
}

/// Memory access indexed entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemAccessEntry {
    pub seq: u64,
    pub tid: u32,
    pub kind: MemAccessKind,
    pub value: u64,
    pub size: u8,
}

// ─────────────────────────────────────────────────────────────────────────────
// PcIndex
// ─────────────────────────────────────────────────────────────────────────────

/// Maps each program-counter address to the sorted list of trace positions
/// where an `Instruction` event at that address was recorded.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PcIndex {
    /// pc → sorted Vec<TracePos>
    index: BTreeMap<u64, Vec<TracePos>>,
    /// Total entries indexed.
    pub total_entries: u64,
}

impl PcIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a PC position.
    pub fn insert(&mut self, pc: u64, seq: u64, tid: u32) {
        self.index
            .entry(pc)
            .or_default()
            .push(TracePos::new(seq, tid));
        self.total_entries += 1;
    }

    /// All positions where `pc` was executed, in trace order.
    #[must_use]
    pub fn positions(&self, pc: u64) -> &[TracePos] {
        self.index.get(&pc).map_or(&[][..], Vec::as_slice)
    }

    /// How many times `pc` was executed.
    #[must_use]
    pub fn hit_count(&self, pc: u64) -> usize {
        self.positions(pc).len()
    }

    /// All indexed PCs.
    #[must_use]
    pub fn all_pcs(&self) -> Vec<u64> {
        self.index.keys().copied().collect()
    }

    /// Top-N most-executed PCs.
    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<(u64, usize)> {
        let mut v: Vec<(u64, usize)> = self
            .index
            .iter()
            .map(|(&pc, positions)| (pc, positions.len()))
            .collect();
        v.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }

    /// PCs within address range `[lo, hi)`.
    #[must_use]
    pub fn pcs_in_range(&self, lo: u64, hi: u64) -> Vec<u64> {
        self.index.range(lo..hi).map(|(&pc, _)| pc).collect()
    }

    /// First execution of `pc` (lowest seq), or `None`.
    #[must_use]
    pub fn first_hit(&self, pc: u64) -> Option<TracePos> {
        self.positions(pc).first().copied()
    }

    /// Last execution of `pc` (highest seq), or `None`.
    #[must_use]
    pub fn last_hit(&self, pc: u64) -> Option<TracePos> {
        self.positions(pc).last().copied()
    }

    /// Number of distinct PCs.
    #[must_use]
    pub fn unique_pc_count(&self) -> usize {
        self.index.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionIndex
// ─────────────────────────────────────────────────────────────────────────────

/// Maps each function entry address to the sorted list of trace positions
/// at which the function was called (CALL events targeting that address).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionIndex {
    /// `fn_addr` → sorted Vec<(seq, `call_site`, tid)>
    index: HashMap<u64, Vec<(u64, u64, u32)>>,
    pub total_calls: u64,
}

impl FunctionIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a function call event.
    pub fn insert(&mut self, fn_addr: u64, seq: u64, call_site: u64, tid: u32) {
        self.index
            .entry(fn_addr)
            .or_default()
            .push((seq, call_site, tid));
        self.total_calls += 1;
    }

    /// All `(seq, call_site, tid)` entries for `fn_addr`.
    #[must_use]
    pub fn calls_of(&self, fn_addr: u64) -> &[(u64, u64, u32)] {
        self.index.get(&fn_addr).map_or(&[][..], Vec::as_slice)
    }

    /// Number of times `fn_addr` was called.
    #[must_use]
    pub fn call_count(&self, fn_addr: u64) -> usize {
        self.calls_of(fn_addr).len()
    }

    /// All tracked function addresses.
    #[must_use]
    pub fn all_functions(&self) -> Vec<u64> {
        self.index.keys().copied().collect()
    }

    /// Top-N most-called functions.
    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<(u64, usize)> {
        let mut v: Vec<(u64, usize)> = self
            .index
            .iter()
            .map(|(&fn_addr, calls)| (fn_addr, calls.len()))
            .collect();
        v.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }

    /// First entry position for `fn_addr`.
    #[must_use]
    pub fn first_call(&self, fn_addr: u64) -> Option<u64> {
        self.calls_of(fn_addr).first().map(|(seq, _, _)| *seq)
    }

    /// Unique number of functions tracked.
    #[must_use]
    pub fn unique_function_count(&self) -> usize {
        self.index.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemIndex
// ─────────────────────────────────────────────────────────────────────────────

/// Maps each memory address to all accesses (reads and writes) in trace order.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemIndex {
    /// addr → Vec<MemAccessEntry>
    index: BTreeMap<u64, Vec<MemAccessEntry>>,
    pub total_reads: u64,
    pub total_writes: u64,
}

impl MemIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a memory access.
    pub fn insert(
        &mut self,
        addr: u64,
        seq: u64,
        tid: u32,
        kind: MemAccessKind,
        value: u64,
        size: u8,
    ) {
        self.index.entry(addr).or_default().push(MemAccessEntry {
            seq,
            tid,
            kind,
            value,
            size,
        });
        match kind {
            MemAccessKind::Read => self.total_reads += 1,
            MemAccessKind::Write => self.total_writes += 1,
        }
    }

    /// All accesses to `addr`.
    #[must_use]
    pub fn accesses(&self, addr: u64) -> &[MemAccessEntry] {
        self.index.get(&addr).map_or(&[][..], Vec::as_slice)
    }

    /// All writes to `addr`.
    #[must_use]
    pub fn writes(&self, addr: u64) -> Vec<&MemAccessEntry> {
        self.accesses(addr)
            .iter()
            .filter(|e| e.kind == MemAccessKind::Write)
            .collect()
    }

    /// All reads from `addr`.
    #[must_use]
    pub fn reads(&self, addr: u64) -> Vec<&MemAccessEntry> {
        self.accesses(addr)
            .iter()
            .filter(|e| e.kind == MemAccessKind::Read)
            .collect()
    }

    /// The value stored at `addr` just before sequence `before_seq`.
    #[must_use]
    pub fn value_at(&self, addr: u64, before_seq: u64) -> Option<u64> {
        self.writes(addr)
            .into_iter()
            .rev()
            .find(|e| e.seq < before_seq)
            .map(|e| e.value)
    }

    /// All tracked addresses.
    #[must_use]
    pub fn all_addresses(&self) -> Vec<u64> {
        self.index.keys().copied().collect()
    }

    /// Addresses accessed within `[lo, hi)`.
    #[must_use]
    pub fn addresses_in_range(&self, lo: u64, hi: u64) -> Vec<u64> {
        self.index.range(lo..hi).map(|(&a, _)| a).collect()
    }

    /// Hottest addresses by total access count.
    #[must_use]
    pub fn hottest(&self, n: usize) -> Vec<(u64, usize)> {
        let mut v: Vec<(u64, usize)> = self
            .index
            .iter()
            .map(|(&a, entries)| (a, entries.len()))
            .collect();
        v.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }

    /// Unique number of memory addresses tracked.
    #[must_use]
    pub fn unique_address_count(&self) -> usize {
        self.index.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ThreadIndex
// ─────────────────────────────────────────────────────────────────────────────

/// Maps each thread ID to the sorted list of trace positions it produced.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThreadIndex {
    index: HashMap<u32, Vec<TracePos>>,
    pub total_events: u64,
}

impl ThreadIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, tid: u32, seq: u64) {
        self.index
            .entry(tid)
            .or_default()
            .push(TracePos::new(seq, tid));
        self.total_events += 1;
    }

    #[must_use]
    pub fn positions(&self, tid: u32) -> &[TracePos] {
        self.index.get(&tid).map_or(&[][..], Vec::as_slice)
    }

    #[must_use]
    pub fn event_count(&self, tid: u32) -> usize {
        self.positions(tid).len()
    }

    #[must_use]
    pub fn all_threads(&self) -> Vec<u32> {
        self.index.keys().copied().collect()
    }

    #[must_use]
    pub fn unique_thread_count(&self) -> usize {
        self.index.len()
    }

    /// The most active thread (by event count).
    #[must_use]
    pub fn most_active_thread(&self) -> Option<u32> {
        self.index
            .iter()
            .max_by_key(|(_, v)| v.len())
            .map(|(&tid, _)| tid)
    }

    /// Thread interleaving events in a mixed sequence range `[from_seq, to_seq)`.
    #[must_use]
    pub fn events_in_range(&self, tid: u32, from_seq: u64, to_seq: u64) -> Vec<TracePos> {
        self.positions(tid)
            .iter()
            .filter(|p| p.seq >= from_seq && p.seq < to_seq)
            .copied()
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ApiIndex
// ─────────────────────────────────────────────────────────────────────────────

/// Maps each syscall/API number to the sorted list of trace positions
/// where it was called.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApiIndex {
    index: HashMap<u64, Vec<(TracePos, Vec<u64>)>>,
    pub total_calls: u64,
}

impl ApiIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, number: u64, seq: u64, tid: u32, args: Vec<u64>) {
        self.index
            .entry(number)
            .or_default()
            .push((TracePos::new(seq, tid), args));
        self.total_calls += 1;
    }

    #[must_use]
    pub fn calls(&self, number: u64) -> &[(TracePos, Vec<u64>)] {
        self.index.get(&number).map_or(&[][..], Vec::as_slice)
    }

    #[must_use]
    pub fn call_count(&self, number: u64) -> usize {
        self.calls(number).len()
    }

    #[must_use]
    pub fn all_syscalls(&self) -> Vec<u64> {
        self.index.keys().copied().collect()
    }

    #[must_use]
    pub fn unique_syscall_count(&self) -> usize {
        self.index.len()
    }

    /// Top-N most-called syscalls.
    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<(u64, usize)> {
        let mut v: Vec<(u64, usize)> = self
            .index
            .iter()
            .map(|(&num, calls)| (num, calls.len()))
            .collect();
        v.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }

    /// First call of `number` in the trace.
    #[must_use]
    pub fn first_call(&self, number: u64) -> Option<TracePos> {
        self.calls(number).first().map(|(pos, _)| *pos)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IndexStats
// ─────────────────────────────────────────────────────────────────────────────

/// Summary statistics of a built `TraceIndexer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexStats {
    pub total_records: u64,
    pub unique_pcs: usize,
    pub unique_functions: usize,
    pub unique_mem_addresses: usize,
    pub unique_threads: usize,
    pub unique_syscalls: usize,
    pub total_mem_reads: u64,
    pub total_mem_writes: u64,
    pub total_api_calls: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// TraceIndexer
// ─────────────────────────────────────────────────────────────────────────────

/// Builds and queries all five indices simultaneously from a `TraceSession`.
pub struct TraceIndexer {
    pub pc_index: PcIndex,
    pub function_index: FunctionIndex,
    pub mem_index: MemIndex,
    pub thread_index: ThreadIndex,
    pub api_index: ApiIndex,
    pub total_records: u64,
    pub built: bool,
}

impl TraceIndexer {
    /// Create an empty indexer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pc_index: PcIndex::new(),
            function_index: FunctionIndex::new(),
            mem_index: MemIndex::new(),
            thread_index: ThreadIndex::new(),
            api_index: ApiIndex::new(),
            total_records: 0,
            built: false,
        }
    }

    /// Build all indices from a `TraceSession`.
    #[must_use]
    pub fn build(session: &TraceSession) -> Self {
        let mut idx = Self::new();
        for rec in &session.records {
            idx.index_record(rec);
        }
        idx.built = true;
        idx
    }

    /// Index a single `TraceRecord`.
    pub fn index_record(&mut self, rec: &TraceRecord) {
        self.total_records += 1;
        self.thread_index.insert(rec.thread_id, rec.seq);

        match &rec.event {
            TraceEvent::Instruction { addr, .. } => {
                self.pc_index.insert(*addr, rec.seq, rec.thread_id);
            }
            TraceEvent::Call { from, to } => {
                self.function_index
                    .insert(*to, rec.seq, *from, rec.thread_id);
                self.pc_index.insert(*from, rec.seq, rec.thread_id);
            }
            TraceEvent::MemRead { addr, size, value } => {
                self.mem_index.insert(
                    *addr,
                    rec.seq,
                    rec.thread_id,
                    MemAccessKind::Read,
                    *value,
                    *size,
                );
            }
            TraceEvent::MemWrite { addr, size, value } => {
                self.mem_index.insert(
                    *addr,
                    rec.seq,
                    rec.thread_id,
                    MemAccessKind::Write,
                    *value,
                    *size,
                );
            }
            TraceEvent::Syscall { number, args } => {
                self.api_index
                    .insert(*number, rec.seq, rec.thread_id, args.clone());
            }
            _ => {}
        }
    }

    /// Flush a whole session into this indexer (append).
    pub fn index_session(&mut self, session: &TraceSession) {
        for rec in &session.records {
            self.index_record(rec);
        }
        self.built = true;
    }

    /// Generate summary stats.
    #[must_use]
    pub fn stats(&self) -> IndexStats {
        IndexStats {
            total_records: self.total_records,
            unique_pcs: self.pc_index.unique_pc_count(),
            unique_functions: self.function_index.unique_function_count(),
            unique_mem_addresses: self.mem_index.unique_address_count(),
            unique_threads: self.thread_index.unique_thread_count(),
            unique_syscalls: self.api_index.unique_syscall_count(),
            total_mem_reads: self.mem_index.total_reads,
            total_mem_writes: self.mem_index.total_writes,
            total_api_calls: self.api_index.total_calls,
        }
    }

    // ── PC queries ────────────────────────────────────────────────────────────

    /// Number of times `pc` was executed.
    #[must_use]
    pub fn pc_hit_count(&self, pc: u64) -> usize {
        self.pc_index.hit_count(pc)
    }

    /// Top-N hottest PCs.
    #[must_use]
    pub fn top_pcs(&self, n: usize) -> Vec<(u64, usize)> {
        self.pc_index.top_n(n)
    }

    // ── Function queries ──────────────────────────────────────────────────────

    /// Number of times `fn_addr` was called.
    #[must_use]
    pub fn function_call_count(&self, fn_addr: u64) -> usize {
        self.function_index.call_count(fn_addr)
    }

    /// Top-N most-called functions.
    #[must_use]
    pub fn top_functions(&self, n: usize) -> Vec<(u64, usize)> {
        self.function_index.top_n(n)
    }

    // ── Memory queries ────────────────────────────────────────────────────────

    /// All writes to `addr`.
    #[must_use]
    pub fn writes_to(&self, addr: u64) -> Vec<&MemAccessEntry> {
        self.mem_index.writes(addr)
    }

    /// All reads from `addr`.
    #[must_use]
    pub fn reads_from(&self, addr: u64) -> Vec<&MemAccessEntry> {
        self.mem_index.reads(addr)
    }

    /// Value at `addr` just before `seq`.
    #[must_use]
    pub fn value_at(&self, addr: u64, before_seq: u64) -> Option<u64> {
        self.mem_index.value_at(addr, before_seq)
    }

    // ── Thread queries ────────────────────────────────────────────────────────

    /// Number of events produced by `tid`.
    #[must_use]
    pub fn thread_event_count(&self, tid: u32) -> usize {
        self.thread_index.event_count(tid)
    }

    // ── API / syscall queries ──────────────────────────────────────────────────

    /// Number of times `syscall_num` was called.
    #[must_use]
    pub fn syscall_count(&self, syscall_num: u64) -> usize {
        self.api_index.call_count(syscall_num)
    }

    /// Reset all indices.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

impl Default for TraceIndexer {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TraceSession;

    fn make_session() -> TraceSession {
        let mut s = TraceSession::new("test", "x86_64");
        s.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 5,
            },
            1,
            100,
        );
        s.push(
            TraceEvent::Instruction {
                addr: 0x1005,
                size: 3,
            },
            1,
            110,
        );
        s.push(
            TraceEvent::Instruction {
                addr: 0x1000,
                size: 5,
            },
            1,
            120,
        ); // 0x1000 again
        s.push(
            TraceEvent::Call {
                from: 0x1008,
                to: 0x2000,
            },
            1,
            130,
        );
        s.push(
            TraceEvent::MemWrite {
                addr: 0x3000,
                size: 8,
                value: 0xDEAD,
            },
            1,
            140,
        );
        s.push(
            TraceEvent::MemRead {
                addr: 0x3000,
                size: 8,
                value: 0xDEAD,
            },
            1,
            150,
        );
        s.push(
            TraceEvent::Syscall {
                number: 1,
                args: vec![0, 1, 2],
            },
            1,
            160,
        );
        s.push(
            TraceEvent::Instruction {
                addr: 0x4000,
                size: 2,
            },
            2,
            170,
        ); // thread 2
        s
    }

    // ── PcIndex ───────────────────────────────────────────────────────────────

    #[test]
    fn pc_index_insert_and_hit_count() {
        let mut idx = PcIndex::new();
        idx.insert(0x1000, 0, 1);
        idx.insert(0x1000, 1, 1);
        idx.insert(0x2000, 2, 1);
        assert_eq!(idx.hit_count(0x1000), 2);
        assert_eq!(idx.hit_count(0x2000), 1);
        assert_eq!(idx.hit_count(0x9999), 0);
    }

    #[test]
    fn pc_index_all_pcs() {
        let mut idx = PcIndex::new();
        idx.insert(0x1000, 0, 1);
        idx.insert(0x2000, 1, 1);
        let pcs = idx.all_pcs();
        assert!(pcs.contains(&0x1000));
        assert!(pcs.contains(&0x2000));
    }

    #[test]
    fn pc_index_top_n() {
        let mut idx = PcIndex::new();
        for i in 0..5 {
            idx.insert(0x1000, i, 1);
        }
        idx.insert(0x2000, 5, 1);
        let top = idx.top_n(1);
        assert_eq!(top[0].0, 0x1000);
        assert_eq!(top[0].1, 5);
    }

    #[test]
    fn pc_index_first_and_last_hit() {
        let mut idx = PcIndex::new();
        idx.insert(0x1000, 10, 1);
        idx.insert(0x1000, 20, 1);
        assert_eq!(idx.first_hit(0x1000).unwrap().seq, 10);
        assert_eq!(idx.last_hit(0x1000).unwrap().seq, 20);
    }

    #[test]
    fn pc_index_pcs_in_range() {
        let mut idx = PcIndex::new();
        idx.insert(0x1000, 0, 1);
        idx.insert(0x2000, 1, 1);
        idx.insert(0x3000, 2, 1);
        let pcs = idx.pcs_in_range(0x1000, 0x3000);
        assert!(pcs.contains(&0x1000));
        assert!(pcs.contains(&0x2000));
        assert!(!pcs.contains(&0x3000));
    }

    // ── FunctionIndex ─────────────────────────────────────────────────────────

    #[test]
    fn function_index_insert_and_count() {
        let mut idx = FunctionIndex::new();
        idx.insert(0x2000, 5, 0x1008, 1);
        idx.insert(0x2000, 10, 0x1020, 1);
        assert_eq!(idx.call_count(0x2000), 2);
        assert_eq!(idx.total_calls, 2);
    }

    #[test]
    fn function_index_all_functions() {
        let mut idx = FunctionIndex::new();
        idx.insert(0x2000, 5, 0x1000, 1);
        idx.insert(0x3000, 6, 0x1010, 1);
        let fns = idx.all_functions();
        assert!(fns.contains(&0x2000));
        assert!(fns.contains(&0x3000));
    }

    #[test]
    fn function_index_top_n() {
        let mut idx = FunctionIndex::new();
        for i in 0..3 {
            idx.insert(0x2000, i as u64, 0x1000, 1);
        }
        idx.insert(0x3000, 10, 0x1000, 1);
        let top = idx.top_n(1);
        assert_eq!(top[0].0, 0x2000);
        assert_eq!(top[0].1, 3);
    }

    #[test]
    fn function_index_first_call() {
        let mut idx = FunctionIndex::new();
        idx.insert(0x2000, 5, 0x1000, 1);
        idx.insert(0x2000, 10, 0x1000, 1);
        assert_eq!(idx.first_call(0x2000), Some(5));
    }

    // ── MemIndex ──────────────────────────────────────────────────────────────

    #[test]
    fn mem_index_reads_and_writes() {
        let mut idx = MemIndex::new();
        idx.insert(0x3000, 5, 1, MemAccessKind::Write, 0xDEAD, 8);
        idx.insert(0x3000, 6, 1, MemAccessKind::Read, 0xDEAD, 8);
        assert_eq!(idx.writes(0x3000).len(), 1);
        assert_eq!(idx.reads(0x3000).len(), 1);
        assert_eq!(idx.total_reads, 1);
        assert_eq!(idx.total_writes, 1);
    }

    #[test]
    fn mem_index_value_at() {
        let mut idx = MemIndex::new();
        idx.insert(0x3000, 5, 1, MemAccessKind::Write, 0xAAAA, 8);
        idx.insert(0x3000, 10, 1, MemAccessKind::Write, 0xBBBB, 8);
        assert_eq!(idx.value_at(0x3000, 7), Some(0xAAAA));
        assert_eq!(idx.value_at(0x3000, 11), Some(0xBBBB));
    }

    #[test]
    fn mem_index_hottest() {
        let mut idx = MemIndex::new();
        for i in 0..5 {
            idx.insert(0x1000, i, 1, MemAccessKind::Read, 0, 1);
        }
        idx.insert(0x2000, 10, 1, MemAccessKind::Read, 0, 1);
        let hot = idx.hottest(1);
        assert_eq!(hot[0].0, 0x1000);
        assert_eq!(hot[0].1, 5);
    }

    #[test]
    fn mem_index_addresses_in_range() {
        let mut idx = MemIndex::new();
        idx.insert(0x1000, 0, 1, MemAccessKind::Read, 0, 1);
        idx.insert(0x2000, 1, 1, MemAccessKind::Read, 0, 1);
        idx.insert(0x3000, 2, 1, MemAccessKind::Read, 0, 1);
        let addrs = idx.addresses_in_range(0x1000, 0x3000);
        assert!(addrs.contains(&0x1000));
        assert!(!addrs.contains(&0x3000));
    }

    // ── ThreadIndex ───────────────────────────────────────────────────────────

    #[test]
    fn thread_index_event_count() {
        let mut idx = ThreadIndex::new();
        idx.insert(1, 0);
        idx.insert(1, 1);
        idx.insert(2, 2);
        assert_eq!(idx.event_count(1), 2);
        assert_eq!(idx.event_count(2), 1);
    }

    #[test]
    fn thread_index_most_active() {
        let mut idx = ThreadIndex::new();
        idx.insert(1, 0);
        idx.insert(1, 1);
        idx.insert(1, 2);
        idx.insert(2, 3);
        assert_eq!(idx.most_active_thread(), Some(1));
    }

    #[test]
    fn thread_index_events_in_range() {
        let mut idx = ThreadIndex::new();
        for i in 0u64..10 {
            idx.insert(1, i);
        }
        let r = idx.events_in_range(1, 3, 7);
        assert_eq!(r.len(), 4); // seqs 3,4,5,6
    }

    // ── ApiIndex ──────────────────────────────────────────────────────────────

    #[test]
    fn api_index_insert_and_count() {
        let mut idx = ApiIndex::new();
        idx.insert(1, 5, 1, vec![0, 1, 2]);
        idx.insert(1, 10, 1, vec![3]);
        assert_eq!(idx.call_count(1), 2);
        assert_eq!(idx.total_calls, 2);
    }

    #[test]
    fn api_index_top_n() {
        let mut idx = ApiIndex::new();
        for i in 0..4 {
            idx.insert(1, i, 1, vec![]);
        }
        idx.insert(2, 10, 1, vec![]);
        let top = idx.top_n(1);
        assert_eq!(top[0].0, 1);
        assert_eq!(top[0].1, 4);
    }

    #[test]
    fn api_index_first_call() {
        let mut idx = ApiIndex::new();
        idx.insert(3, 100, 1, vec![]);
        idx.insert(3, 200, 1, vec![]);
        assert_eq!(idx.first_call(3).unwrap().seq, 100);
    }

    // ── TraceIndexer ──────────────────────────────────────────────────────────

    #[test]
    fn indexer_build() {
        let session = make_session();
        let idx = TraceIndexer::build(&session);
        assert!(idx.built);
        assert!(idx.total_records > 0);
    }

    #[test]
    fn indexer_pc_hit_count() {
        let session = make_session();
        let idx = TraceIndexer::build(&session);
        // 0x1000 appears twice
        assert_eq!(idx.pc_hit_count(0x1000), 2);
    }

    #[test]
    fn indexer_function_call_count() {
        let session = make_session();
        let idx = TraceIndexer::build(&session);
        assert_eq!(idx.function_call_count(0x2000), 1);
    }

    #[test]
    fn indexer_mem_writes_and_reads() {
        let session = make_session();
        let idx = TraceIndexer::build(&session);
        assert_eq!(idx.writes_to(0x3000).len(), 1);
        assert_eq!(idx.reads_from(0x3000).len(), 1);
    }

    #[test]
    fn indexer_syscall_count() {
        let session = make_session();
        let idx = TraceIndexer::build(&session);
        assert_eq!(idx.syscall_count(1), 1);
    }

    #[test]
    fn indexer_thread_event_count() {
        let session = make_session();
        let idx = TraceIndexer::build(&session);
        assert!(idx.thread_event_count(1) > 0);
        assert!(idx.thread_event_count(2) > 0);
    }

    #[test]
    fn indexer_stats() {
        let session = make_session();
        let idx = TraceIndexer::build(&session);
        let s = idx.stats();
        assert!(s.unique_pcs >= 3);
        assert_eq!(s.unique_syscalls, 1);
        assert_eq!(s.unique_threads, 2);
    }

    #[test]
    fn indexer_value_at() {
        let session = make_session();
        let idx = TraceIndexer::build(&session);
        // The write to 0x3000 with value 0xDEAD is at seq=4 (5th record)
        // Reading value before a later seq should return 0xDEAD
        let val = idx.value_at(0x3000, 1000);
        assert_eq!(val, Some(0xDEAD));
    }

    #[test]
    fn indexer_reset() {
        let mut idx = TraceIndexer::build(&make_session());
        idx.reset();
        assert_eq!(idx.total_records, 0);
        assert!(!idx.built);
    }

    #[test]
    fn indexer_top_pcs() {
        let session = make_session();
        let idx = TraceIndexer::build(&session);
        let top = idx.top_pcs(3);
        assert!(!top.is_empty());
        // results sorted by count descending
        if top.len() >= 2 {
            assert!(top[0].1 >= top[1].1);
        }
    }

    #[test]
    fn indexer_index_session_append() {
        let s1 = make_session();
        let s2 = make_session();
        let mut idx = TraceIndexer::new();
        idx.index_session(&s1);
        let count_after_s1 = idx.total_records;
        idx.index_session(&s2);
        assert!(idx.total_records > count_after_s1);
    }
}
