//! Trace index: fast multi-dimensional index over execution traces.
//!
//! `TraceIndex` builds secondary indexes over a `TraceSession`, enabling O(1)
//! lookup by address, thread, event type, and sequence range. `AddressIndex`
//! and `FunctionIndex` provide specialized views.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::{TraceEvent, TraceSession};

// ─── IndexEntry ───────────────────────────────────────────────────────────────

/// A compact reference into the session's record list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    /// Sequence number of the record.
    pub seq: u64,
    /// Index in the parent session's `records` slice.
    pub record_idx: usize,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
}

impl IndexEntry {
    #[must_use]
    pub const fn new(seq: u64, record_idx: usize, timestamp_ns: u64) -> Self {
        Self { seq, record_idx, timestamp_ns }
    }
}

// ─── AddressIndex ─────────────────────────────────────────────────────────────

/// Index from instruction address → sorted list of index entries.
#[derive(Debug, Clone, Default)]
pub struct AddressIndex {
    /// address → Vec<(seq, `record_idx`)>
    inner: HashMap<u64, Vec<IndexEntry>>,
    /// Total number of indexed entries.
    pub total: usize,
}

impl AddressIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert one entry.
    pub fn insert(&mut self, addr: u64, entry: IndexEntry) {
        self.inner.entry(addr).or_default().push(entry);
        self.total += 1;
    }

    /// Return all entries at `addr`.
    pub fn get(&self, addr: u64) -> &[IndexEntry] {
        self.inner.get(&addr).map_or(&[], Vec::as_slice)
    }

    /// Return all addresses in the index.
    #[must_use]
    pub fn all_addresses(&self) -> Vec<u64> {
        let mut addrs: Vec<u64> = self.inner.keys().copied().collect();
        addrs.sort_unstable();
        addrs
    }

    /// Return how many unique addresses are indexed.
    #[must_use]
    pub fn unique_address_count(&self) -> usize {
        self.inner.len()
    }

    /// Return how many times `addr` was executed.
    pub fn hit_count(&self, addr: u64) -> usize {
        self.inner.get(&addr).map_or(0, Vec::len)
    }

    /// Return the top-N hottest addresses by hit count.
    #[must_use]
    pub fn top_n_hot(&self, n: usize) -> Vec<(u64, usize)> {
        let mut pairs: Vec<(u64, usize)> = self
            .inner
            .iter()
            .map(|(&addr, entries)| (addr, entries.len()))
            .collect();
        if n < pairs.len() {
            pairs.select_nth_unstable_by(n, |a, b| b.1.cmp(&a.1));
            pairs.truncate(n);
        }
        pairs.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        pairs
    }

    /// Addresses within `[start, end)` that were executed, sorted.
    #[must_use]
    pub fn in_range(&self, start: u64, end: u64) -> Vec<u64> {
        let mut addrs: Vec<u64> = self
            .inner
            .keys()
            .copied()
            .filter(|&a| a >= start && a < end)
            .collect();
        addrs.sort_unstable();
        addrs
    }

    /// Build from a session (instruction events only).
    #[must_use]
    pub fn from_session(session: &TraceSession) -> Self {
        let mut idx = Self::new();
        for (i, rec) in session.records.iter().enumerate() {
            if let TraceEvent::Instruction { addr, .. } = rec.event {
                idx.insert(addr, IndexEntry::new(rec.seq, i, rec.timestamp_ns));
            }
        }
        idx
    }
}

// ─── FunctionIndex ────────────────────────────────────────────────────────────

/// Tracks function call/return pairs to identify per-function execution ranges.
#[derive(Debug, Clone, Default)]
pub struct FunctionIndex {
    /// `function_entry_addr` → list of (`call_seq`, `return_seq`) pairs.
    calls: HashMap<u64, Vec<CallSpan>>,
}

/// A single call–return span.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CallSpan {
    pub callee_addr: u64,
    pub call_seq: u64,
    pub return_seq: Option<u64>,
    pub thread_id: u32,
}

impl FunctionIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from a session by matching Call and Return events.
    #[must_use]
    pub fn from_session(session: &TraceSession) -> Self {
        let mut idx = Self::new();
        let mut stack: Vec<(u64, u64, u32)> = Vec::new(); // (callee, call_seq, tid)

        for rec in &session.records {
            match rec.event {
                TraceEvent::Call { to, .. } => {
                    stack.push((to, rec.seq, rec.thread_id));
                    idx.calls
                        .entry(to)
                        .or_default()
                        .push(CallSpan {
                            callee_addr: to,
                            call_seq: rec.seq,
                            return_seq: None,
                            thread_id: rec.thread_id,
                        });
                }
                TraceEvent::Return { .. } => {
                    if let Some((callee, call_seq, tid)) = stack.pop() {
                        if let Some(spans) = idx.calls.get_mut(&callee) {
                            for span in spans.iter_mut().rev() {
                                if span.call_seq == call_seq && span.thread_id == tid {
                                    span.return_seq = Some(rec.seq);
                                    break;
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        idx
    }

    /// Return all call spans for a function at `entry_addr`.
    pub fn spans_for(&self, entry_addr: u64) -> &[CallSpan] {
        self.calls.get(&entry_addr).map_or(&[], Vec::as_slice)
    }

    /// Number of times a function at `entry_addr` was called.
    pub fn call_count(&self, entry_addr: u64) -> usize {
        self.calls.get(&entry_addr).map_or(0, Vec::len)
    }

    /// Return all unique function entry addresses seen.
    #[must_use]
    pub fn all_functions(&self) -> Vec<u64> {
        let mut addrs: Vec<u64> = self.calls.keys().copied().collect();
        addrs.sort_unstable();
        addrs
    }

    /// Return the top-N most-called functions.
    #[must_use]
    pub fn top_called(&self, n: usize) -> Vec<(u64, usize)> {
        let mut pairs: Vec<(u64, usize)> = self
            .calls
            .iter()
            .map(|(&addr, spans)| (addr, spans.len()))
            .collect();
        if n < pairs.len() {
            pairs.select_nth_unstable_by(n, |a, b| b.1.cmp(&a.1));
            pairs.truncate(n);
        }
        pairs.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        pairs
    }

    /// All open (unreturned) spans.
    #[must_use]
    pub fn open_spans(&self) -> Vec<&CallSpan> {
        self.calls
            .values()
            .flat_map(|spans| spans.iter())
            .filter(|s| s.return_seq.is_none())
            .collect()
    }
}

// ─── TimeIndex ────────────────────────────────────────────────────────────────

/// Index by time: `BTreeMap`<`timestamp_ns` → seq> for range queries.
#[derive(Debug, Clone, Default)]
pub struct TimeIndex {
    inner: BTreeMap<u64, u64>,
}

impl TimeIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, timestamp_ns: u64, seq: u64) {
        self.inner.insert(timestamp_ns, seq);
    }

    /// Return all sequence numbers in the time range `[start_ns, end_ns]`.
    #[must_use]
    pub fn seqs_in_range(&self, start_ns: u64, end_ns: u64) -> Vec<u64> {
        self.inner
            .range(start_ns..=end_ns)
            .map(|(_, &seq)| seq)
            .collect()
    }

    /// The earliest timestamp in the index.
    #[must_use]
    pub fn min_time(&self) -> Option<u64> {
        self.inner.keys().next().copied()
    }

    /// The latest timestamp in the index.
    #[must_use]
    pub fn max_time(&self) -> Option<u64> {
        self.inner.keys().next_back().copied()
    }

    /// Duration covered by the index.
    #[must_use]
    pub fn duration_ns(&self) -> u64 {
        match (self.min_time(), self.max_time()) {
            (Some(a), Some(b)) => b.saturating_sub(a),
            _ => 0,
        }
    }

    #[must_use]
    pub fn from_session(session: &TraceSession) -> Self {
        let mut idx = Self::new();
        for rec in &session.records {
            idx.insert(rec.timestamp_ns, rec.seq);
        }
        idx
    }
}

// ─── SequenceRangeIndex ───────────────────────────────────────────────────────

/// Index that supports fast lookup by sequence number range using a sorted vec.
#[derive(Debug, Clone, Default)]
pub struct SequenceRangeIndex {
    /// Sorted (seq, `record_idx`) pairs.
    entries: Vec<(u64, usize)>,
}

impl SequenceRangeIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_sorted(&mut self, seq: u64, record_idx: usize) {
        let pos = self.entries.partition_point(|(s, _)| *s < seq);
        self.entries.insert(pos, (seq, record_idx));
    }

    #[must_use]
    pub fn from_session(session: &TraceSession) -> Self {
        let mut idx = Self::new();
        for (i, rec) in session.records.iter().enumerate() {
            idx.insert_sorted(rec.seq, i);
        }
        idx
    }

    /// Return record indices for sequences in `[start, end]`.
    #[must_use]
    pub fn indices_in_range(&self, start: u64, end: u64) -> Vec<usize> {
        let lo = self.entries.partition_point(|(s, _)| *s < start);
        let hi = self.entries.partition_point(|(s, _)| *s <= end);
        self.entries[lo..hi].iter().map(|(_, idx)| *idx).collect()
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─── FullTraceIndex ───────────────────────────────────────────────────────────

/// Composite index combining address, function, time, and sequence dimensions.
pub struct FullTraceIndex {
    pub address: AddressIndex,
    pub function: FunctionIndex,
    pub time: TimeIndex,
    pub sequence: SequenceRangeIndex,
    /// Event type → sorted sequence numbers.
    pub by_type: HashMap<String, Vec<u64>>,
    /// Thread ID → sorted sequence numbers.
    pub by_thread: HashMap<u32, Vec<u64>>,
}

impl FullTraceIndex {
    /// Build a complete index from a session.
    #[must_use]
    pub fn build(session: &TraceSession) -> Self {
        let address = AddressIndex::from_session(session);
        let function = FunctionIndex::from_session(session);
        let time = TimeIndex::from_session(session);
        let sequence = SequenceRangeIndex::from_session(session);

        let mut by_type: HashMap<String, Vec<u64>> = HashMap::new();
        let mut by_thread: HashMap<u32, Vec<u64>> = HashMap::new();

        for rec in &session.records {
            let type_name = event_type_name(&rec.event).to_string();
            by_type.entry(type_name).or_default().push(rec.seq);
            by_thread.entry(rec.thread_id).or_default().push(rec.seq);
        }

        Self {
            address,
            function,
            time,
            sequence,
            by_type,
            by_thread,
        }
    }

    /// All sequence numbers for events of the given type.
    pub fn seqs_by_type(&self, type_name: &str) -> &[u64] {
        self.by_type.get(type_name).map_or(&[], Vec::as_slice)
    }

    /// All sequence numbers for a given thread.
    pub fn seqs_by_thread(&self, tid: u32) -> &[u64] {
        self.by_thread.get(&tid).map_or(&[], Vec::as_slice)
    }

    /// Return record indices for a seq range, using the sequence index.
    #[must_use]
    pub fn records_in_seq_range(&self, start: u64, end: u64) -> Vec<usize> {
        self.sequence.indices_in_range(start, end)
    }

    /// Summary statistics about the index.
    #[must_use]
    pub fn stats(&self) -> IndexStats {
        IndexStats {
            unique_addresses: self.address.unique_address_count(),
            total_instructions: self.address.total,
            unique_functions: self.function.all_functions().len(),
            duration_ns: self.time.duration_ns(),
            total_records: self.sequence.len(),
            thread_count: self.by_thread.len(),
        }
    }
}

/// Summary statistics from the index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexStats {
    pub unique_addresses: usize,
    pub total_instructions: usize,
    pub unique_functions: usize,
    pub duration_ns: u64,
    pub total_records: usize,
    pub thread_count: usize,
}

const fn event_type_name(event: &TraceEvent) -> &'static str {
    match event {
        TraceEvent::Instruction { .. } => "Instruction",
        TraceEvent::MemRead { .. } => "MemRead",
        TraceEvent::MemWrite { .. } => "MemWrite",
        TraceEvent::Call { .. } => "Call",
        TraceEvent::Return { .. } => "Return",
        TraceEvent::Exception { .. } => "Exception",
        TraceEvent::Syscall { .. } => "Syscall",
        TraceEvent::Branch { .. } => "Branch",
        TraceEvent::ModuleLoad { .. } => "ModuleLoad",
        TraceEvent::RegisterChange { .. } => "RegisterChange",
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TraceSession;

    fn make_session() -> TraceSession {
        let mut s = TraceSession::new("test", "x86_64");
        // Instructions
        s.push(TraceEvent::Instruction { addr: 0x1000, size: 4 }, 1, 100);
        s.push(TraceEvent::Instruction { addr: 0x1004, size: 4 }, 1, 200);
        s.push(TraceEvent::Instruction { addr: 0x1000, size: 4 }, 1, 300); // 0x1000 hit twice
        // Call/return pair
        s.push(TraceEvent::Call { from: 0x1008, to: 0x2000 }, 1, 400);
        s.push(TraceEvent::Instruction { addr: 0x2000, size: 4 }, 1, 500);
        s.push(TraceEvent::Return { from: 0x2004, to: 0x100c }, 1, 600);
        // Thread 2
        s.push(TraceEvent::Instruction { addr: 0x3000, size: 2 }, 2, 700);
        s
    }

    #[test]
    fn test_address_index_hit_count() {
        let session = make_session();
        let idx = AddressIndex::from_session(&session);
        assert_eq!(idx.hit_count(0x1000), 2);
        assert_eq!(idx.hit_count(0x1004), 1);
        assert_eq!(idx.hit_count(0xDEAD), 0);
    }

    #[test]
    fn test_address_index_unique_count() {
        let session = make_session();
        let idx = AddressIndex::from_session(&session);
        // 0x1000, 0x1004, 0x2000, 0x3000
        assert_eq!(idx.unique_address_count(), 4);
    }

    #[test]
    fn test_address_index_top_hot() {
        let session = make_session();
        let idx = AddressIndex::from_session(&session);
        let top = idx.top_n_hot(1);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].0, 0x1000);
        assert_eq!(top[0].1, 2);
    }

    #[test]
    fn test_address_index_in_range() {
        let session = make_session();
        let idx = AddressIndex::from_session(&session);
        let addrs = idx.in_range(0x1000, 0x1010);
        assert!(addrs.contains(&0x1000));
        assert!(addrs.contains(&0x1004));
        assert!(!addrs.contains(&0x2000));
    }

    #[test]
    fn test_function_index_call_count() {
        let session = make_session();
        let idx = FunctionIndex::from_session(&session);
        assert_eq!(idx.call_count(0x2000), 1);
        assert_eq!(idx.call_count(0xDEAD), 0);
    }

    #[test]
    fn test_function_index_span_return_seq() {
        let session = make_session();
        let idx = FunctionIndex::from_session(&session);
        let spans = idx.spans_for(0x2000);
        assert_eq!(spans.len(), 1);
        // Return was the 6th event (seq 5)
        assert!(spans[0].return_seq.is_some());
    }

    #[test]
    fn test_function_index_all_functions() {
        let session = make_session();
        let idx = FunctionIndex::from_session(&session);
        let fns = idx.all_functions();
        assert!(fns.contains(&0x2000));
    }

    #[test]
    fn test_time_index_range_query() {
        let session = make_session();
        let idx = TimeIndex::from_session(&session);
        let seqs = idx.seqs_in_range(200, 400);
        // seq 1 (ts=200), seq 2 (ts=300), seq 3 (ts=400)
        assert!(seqs.contains(&1));
        assert!(seqs.contains(&2));
        assert!(seqs.contains(&3));
    }

    #[test]
    fn test_time_index_duration() {
        let session = make_session();
        let idx = TimeIndex::from_session(&session);
        assert_eq!(idx.duration_ns(), 600); // 700 - 100
    }

    #[test]
    fn test_sequence_range_index_in_range() {
        let session = make_session();
        let idx = SequenceRangeIndex::from_session(&session);
        let indices = idx.indices_in_range(0, 2);
        assert_eq!(indices.len(), 3); // seq 0,1,2
    }

    #[test]
    fn test_full_trace_index_build() {
        let session = make_session();
        let idx = FullTraceIndex::build(&session);
        let stats = idx.stats();
        assert_eq!(stats.unique_addresses, 4);
        assert_eq!(stats.thread_count, 2);
        assert_eq!(stats.total_records, 7);
    }

    #[test]
    fn test_full_trace_index_seqs_by_type() {
        let session = make_session();
        let idx = FullTraceIndex::build(&session);
        let instr_seqs = idx.seqs_by_type("Instruction");
        // make_session pushes 5 Instruction events (0x1000, 0x1004, 0x1000,
        // 0x2000, 0x3000); previous expected value of 4 ignored a duplicate.
        assert_eq!(instr_seqs.len(), 5);
    }

    #[test]
    fn test_full_trace_index_seqs_by_thread() {
        let session = make_session();
        let idx = FullTraceIndex::build(&session);
        let t1 = idx.seqs_by_thread(1);
        let t2 = idx.seqs_by_thread(2);
        assert_eq!(t1.len(), 6);
        assert_eq!(t2.len(), 1);
    }

    #[test]
    fn test_index_entry_constructor() {
        let e = IndexEntry::new(42, 7, 99_999);
        assert_eq!(e.seq, 42);
        assert_eq!(e.record_idx, 7);
    }

    #[test]
    fn test_address_index_manual_insert() {
        let mut idx = AddressIndex::new();
        idx.insert(0x1000, IndexEntry::new(0, 0, 100));
        idx.insert(0x1000, IndexEntry::new(1, 1, 200));
        assert_eq!(idx.hit_count(0x1000), 2);
        assert_eq!(idx.get(0x1000).len(), 2);
    }
}
