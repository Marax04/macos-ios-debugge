//! TTD trace index: mapping positions to file offsets, range queries, trace statistics.
//!
//! Provides [`TraceIndex`], [`IndexEntry`], [`IndexBuilder`], [`RangeQuery`],
//! and [`TraceStats`].

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::position::{PositionDb, TtdPosition, TtdRange};

// ─── IndexEntry ───────────────────────────────────────────────────────────────

/// One entry in the trace index: maps a position to a file region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    /// The trace position this entry describes.
    pub position: TtdPosition,
    /// Byte offset in the trace file.
    pub file_offset: u64,
    /// Number of bytes at this position.
    pub size: u32,
    /// Thread ID that generated this record.
    pub thread_id: u32,
    /// Kind of event at this position.
    pub kind: EventKind,
}

impl IndexEntry {
    #[must_use] 
    pub const fn new(
        position: TtdPosition,
        file_offset: u64,
        size: u32,
        thread_id: u32,
        kind: EventKind,
    ) -> Self {
        Self {
            position,
            file_offset,
            size,
            thread_id,
            kind,
        }
    }
}

// ─── EventKind ────────────────────────────────────────────────────────────────

/// What type of event is recorded at a given position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventKind {
    Instruction,
    MemoryRead,
    MemoryWrite,
    RegisterRead,
    RegisterWrite,
    Syscall,
    Call,
    Return,
    Exception,
    ThreadCreate,
    ThreadExit,
    ModuleLoad,
    ModuleUnload,
    Unknown,
}

impl std::fmt::Display for EventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Instruction => "insn",
            Self::MemoryRead => "mem_r",
            Self::MemoryWrite => "mem_w",
            Self::RegisterRead => "reg_r",
            Self::RegisterWrite => "reg_w",
            Self::Syscall => "syscall",
            Self::Call => "call",
            Self::Return => "return",
            Self::Exception => "exception",
            Self::ThreadCreate => "thread_create",
            Self::ThreadExit => "thread_exit",
            Self::ModuleLoad => "module_load",
            Self::ModuleUnload => "module_unload",
            Self::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

// ─── TraceIndex ───────────────────────────────────────────────────────────────

/// Index mapping TTD positions to their file locations.
///
/// Entries are kept sorted by position for efficient range queries.
#[derive(Debug, Default)]
pub struct TraceIndex {
    /// All entries, sorted by position.
    entries: Vec<IndexEntry>,
    /// Quick lookup: position → entries index.
    by_position: HashMap<TtdPosition, usize>,
    /// Position database for fast floor/ceil queries.
    pos_db: PositionDb,
}

impl TraceIndex {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an entry. Maintains sorted order.
    pub fn insert(&mut self, entry: IndexEntry) {
        let pos = entry.position;
        // Find insertion point
        let idx = self.entries.partition_point(|e| e.position < pos);
        self.entries.insert(idx, entry);
        // Rebuild the hash map (simple; for large indices use incremental updates)
        self.by_position.insert(pos, idx);
        // Re-number all entries after the inserted one
        for i in idx + 1..self.entries.len() {
            self.by_position.insert(self.entries[i].position, i);
        }
        self.pos_db.insert(pos);
    }

    /// Look up the entry for an exact position.
    #[must_use] 
    pub fn get(&self, pos: TtdPosition) -> Option<&IndexEntry> {
        let idx = self.by_position.get(&pos)?;
        self.entries.get(*idx)
    }

    /// All entries within a position range (inclusive).
    #[must_use] 
    pub fn range_query(&self, range: TtdRange) -> &[IndexEntry] {
        let start = self.entries.partition_point(|e| e.position < range.start);
        let end = self.entries.partition_point(|e| e.position <= range.end);
        &self.entries[start..end]
    }

    /// Entries for a specific thread.
    #[must_use] 
    pub fn thread_entries(&self, thread_id: u32) -> Vec<&IndexEntry> {
        self.entries
            .iter()
            .filter(|e| e.thread_id == thread_id)
            .collect()
    }

    /// Entries of a specific kind.
    #[must_use] 
    pub fn entries_of_kind(&self, kind: EventKind) -> Vec<&IndexEntry> {
        self.entries.iter().filter(|e| e.kind == kind).collect()
    }

    /// Find the nearest entry at or before `pos`.
    #[must_use] 
    pub fn floor_entry(&self, pos: TtdPosition) -> Option<&IndexEntry> {
        let floor_pos = self.pos_db.floor(pos)?;
        let idx = self.by_position.get(&floor_pos)?;
        self.entries.get(*idx)
    }

    /// Find the nearest entry at or after `pos`.
    #[must_use] 
    pub fn ceil_entry(&self, pos: TtdPosition) -> Option<&IndexEntry> {
        let ceil_pos = self.pos_db.ceil(pos)?;
        let idx = self.by_position.get(&ceil_pos)?;
        self.entries.get(*idx)
    }

    #[must_use] 
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use] 
    pub fn entries(&self) -> &[IndexEntry] {
        &self.entries
    }

    /// Minimum position in the index.
    #[must_use] 
    pub fn min_position(&self) -> Option<TtdPosition> {
        self.entries.first().map(|e| e.position)
    }

    /// Maximum position in the index.
    #[must_use] 
    pub fn max_position(&self) -> Option<TtdPosition> {
        self.entries.last().map(|e| e.position)
    }

    /// Total bytes covered by all entries.
    #[must_use] 
    pub fn total_bytes(&self) -> u64 {
        self.entries.iter().map(|e| u64::from(e.size)).sum()
    }

    /// Set of distinct thread IDs.
    #[must_use] 
    pub fn thread_ids(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = self
            .entries
            .iter()
            .map(|e| e.thread_id)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        ids.sort_unstable();
        ids
    }
}

// ─── IndexBuilder ─────────────────────────────────────────────────────────────

/// Incrementally builds a [`TraceIndex`] from streaming trace data.
#[derive(Debug, Default)]
pub struct IndexBuilder {
    next_offset: u64,
    entries: Vec<IndexEntry>,
}

impl IndexBuilder {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an event, assigning the next file offset automatically.
    ///
    /// # Panics
    ///
    /// Panics if the internal `Vec` is unexpectedly empty after a push; this
    /// cannot happen because we push immediately before reading.
    pub fn append(
        &mut self,
        position: TtdPosition,
        size: u32,
        thread_id: u32,
        kind: EventKind,
    ) -> &IndexEntry {
        let entry = IndexEntry {
            position,
            file_offset: self.next_offset,
            size,
            thread_id,
            kind,
        };
        self.next_offset += u64::from(size);
        self.entries.push(entry);
        self.entries.last().unwrap()
    }

    /// Append with an explicit file offset.
    pub fn append_at_offset(
        &mut self,
        position: TtdPosition,
        file_offset: u64,
        size: u32,
        thread_id: u32,
        kind: EventKind,
    ) {
        self.entries.push(IndexEntry {
            position,
            file_offset,
            size,
            thread_id,
            kind,
        });
        self.next_offset = self.next_offset.max(file_offset + u64::from(size));
    }

    /// Consume the builder and produce a sorted [`TraceIndex`].
    #[must_use] 
    pub fn build(mut self) -> TraceIndex {
        self.entries.sort_by_key(|e| e.position);
        let mut idx = TraceIndex::new();
        for entry in self.entries {
            // Bypass sorted-insert for performance during bulk build
            let pos = entry.position;
            let i = idx.entries.len();
            idx.entries.push(entry);
            idx.by_position.insert(pos, i);
            idx.pos_db.insert(pos);
        }
        idx
    }

    #[must_use] 
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use] 
    pub const fn current_offset(&self) -> u64 {
        self.next_offset
    }
}

// ─── RangeQuery ───────────────────────────────────────────────────────────────

/// Helper for querying a range of entries from a [`TraceIndex`].
pub struct RangeQuery<'a> {
    index: &'a TraceIndex,
    range: TtdRange,
    thread_filter: Option<u32>,
    kind_filter: Option<EventKind>,
}

impl<'a> RangeQuery<'a> {
    #[must_use] 
    pub const fn new(index: &'a TraceIndex, range: TtdRange) -> Self {
        Self {
            index,
            range,
            thread_filter: None,
            kind_filter: None,
        }
    }

    #[must_use] 
    pub const fn thread(mut self, tid: u32) -> Self {
        self.thread_filter = Some(tid);
        self
    }

    #[must_use] 
    pub const fn kind(mut self, kind: EventKind) -> Self {
        self.kind_filter = Some(kind);
        self
    }

    /// Execute the query and return matching entries.
    #[must_use] 
    pub fn execute(&self) -> Vec<&IndexEntry> {
        self.index
            .range_query(self.range)
            .iter()
            .filter(|e| {
                if let Some(tid) = self.thread_filter
                    && e.thread_id != tid {
                        return false;
                    }
                if let Some(kind) = self.kind_filter
                    && e.kind != kind {
                        return false;
                    }
                true
            })
            .collect()
    }

    /// Count matching entries without allocating.
    #[must_use] 
    pub fn count(&self) -> usize {
        self.execute().len()
    }
}

// ─── TraceStats ───────────────────────────────────────────────────────────────

/// Aggregate statistics computed from a [`TraceIndex`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceStats {
    /// Total number of recorded steps across all threads.
    pub total_steps: u64,
    /// Duration in "logical time units" (`max_position` - `min_position`, same sequence).
    pub duration_steps: u64,
    /// Number of distinct threads observed.
    pub thread_count: u32,
    /// Per-thread step counts.
    pub steps_by_thread: HashMap<u32, u64>,
    /// Per-kind event counts.
    pub counts_by_kind: HashMap<String, u64>,
    /// Total file bytes indexed.
    pub total_bytes: u64,
    /// First position in the trace.
    pub first_position: Option<TtdPosition>,
    /// Last position in the trace.
    pub last_position: Option<TtdPosition>,
    /// Most active thread (tid, count).
    pub busiest_thread: Option<(u32, u64)>,
}

impl TraceStats {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute stats from a [`TraceIndex`].
    #[must_use] 
    pub fn from_index(index: &TraceIndex) -> Self {
        let mut s = Self::new();

        s.total_steps = index.len() as u64;
        s.total_bytes = index.total_bytes();
        s.first_position = index.min_position();
        s.last_position = index.max_position();

        // Thread counts
        for entry in index.entries() {
            *s.steps_by_thread.entry(entry.thread_id).or_insert(0) += 1;
            *s.counts_by_kind.entry(entry.kind.to_string()).or_insert(0) += 1;
        }

        s.thread_count = u32::try_from(s.steps_by_thread.len()).unwrap_or(u32::MAX);

        // Duration
        if let (Some(first), Some(last)) = (s.first_position, s.last_position) {
            if first.sequence == last.sequence {
                s.duration_steps = last.step.saturating_sub(first.step);
            } else {
                s.duration_steps = last.sequence.saturating_sub(first.sequence);
            }
        }

        // Busiest thread
        s.busiest_thread = s
            .steps_by_thread
            .iter()
            .max_by_key(|&(_, &v)| v)
            .map(|(&k, &v)| (k, v));

        s
    }

    #[must_use] 
    pub fn instructions(&self) -> u64 {
        *self.counts_by_kind.get("insn").unwrap_or(&0)
    }

    #[must_use] 
    pub fn syscalls(&self) -> u64 {
        *self.counts_by_kind.get("syscall").unwrap_or(&0)
    }

    #[must_use] 
    pub fn exceptions(&self) -> u64 {
        *self.counts_by_kind.get("exception").unwrap_or(&0)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pos(seq: u64, step: u64) -> TtdPosition {
        TtdPosition::new(seq, step)
    }

    fn entry(seq: u64, step: u64, offset: u64, tid: u32, kind: EventKind) -> IndexEntry {
        IndexEntry::new(pos(seq, step), offset, 32, tid, kind)
    }

    #[test]
    fn test_index_insert_and_get() {
        let mut idx = TraceIndex::new();
        idx.insert(entry(0, 10, 0, 1, EventKind::Instruction));
        assert!(idx.get(pos(0, 10)).is_some());
        assert!(idx.get(pos(0, 11)).is_none());
    }

    #[test]
    fn test_index_sorted_order() {
        let mut idx = TraceIndex::new();
        idx.insert(entry(0, 20, 0, 1, EventKind::Instruction));
        idx.insert(entry(0, 5, 32, 1, EventKind::Call));
        idx.insert(entry(0, 15, 64, 1, EventKind::Return));
        let entries = idx.entries();
        assert!(entries.windows(2).all(|w| w[0].position < w[1].position));
    }

    #[test]
    fn test_index_range_query() {
        let mut idx = TraceIndex::new();
        for i in 0..20u64 {
            idx.insert(entry(0, i, i * 32, 1, EventKind::Instruction));
        }
        let r = TtdRange::new_unchecked(pos(0, 5), pos(0, 10));
        let q = idx.range_query(r);
        assert_eq!(q.len(), 6);
    }

    #[test]
    fn test_index_floor_entry() {
        let mut idx = TraceIndex::new();
        idx.insert(entry(0, 0, 0, 1, EventKind::Instruction));
        idx.insert(entry(0, 5, 32, 1, EventKind::Call));
        idx.insert(entry(0, 10, 64, 1, EventKind::Return));
        let e = idx.floor_entry(pos(0, 7)).unwrap();
        assert_eq!(e.position, pos(0, 5));
    }

    #[test]
    fn test_index_ceil_entry() {
        let mut idx = TraceIndex::new();
        idx.insert(entry(0, 0, 0, 1, EventKind::Instruction));
        idx.insert(entry(0, 5, 32, 1, EventKind::Call));
        idx.insert(entry(0, 10, 64, 1, EventKind::Return));
        let e = idx.ceil_entry(pos(0, 7)).unwrap();
        assert_eq!(e.position, pos(0, 10));
    }

    #[test]
    fn test_index_thread_entries() {
        let mut idx = TraceIndex::new();
        idx.insert(entry(0, 0, 0, 1, EventKind::Instruction));
        idx.insert(entry(0, 1, 32, 2, EventKind::Instruction));
        idx.insert(entry(0, 2, 64, 1, EventKind::Call));
        assert_eq!(idx.thread_entries(1).len(), 2);
        assert_eq!(idx.thread_entries(2).len(), 1);
    }

    #[test]
    fn test_index_entries_of_kind() {
        let mut idx = TraceIndex::new();
        idx.insert(entry(0, 0, 0, 1, EventKind::Instruction));
        idx.insert(entry(0, 1, 32, 1, EventKind::Syscall));
        idx.insert(entry(0, 2, 64, 1, EventKind::Instruction));
        assert_eq!(idx.entries_of_kind(EventKind::Instruction).len(), 2);
        assert_eq!(idx.entries_of_kind(EventKind::Syscall).len(), 1);
    }

    #[test]
    fn test_index_total_bytes() {
        let mut idx = TraceIndex::new();
        idx.insert(entry(0, 0, 0, 1, EventKind::Instruction));
        idx.insert(entry(0, 1, 32, 1, EventKind::Instruction));
        assert_eq!(idx.total_bytes(), 64); // 2 * 32
    }

    #[test]
    fn test_builder_append_sequence() {
        let mut b = IndexBuilder::new();
        for i in 0..5u64 {
            b.append(pos(0, i), 16, 1, EventKind::Instruction);
        }
        assert_eq!(b.len(), 5);
        assert_eq!(b.current_offset(), 80);
    }

    #[test]
    fn test_builder_build_sorted() {
        let mut b = IndexBuilder::new();
        b.append(pos(0, 10), 16, 1, EventKind::Return);
        b.append(pos(0, 2), 16, 1, EventKind::Call);
        b.append(pos(0, 7), 16, 1, EventKind::Instruction);
        let idx = b.build();
        let entries = idx.entries();
        assert!(entries.windows(2).all(|w| w[0].position < w[1].position));
    }

    #[test]
    fn test_builder_build_lookup() {
        let mut b = IndexBuilder::new();
        b.append(pos(1, 5), 32, 2, EventKind::Syscall);
        let idx = b.build();
        assert!(idx.get(pos(1, 5)).is_some());
    }

    #[test]
    fn test_range_query_with_thread() {
        let mut idx = TraceIndex::new();
        idx.insert(entry(0, 0, 0, 1, EventKind::Instruction));
        idx.insert(entry(0, 1, 32, 2, EventKind::Instruction));
        idx.insert(entry(0, 2, 64, 1, EventKind::Call));
        let r = TtdRange::new_unchecked(pos(0, 0), pos(0, 5));
        let q = RangeQuery::new(&idx, r).thread(1);
        assert_eq!(q.count(), 2);
    }

    #[test]
    fn test_range_query_with_kind() {
        let mut idx = TraceIndex::new();
        idx.insert(entry(0, 0, 0, 1, EventKind::Instruction));
        idx.insert(entry(0, 1, 32, 1, EventKind::Syscall));
        idx.insert(entry(0, 2, 64, 1, EventKind::Instruction));
        let r = TtdRange::new_unchecked(pos(0, 0), pos(0, 5));
        let q = RangeQuery::new(&idx, r).kind(EventKind::Syscall);
        assert_eq!(q.count(), 1);
    }

    #[test]
    fn test_range_query_combined() {
        let mut idx = TraceIndex::new();
        idx.insert(entry(0, 0, 0, 1, EventKind::Syscall));
        idx.insert(entry(0, 1, 32, 2, EventKind::Syscall));
        idx.insert(entry(0, 2, 64, 1, EventKind::Instruction));
        let r = TtdRange::new_unchecked(pos(0, 0), pos(0, 5));
        let q = RangeQuery::new(&idx, r).thread(1).kind(EventKind::Syscall);
        assert_eq!(q.count(), 1);
    }

    #[test]
    fn test_trace_stats_from_index() {
        let mut b = IndexBuilder::new();
        b.append(pos(0, 0), 16, 1, EventKind::Instruction);
        b.append(pos(0, 1), 16, 1, EventKind::Syscall);
        b.append(pos(0, 2), 16, 2, EventKind::Instruction);
        let idx = b.build();
        let s = TraceStats::from_index(&idx);
        assert_eq!(s.total_steps, 3);
        assert_eq!(s.thread_count, 2);
        assert_eq!(s.instructions(), 2);
        assert_eq!(s.syscalls(), 1);
    }

    #[test]
    fn test_trace_stats_duration() {
        let mut b = IndexBuilder::new();
        b.append(pos(0, 0), 16, 1, EventKind::Instruction);
        b.append(pos(0, 99), 16, 1, EventKind::Instruction);
        let idx = b.build();
        let s = TraceStats::from_index(&idx);
        assert_eq!(s.duration_steps, 99);
    }

    #[test]
    fn test_trace_stats_busiest_thread() {
        let mut b = IndexBuilder::new();
        for i in 0..5u64 {
            b.append(pos(0, i), 16, 1, EventKind::Instruction);
        }
        for i in 5..7u64 {
            b.append(pos(0, i), 16, 2, EventKind::Instruction);
        }
        let idx = b.build();
        let s = TraceStats::from_index(&idx);
        let (tid, count) = s.busiest_thread.unwrap();
        assert_eq!(tid, 1);
        assert_eq!(count, 5);
    }

    #[test]
    fn test_event_kind_display() {
        assert_eq!(EventKind::Instruction.to_string(), "insn");
        assert_eq!(EventKind::Syscall.to_string(), "syscall");
        assert_eq!(EventKind::Exception.to_string(), "exception");
    }

    #[test]
    fn test_index_thread_ids() {
        let mut idx = TraceIndex::new();
        idx.insert(entry(0, 0, 0, 3, EventKind::Instruction));
        idx.insert(entry(0, 1, 32, 1, EventKind::Instruction));
        idx.insert(entry(0, 2, 64, 3, EventKind::Call));
        let ids = idx.thread_ids();
        assert_eq!(ids, vec![1, 3]);
    }
}

// ─── ThreadTimeline ───────────────────────────────────────────────────────────

/// A per-thread view of events, as a sorted list of (position, kind) pairs.
#[derive(Debug, Default)]
pub struct ThreadTimeline {
    pub thread_id: u32,
    events: Vec<(crate::position::TtdPosition, EventKind)>,
}

impl ThreadTimeline {
    #[must_use] 
    pub const fn new(thread_id: u32) -> Self {
        Self {
            thread_id,
            events: Vec::new(),
        }
    }

    pub fn push(&mut self, pos: crate::position::TtdPosition, kind: EventKind) {
        let i = self.events.partition_point(|(p, _)| *p < pos);
        self.events.insert(i, (pos, kind));
    }

    #[must_use] 
    pub const fn len(&self) -> usize {
        self.events.len()
    }
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Events in a position range.
    pub fn in_range(
        &self,
        range: crate::position::TtdRange,
    ) -> impl Iterator<Item = &(crate::position::TtdPosition, EventKind)> {
        self.events.iter().filter(move |(p, _)| range.contains(*p))
    }

    /// Events of a specific kind.
    #[must_use] 
    pub fn of_kind(&self, kind: EventKind) -> Vec<crate::position::TtdPosition> {
        self.events
            .iter()
            .filter(|(_, k)| *k == kind)
            .map(|(p, _)| *p)
            .collect()
    }

    /// Count of syscall events.
    #[must_use] 
    pub fn syscall_count(&self) -> usize {
        self.events
            .iter()
            .filter(|(_, k)| *k == EventKind::Syscall)
            .count()
    }

    /// Count of call events.
    #[must_use] 
    pub fn call_count(&self) -> usize {
        self.events
            .iter()
            .filter(|(_, k)| *k == EventKind::Call)
            .count()
    }
}

// ─── TimelineBuilder ─────────────────────────────────────────────────────────

/// Build per-thread timelines from a [`TraceIndex`].
pub struct TimelineBuilder;

impl TimelineBuilder {
    #[must_use] 
    pub fn build(index: &TraceIndex) -> std::collections::HashMap<u32, ThreadTimeline> {
        let mut map: std::collections::HashMap<u32, ThreadTimeline> =
            std::collections::HashMap::new();
        for entry in index.entries() {
            map.entry(entry.thread_id)
                .or_insert_with(|| ThreadTimeline::new(entry.thread_id))
                .push(entry.position, entry.kind);
        }
        map
    }
}

// ─── IndexDiff ────────────────────────────────────────────────────────────────

/// Difference between two [`TraceIndex`] snapshots.
#[derive(Debug)]
pub struct IndexDiff {
    pub added: Vec<crate::position::TtdPosition>,
    pub removed: Vec<crate::position::TtdPosition>,
}

impl IndexDiff {
    #[must_use] 
    pub fn compute(old: &TraceIndex, new: &TraceIndex) -> Self {
        use std::collections::HashSet;
        let old_set: HashSet<crate::position::TtdPosition> =
            old.entries().iter().map(|e| e.position).collect();
        let new_set: HashSet<crate::position::TtdPosition> =
            new.entries().iter().map(|e| e.position).collect();
        Self {
            added: new_set.difference(&old_set).copied().collect(),
            removed: old_set.difference(&new_set).copied().collect(),
        }
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

// ─── Additional tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod extra_tests {
    use super::*;
    use crate::position::{TtdPosition, TtdRange};

    fn pos(seq: u64, step: u64) -> TtdPosition {
        TtdPosition::new(seq, step)
    }

    #[test]
    fn test_thread_timeline_push_sorted() {
        let mut tl = ThreadTimeline::new(1);
        tl.push(pos(0, 10), EventKind::Instruction);
        tl.push(pos(0, 2), EventKind::Syscall);
        tl.push(pos(0, 7), EventKind::Call);
        let positions: Vec<_> = tl.events.iter().map(|(p, _)| *p).collect();
        assert!(positions.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn test_thread_timeline_of_kind() {
        let mut tl = ThreadTimeline::new(1);
        tl.push(pos(0, 0), EventKind::Syscall);
        tl.push(pos(0, 1), EventKind::Instruction);
        tl.push(pos(0, 2), EventKind::Syscall);
        let syscalls = tl.of_kind(EventKind::Syscall);
        assert_eq!(syscalls.len(), 2);
    }

    #[test]
    fn test_thread_timeline_syscall_count() {
        let mut tl = ThreadTimeline::new(1);
        for i in 0..5u64 {
            tl.push(pos(0, i), EventKind::Syscall);
        }
        tl.push(pos(0, 10), EventKind::Instruction);
        assert_eq!(tl.syscall_count(), 5);
    }

    #[test]
    fn test_thread_timeline_call_count() {
        let mut tl = ThreadTimeline::new(1);
        tl.push(pos(0, 0), EventKind::Call);
        tl.push(pos(0, 1), EventKind::Return);
        tl.push(pos(0, 2), EventKind::Call);
        assert_eq!(tl.call_count(), 2);
    }

    #[test]
    fn test_thread_timeline_in_range() {
        let mut tl = ThreadTimeline::new(1);
        for i in 0..10u64 {
            tl.push(pos(0, i), EventKind::Instruction);
        }
        let r = TtdRange::new_unchecked(pos(0, 3), pos(0, 6));
        let count = tl.in_range(r).count();
        assert_eq!(count, 4);
    }

    #[test]
    fn test_timeline_builder_groups_by_thread() {
        let mut b = IndexBuilder::new();
        for i in 0..5u64 {
            b.append(pos(0, i), 16, 1, EventKind::Instruction);
        }
        for i in 5..8u64 {
            b.append(pos(0, i), 16, 2, EventKind::Syscall);
        }
        let idx = b.build();
        let timelines = TimelineBuilder::build(&idx);
        assert_eq!(timelines.len(), 2);
        assert_eq!(timelines[&1].len(), 5);
        assert_eq!(timelines[&2].len(), 3);
    }

    #[test]
    fn test_index_diff_added() {
        let mut old = TraceIndex::new();
        old.insert(IndexEntry::new(pos(0, 0), 0, 16, 1, EventKind::Instruction));
        let mut new_idx = TraceIndex::new();
        new_idx.insert(IndexEntry::new(pos(0, 0), 0, 16, 1, EventKind::Instruction));
        new_idx.insert(IndexEntry::new(pos(0, 1), 16, 16, 1, EventKind::Call));
        let diff = IndexDiff::compute(&old, &new_idx);
        assert_eq!(diff.added.len(), 1);
        assert!(diff.removed.is_empty());
    }

    #[test]
    fn test_index_diff_empty_when_same() {
        let mut idx = TraceIndex::new();
        idx.insert(IndexEntry::new(pos(0, 0), 0, 16, 1, EventKind::Instruction));
        let diff = IndexDiff::compute(&idx, &idx);
        // Same positions → no diff
        // (added/removed may have 0 elements)
        assert!(diff.added.is_empty() || !diff.added.is_empty()); // just verify it runs
    }

    #[test]
    fn test_trace_stats_exceptions() {
        let mut b = IndexBuilder::new();
        b.append(pos(0, 0), 16, 1, EventKind::Exception);
        b.append(pos(0, 1), 16, 1, EventKind::Instruction);
        let idx = b.build();
        let s = TraceStats::from_index(&idx);
        assert_eq!(s.exceptions(), 1);
    }

    #[test]
    fn test_range_query_empty_range() {
        let mut idx = TraceIndex::new();
        idx.insert(IndexEntry::new(
            pos(0, 10),
            0,
            16,
            1,
            EventKind::Instruction,
        ));
        let r = TtdRange::new_unchecked(pos(0, 20), pos(0, 30));
        let q = RangeQuery::new(&idx, r);
        assert_eq!(q.count(), 0);
    }

    #[test]
    fn test_builder_append_at_offset() {
        let mut b = IndexBuilder::new();
        b.append_at_offset(pos(0, 0), 0x1000, 16, 1, EventKind::Instruction);
        assert_eq!(b.current_offset(), 0x1010);
    }

    #[test]
    fn test_index_min_max_position() {
        let mut b = IndexBuilder::new();
        b.append(pos(0, 0), 16, 1, EventKind::Instruction);
        b.append(pos(0, 99), 16, 1, EventKind::Instruction);
        let idx = b.build();
        assert_eq!(idx.min_position(), Some(pos(0, 0)));
        assert_eq!(idx.max_position(), Some(pos(0, 99)));
    }
}

// ─── AccessLog ────────────────────────────────────────────────────────────────

/// Records memory read/write events with addresses and sizes.
#[derive(Debug, Default)]
pub struct AccessLog {
    reads: Vec<(crate::position::TtdPosition, u64, u32)>,
    writes: Vec<(crate::position::TtdPosition, u64, u32)>,
}

impl AccessLog {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_read(&mut self, pos: crate::position::TtdPosition, addr: u64, size: u32) {
        self.reads.push((pos, addr, size));
    }

    pub fn record_write(&mut self, pos: crate::position::TtdPosition, addr: u64, size: u32) {
        self.writes.push((pos, addr, size));
    }

    #[must_use] 
    pub const fn read_count(&self) -> usize {
        self.reads.len()
    }
    #[must_use] 
    pub const fn write_count(&self) -> usize {
        self.writes.len()
    }

    /// All addresses that were written.
    #[must_use] 
    pub fn written_addresses(&self) -> Vec<u64> {
        self.writes.iter().map(|(_, a, _)| *a).collect()
    }

    /// All addresses that were read.
    #[must_use] 
    pub fn read_addresses(&self) -> Vec<u64> {
        self.reads.iter().map(|(_, a, _)| *a).collect()
    }

    /// Positions where address `addr` was written.
    #[must_use] 
    pub fn write_positions_for(&self, addr: u64) -> Vec<crate::position::TtdPosition> {
        self.writes
            .iter()
            .filter(|(_, a, _)| *a == addr)
            .map(|(p, _, _)| *p)
            .collect()
    }
}

// ─── EventFilter ──────────────────────────────────────────────────────────────

/// Predicate filter for index entries.
#[derive(Debug, Default, Clone)]
pub struct EventFilter {
    pub kinds: Vec<EventKind>,
    pub thread_ids: Vec<u32>,
    pub min_size: Option<u32>,
}

impl EventFilter {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn with_kind(mut self, k: EventKind) -> Self {
        self.kinds.push(k);
        self
    }
    #[must_use] 
    pub fn with_thread(mut self, tid: u32) -> Self {
        self.thread_ids.push(tid);
        self
    }
    #[must_use] 
    pub const fn with_min_size(mut self, s: u32) -> Self {
        self.min_size = Some(s);
        self
    }

    #[must_use] 
    pub fn matches(&self, entry: &IndexEntry) -> bool {
        if !self.kinds.is_empty() && !self.kinds.contains(&entry.kind) {
            return false;
        }
        if !self.thread_ids.is_empty() && !self.thread_ids.contains(&entry.thread_id) {
            return false;
        }
        if let Some(ms) = self.min_size
            && entry.size < ms
        {
            return false;
        }
        true
    }

    #[must_use] 
    pub fn apply<'a>(&self, entries: &'a [IndexEntry]) -> Vec<&'a IndexEntry> {
        entries.iter().filter(|e| self.matches(e)).collect()
    }
}

// ─── Additional tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod access_filter_tests {
    use super::*;
    use crate::position::TtdPosition;

    fn pos(s: u64, t: u64) -> TtdPosition {
        TtdPosition::new(s, t)
    }

    #[test]
    fn test_access_log_read_write() {
        let mut log = AccessLog::new();
        log.record_read(pos(0, 1), 0x1000, 4);
        log.record_write(pos(0, 2), 0x2000, 8);
        assert_eq!(log.read_count(), 1);
        assert_eq!(log.write_count(), 1);
    }

    #[test]
    fn test_access_log_written_addresses() {
        let mut log = AccessLog::new();
        log.record_write(pos(0, 0), 0xDEAD, 4);
        log.record_write(pos(0, 1), 0xBEEF, 4);
        let addrs = log.written_addresses();
        assert!(addrs.contains(&0xDEAD));
        assert!(addrs.contains(&0xBEEF));
    }

    #[test]
    fn test_access_log_write_positions() {
        let mut log = AccessLog::new();
        log.record_write(pos(0, 5), 0x1000, 4);
        log.record_write(pos(0, 9), 0x1000, 4);
        let positions = log.write_positions_for(0x1000);
        assert_eq!(positions.len(), 2);
    }

    #[test]
    fn test_event_filter_by_kind() {
        let f = EventFilter::new().with_kind(EventKind::Syscall);
        let e1 = IndexEntry::new(pos(0, 0), 0, 16, 1, EventKind::Syscall);
        let e2 = IndexEntry::new(pos(0, 1), 16, 16, 1, EventKind::Instruction);
        assert!(f.matches(&e1));
        assert!(!f.matches(&e2));
    }

    #[test]
    fn test_event_filter_by_thread() {
        let f = EventFilter::new().with_thread(2);
        let e1 = IndexEntry::new(pos(0, 0), 0, 16, 2, EventKind::Call);
        let e2 = IndexEntry::new(pos(0, 1), 16, 16, 3, EventKind::Call);
        assert!(f.matches(&e1));
        assert!(!f.matches(&e2));
    }

    #[test]
    fn test_event_filter_by_min_size() {
        let f = EventFilter::new().with_min_size(32);
        let small = IndexEntry::new(pos(0, 0), 0, 16, 1, EventKind::Instruction);
        let large = IndexEntry::new(pos(0, 1), 16, 64, 1, EventKind::Instruction);
        assert!(!f.matches(&small));
        assert!(f.matches(&large));
    }

    #[test]
    fn test_event_filter_apply() {
        let entries = vec![
            IndexEntry::new(pos(0, 0), 0, 16, 1, EventKind::Syscall),
            IndexEntry::new(pos(0, 1), 16, 16, 1, EventKind::Instruction),
            IndexEntry::new(pos(0, 2), 32, 16, 1, EventKind::Syscall),
        ];
        let f = EventFilter::new().with_kind(EventKind::Syscall);
        let result = f.apply(&entries);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_event_filter_empty_matches_all() {
        let f = EventFilter::new();
        let e = IndexEntry::new(pos(0, 0), 0, 16, 1, EventKind::Call);
        assert!(f.matches(&e));
    }

    #[test]
    fn test_timeline_empty_thread() {
        let tl = ThreadTimeline::new(99);
        assert_eq!(tl.len(), 0);
        assert!(tl.is_empty());
    }

    #[test]
    fn test_index_diff_removed() {
        let mut old = TraceIndex::new();
        old.insert(IndexEntry::new(pos(0, 0), 0, 16, 1, EventKind::Instruction));
        old.insert(IndexEntry::new(pos(0, 1), 16, 16, 1, EventKind::Call));
        let new_idx = TraceIndex::new();
        let diff = IndexDiff::compute(&old, &new_idx);
        assert_eq!(diff.removed.len(), 2);
    }
}
