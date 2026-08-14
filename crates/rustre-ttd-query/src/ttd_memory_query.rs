//! TTD memory query: read memory at specific positions, track memory writes,
//! snapshot reconstruction, and change-set analysis.

use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// MemoryPosition — a (sequence, step) pair used as a timeline key
// ---------------------------------------------------------------------------

/// A position in the TTD trace expressed as a (sequence, step) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MemoryPosition {
    pub sequence: u64,
    pub step: u32,
}

impl MemoryPosition {
    /// Create a new position.
    #[must_use]
    pub const fn new(sequence: u64, step: u32) -> Self {
        Self { sequence, step }
    }

    /// Return the position immediately before this one (clamped at zero).
    #[must_use]
    pub const fn prev(&self) -> Self {
        if self.step > 0 {
            Self {
                sequence: self.sequence,
                step: self.step - 1,
            }
        } else if self.sequence > 0 {
            Self {
                sequence: self.sequence - 1,
                step: u32::MAX,
            }
        } else {
            *self
        }
    }

    /// Return the position immediately after this one.
    #[must_use]
    pub const fn next(&self) -> Self {
        if self.step < u32::MAX {
            Self {
                sequence: self.sequence,
                step: self.step + 1,
            }
        } else {
            Self {
                sequence: self.sequence + 1,
                step: 0,
            }
        }
    }
}

impl std::fmt::Display for MemoryPosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.sequence, self.step)
    }
}

// ---------------------------------------------------------------------------
// MemoryWrite — a single recorded write event
// ---------------------------------------------------------------------------

/// A single memory-write event recorded at a specific trace position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryWrite {
    /// The trace position at which the write occurred.
    pub position: MemoryPosition,
    /// The start address of the write.
    pub address: u64,
    /// The bytes written.
    pub data: Vec<u8>,
    /// Thread ID that performed the write.
    pub thread_id: u32,
}

impl MemoryWrite {
    /// Create a new write record.
    #[must_use]
    pub const fn new(position: MemoryPosition, address: u64, data: Vec<u8>, thread_id: u32) -> Self {
        Self {
            position,
            address,
            data,
            thread_id,
        }
    }

    /// Return the exclusive end address of this write.
    #[must_use]
    pub const fn end_address(&self) -> u64 {
        self.address.saturating_add(self.data.len() as u64)
    }

    /// Whether this write overlaps the given range `[addr, addr+len)`.
    #[must_use]
    pub const fn overlaps(&self, addr: u64, len: u64) -> bool {
        self.address < addr.saturating_add(len) && self.end_address() > addr
    }
}

impl std::fmt::Display for MemoryWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Write @ {} addr={:#x} len={} tid={}",
            self.position,
            self.address,
            self.data.len(),
            self.thread_id
        )
    }
}

// ---------------------------------------------------------------------------
// MemorySnapshot — reconstructed memory contents at a position
// ---------------------------------------------------------------------------

/// A reconstructed snapshot of a contiguous memory region at a given position.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySnapshot {
    /// The address of the first byte.
    pub base_address: u64,
    /// The reconstructed bytes (may contain `None` for unknown bytes).
    pub bytes: Vec<Option<u8>>,
    /// The position at which this snapshot was taken.
    pub position: MemoryPosition,
    /// Number of bytes whose values were reconstructed from write history.
    pub known_bytes: usize,
}

impl MemorySnapshot {
    /// Create an empty snapshot of size `len` at `base_address`.
    #[must_use]
    pub fn empty(base_address: u64, len: usize, position: MemoryPosition) -> Self {
        Self {
            base_address,
            bytes: vec![None; len],
            position,
            known_bytes: 0,
        }
    }

    /// Return the number of bytes in this snapshot.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return `true` if the snapshot is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Apply a write to this snapshot, updating the known bytes.
    pub fn apply_write(&mut self, write: &MemoryWrite) {
        let snap_end = self.base_address.saturating_add(self.bytes.len() as u64);
        let write_end = write.end_address();

        let overlap_start = write.address.max(self.base_address);
        let overlap_end = write_end.min(snap_end);

        if overlap_start >= overlap_end {
            return;
        }

        let snap_offset = (overlap_start - self.base_address) as usize;
        let write_offset = (overlap_start - write.address) as usize;
        let overlap_len = (overlap_end - overlap_start) as usize;

        for i in 0..overlap_len {
            if write_offset + i < write.data.len() {
                if self.bytes[snap_offset + i].is_none() {
                    self.known_bytes += 1;
                }
                self.bytes[snap_offset + i] = Some(write.data[write_offset + i]);
            }
        }
    }

    /// Return a byte at relative offset `off`, or `None` if unknown.
    #[must_use]
    pub fn byte_at(&self, off: usize) -> Option<u8> {
        self.bytes.get(off).copied().flatten()
    }

    /// Read a `u32` at relative offset `off` (little-endian). Returns `None` if any byte unknown.
    #[must_use]
    pub fn read_u32_le(&self, off: usize) -> Option<u32> {
        let b0 = self.byte_at(off)?;
        let b1 = self.byte_at(off + 1)?;
        let b2 = self.byte_at(off + 2)?;
        let b3 = self.byte_at(off + 3)?;
        Some(u32::from_le_bytes([b0, b1, b2, b3]))
    }

    /// Read a `u64` at relative offset `off` (little-endian). Returns `None` if any byte unknown.
    #[must_use]
    pub fn read_u64_le(&self, off: usize) -> Option<u64> {
        let b0 = self.byte_at(off)?;
        let b1 = self.byte_at(off + 1)?;
        let b2 = self.byte_at(off + 2)?;
        let b3 = self.byte_at(off + 3)?;
        let b4 = self.byte_at(off + 4)?;
        let b5 = self.byte_at(off + 5)?;
        let b6 = self.byte_at(off + 6)?;
        let b7 = self.byte_at(off + 7)?;
        Some(u64::from_le_bytes([b0, b1, b2, b3, b4, b5, b6, b7]))
    }

    /// Percentage of bytes with known values.
    #[must_use]
    pub fn coverage(&self) -> f64 {
        if self.bytes.is_empty() {
            return 0.0;
        }
        (self.known_bytes as f64 / self.bytes.len() as f64) * 100.0
    }

    /// Convert to a raw byte vector, filling unknown bytes with `fill`.
    #[must_use]
    pub fn to_raw(&self, fill: u8) -> Vec<u8> {
        self.bytes.iter().map(|b| b.unwrap_or(fill)).collect()
    }
}

impl std::fmt::Display for MemorySnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Snapshot @ {} base={:#x} len={} known={:.1}%",
            self.position,
            self.base_address,
            self.bytes.len(),
            self.coverage()
        )
    }
}

// ---------------------------------------------------------------------------
// MemoryChangeSet — set of addresses modified between two positions
// ---------------------------------------------------------------------------

/// Records which addresses changed between two trace positions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryChangeSet {
    pub from_position: MemoryPosition,
    pub to_position: MemoryPosition,
    /// Sorted list of (address, `old_value`, `new_value`) tuples.
    pub changes: Vec<(u64, Option<u8>, u8)>,
}

impl MemoryChangeSet {
    /// Number of changed bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.changes.len()
    }

    /// Whether there are no changes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Return only the addresses that changed.
    #[must_use]
    pub fn changed_addresses(&self) -> Vec<u64> {
        self.changes.iter().map(|(a, _, _)| *a).collect()
    }

    /// Return contiguous ranges of changed addresses.
    #[must_use]
    pub fn changed_ranges(&self) -> Vec<(u64, u64)> {
        if self.changes.is_empty() {
            return Vec::new();
        }
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        let mut range_start = self.changes[0].0;
        let mut prev_addr = self.changes[0].0;

        for (addr, _, _) in &self.changes[1..] {
            if *addr == prev_addr + 1 {
                prev_addr = *addr;
            } else {
                ranges.push((range_start, prev_addr + 1));
                range_start = *addr;
                prev_addr = *addr;
            }
        }
        ranges.push((range_start, prev_addr + 1));
        ranges
    }
}

// ---------------------------------------------------------------------------
// WriteIndex — internal BTree index of all writes
// ---------------------------------------------------------------------------

/// Index for looking up writes by address and position.
pub struct WriteIndex {
    /// address -> list of (position, write) sorted by position
    by_address: BTreeMap<u64, Vec<(MemoryPosition, MemoryWrite)>>,
    /// All writes sorted by position
    by_position: BTreeMap<MemoryPosition, Vec<MemoryWrite>>,
}

impl WriteIndex {
    /// Create an empty index.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            by_address: BTreeMap::new(),
            by_position: BTreeMap::new(),
        }
    }

    /// Insert a write into the index.
    pub fn insert(&mut self, write: MemoryWrite) {
        let pos = write.position;
        let addr = write.address;
        let end = write.end_address();

        // Index each byte address
        for byte_addr in addr..end {
            self.by_address
                .entry(byte_addr)
                .or_default()
                .push((pos, write.clone()));
        }
        self.by_position.entry(pos).or_default().push(write);
    }

    /// Find the last write to `addr` at or before `pos`.
    #[must_use]
    pub fn last_write_before(&self, addr: u64, pos: MemoryPosition) -> Option<&MemoryWrite> {
        let writes = self.by_address.get(&addr)?;
        // Binary search for the last write at or before pos
        let idx = writes.partition_point(|(p, _)| *p <= pos);
        if idx > 0 {
            Some(&writes[idx - 1].1)
        } else {
            None
        }
    }

    /// Find all writes to the range `[addr, addr+len)` at or before `pos`.
    #[must_use]
    pub fn writes_to_range_before(
        &self,
        addr: u64,
        len: u64,
        pos: MemoryPosition,
    ) -> Vec<&MemoryWrite> {
        let mut result = Vec::new();
        for byte_addr in addr..addr.saturating_add(len) {
            if let Some(writes) = self.by_address.get(&byte_addr) {
                let idx = writes.partition_point(|(p, _)| *p <= pos);
                if idx > 0 {
                    result.push(&writes[idx - 1].1);
                }
            }
        }
        // Deduplicate by write identity
        result.sort_by_key(|w| (w.position, w.address));
        result.dedup_by_key(|w| (w.position, w.address));
        result
    }

    /// All writes between `from` and `to` positions (inclusive).
    #[must_use]
    pub fn writes_in_range(&self, from: MemoryPosition, to: MemoryPosition) -> Vec<&MemoryWrite> {
        self.by_position
            .range((Bound::Included(&from), Bound::Included(&to)))
            .flat_map(|(_, writes)| writes.iter())
            .collect()
    }

    /// Total number of write events.
    #[must_use]
    pub fn total_events(&self) -> usize {
        self.by_position.values().map(std::vec::Vec::len).sum()
    }

    /// All unique addresses that have been written.
    #[must_use]
    pub fn unique_written_addresses(&self) -> Vec<u64> {
        self.by_address.keys().copied().collect()
    }
}

impl Default for WriteIndex {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TtdMemoryQuery
// ---------------------------------------------------------------------------

/// Query engine for TTD memory access patterns.
///
/// Maintains a `WriteIndex` built from all recorded `MemWrite` events and
/// supports snapshot reconstruction, write history retrieval, and change-set
/// computation.
pub struct TtdMemoryQuery {
    index: WriteIndex,
    /// Statistics: total bytes written per thread
    writes_by_thread: HashMap<u32, u64>,
    /// Total distinct addresses written
    total_write_events: usize,
}

impl TtdMemoryQuery {
    /// Create an empty query engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            index: WriteIndex::new(),
            writes_by_thread: HashMap::new(),
            total_write_events: 0,
        }
    }

    /// Record a write event.
    pub fn record_write(
        &mut self,
        position: MemoryPosition,
        address: u64,
        data: Vec<u8>,
        thread_id: u32,
    ) {
        let byte_count = data.len() as u64;
        let write = MemoryWrite::new(position, address, data, thread_id);
        self.index.insert(write);
        *self.writes_by_thread.entry(thread_id).or_default() += byte_count;
        self.total_write_events += 1;
    }

    /// Reconstruct a memory snapshot of `[base, base+len)` at `pos`.
    ///
    /// Bytes that have never been written will be `None` in the snapshot.
    #[must_use]
    pub fn snapshot_at(&self, base: u64, len: usize, pos: MemoryPosition) -> MemorySnapshot {
        let mut snap = MemorySnapshot::empty(base, len, pos);
        let writes = self.index.writes_to_range_before(base, len as u64, pos);
        for write in writes {
            snap.apply_write(write);
        }
        snap
    }

    /// Return the last write to address `addr` at or before `pos`.
    #[must_use]
    pub fn last_write_to(&self, addr: u64, pos: MemoryPosition) -> Option<&MemoryWrite> {
        self.index.last_write_before(addr, pos)
    }

    /// Return all writes to `[addr, addr+len)` up to and including `pos`.
    #[must_use]
    pub fn writes_to_range_before(
        &self,
        addr: u64,
        len: u64,
        pos: MemoryPosition,
    ) -> Vec<&MemoryWrite> {
        self.index.writes_to_range_before(addr, len, pos)
    }

    /// Compute a change-set between two snapshots of the same region.
    #[must_use]
    pub fn change_set(
        &self,
        base: u64,
        len: usize,
        from_pos: MemoryPosition,
        to_pos: MemoryPosition,
    ) -> MemoryChangeSet {
        let snap_before = self.snapshot_at(base, len, from_pos);
        let snap_after = self.snapshot_at(base, len, to_pos);

        let mut changes = Vec::new();
        for i in 0..len {
            let old_val = snap_before.byte_at(i);
            let new_val = snap_after.byte_at(i);
            if let Some(new_b) = new_val
                && old_val != new_val {
                    changes.push((base + i as u64, old_val, new_b));
                }
        }
        MemoryChangeSet {
            from_position: from_pos,
            to_position: to_pos,
            changes,
        }
    }

    /// Return all write events between two positions.
    #[must_use]
    pub fn writes_between(
        &self,
        from: MemoryPosition,
        to: MemoryPosition,
    ) -> Vec<&MemoryWrite> {
        self.index.writes_in_range(from, to)
    }

    /// Compute write frequency: how many times each address was written.
    #[must_use]
    pub fn write_frequency(&self, from: MemoryPosition, to: MemoryPosition) -> HashMap<u64, usize> {
        let mut freq: HashMap<u64, usize> = HashMap::new();
        let writes = self.writes_between(from, to);
        for w in writes {
            for byte_addr in w.address..w.end_address() {
                *freq.entry(byte_addr).or_default() += 1;
            }
        }
        freq
    }

    /// Find addresses written by more than one thread (potential data races).
    #[must_use]
    pub fn multi_thread_writes(
        &self,
        from: MemoryPosition,
        to: MemoryPosition,
    ) -> Vec<(u64, Vec<u32>)> {
        let mut addr_threads: HashMap<u64, std::collections::HashSet<u32>> = HashMap::new();
        let writes = self.writes_between(from, to);
        for w in writes {
            for byte_addr in w.address..w.end_address() {
                addr_threads.entry(byte_addr).or_default().insert(w.thread_id);
            }
        }
        let mut result: Vec<(u64, Vec<u32>)> = addr_threads
            .into_iter()
            .filter(|(_, threads)| threads.len() > 1)
            .map(|(addr, threads)| {
                let mut t: Vec<u32> = threads.into_iter().collect();
                t.sort_unstable();
                (addr, t)
            })
            .collect();
        result.sort_by_key(|(a, _)| *a);
        result
    }

    /// Total number of write events recorded.
    #[must_use]
    pub const fn total_write_events(&self) -> usize {
        self.total_write_events
    }

    /// Bytes written per thread.
    #[must_use]
    pub const fn bytes_written_by_thread(&self) -> &HashMap<u32, u64> {
        &self.writes_by_thread
    }

    /// Unique addresses that have been written to.
    #[must_use]
    pub fn unique_written_addresses(&self) -> Vec<u64> {
        self.index.unique_written_addresses()
    }

    /// Find all writes that wrote a specific byte sequence (e.g., a magic value).
    #[must_use]
    pub fn find_writes_of_pattern(&self, pattern: &[u8]) -> Vec<&MemoryWrite> {
        let all = self.index.writes_in_range(
            MemoryPosition::new(0, 0),
            MemoryPosition::new(u64::MAX, u32::MAX),
        );
        all.into_iter()
            .filter(|w| {
                w.data.windows(pattern.len()).any(|window| window == pattern)
            })
            .collect()
    }

    /// Return the write timeline for a single address: (position, `byte_value`).
    #[must_use]
    pub fn address_timeline(&self, addr: u64) -> Vec<(MemoryPosition, u8)> {
        let writes = self.index.by_address.get(&addr);
        let Some(writes) = writes else {
            return Vec::new();
        };
        let mut timeline: Vec<(MemoryPosition, u8)> = writes
            .iter()
            .filter_map(|(pos, w)| {
                let byte_off = (addr - w.address) as usize;
                w.data.get(byte_off).map(|&b| (*pos, b))
            })
            .collect();
        timeline.sort_by_key(|(p, _)| *p);
        timeline
    }

    /// Count how many distinct memory regions (non-overlapping) have been written.
    #[must_use]
    pub fn distinct_written_regions(&self) -> usize {
        let mut addrs: Vec<u64> = self.unique_written_addresses();
        addrs.sort_unstable();
        if addrs.is_empty() {
            return 0;
        }
        let mut regions = 1usize;
        for i in 1..addrs.len() {
            if addrs[i] != addrs[i - 1] + 1 {
                regions += 1;
            }
        }
        regions
    }
}

impl Default for TtdMemoryQuery {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for TtdMemoryQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TtdMemoryQuery")
            .field("total_write_events", &self.total_write_events)
            .field(
                "unique_addresses",
                &self.index.unique_written_addresses().len(),
            )
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn pos(seq: u64) -> MemoryPosition {
        MemoryPosition::new(seq, 0)
    }

    #[test]
    fn test_position_ordering() {
        assert!(pos(1) < pos(2));
        let p1 = MemoryPosition::new(1, 5);
        let p2 = MemoryPosition::new(1, 6);
        assert!(p1 < p2);
    }

    #[test]
    fn test_position_prev_next() {
        let p = MemoryPosition::new(5, 3);
        assert_eq!(p.prev(), MemoryPosition::new(5, 2));
        assert_eq!(p.next(), MemoryPosition::new(5, 4));
    }

    #[test]
    fn test_write_overlap() {
        let w = MemoryWrite::new(pos(1), 0x1000, vec![1, 2, 3, 4], 1);
        assert!(w.overlaps(0x1000, 4));
        assert!(w.overlaps(0x1001, 2));
        assert!(!w.overlaps(0x1004, 4));
    }

    #[test]
    fn test_snapshot_empty() {
        let snap = MemorySnapshot::empty(0x1000, 8, pos(0));
        assert_eq!(snap.len(), 8);
        assert_eq!(snap.known_bytes, 0);
        assert!(snap.byte_at(0).is_none());
    }

    #[test]
    fn test_snapshot_apply_write() {
        let mut snap = MemorySnapshot::empty(0x1000, 8, pos(1));
        let w = MemoryWrite::new(pos(1), 0x1002, vec![0xAA, 0xBB], 1);
        snap.apply_write(&w);
        assert!(snap.byte_at(0).is_none());
        assert_eq!(snap.byte_at(2), Some(0xAA));
        assert_eq!(snap.byte_at(3), Some(0xBB));
        assert_eq!(snap.known_bytes, 2);
    }

    #[test]
    fn test_memory_query_snapshot() {
        let mut q = TtdMemoryQuery::new();
        q.record_write(pos(1), 0x1000, vec![1, 2, 3, 4, 5, 6, 7, 8], 1);
        q.record_write(pos(3), 0x1002, vec![0xFF, 0xFF], 1);

        let snap = q.snapshot_at(0x1000, 8, pos(2));
        assert_eq!(snap.byte_at(0), Some(1));
        assert_eq!(snap.byte_at(2), Some(3)); // pos(3) not yet

        let snap2 = q.snapshot_at(0x1000, 8, pos(4));
        assert_eq!(snap2.byte_at(2), Some(0xFF));
        assert_eq!(snap2.byte_at(3), Some(0xFF));
    }

    #[test]
    fn test_change_set() {
        let mut q = TtdMemoryQuery::new();
        q.record_write(pos(1), 0x1000, vec![1, 2, 3, 4], 1);
        q.record_write(pos(5), 0x1001, vec![0x99], 1);

        let cs = q.change_set(0x1000, 4, pos(2), pos(6));
        assert!(!cs.is_empty());
        assert!(cs.changed_addresses().contains(&0x1001));
    }

    #[test]
    fn test_address_timeline() {
        let mut q = TtdMemoryQuery::new();
        q.record_write(pos(1), 0x2000, vec![10], 1);
        q.record_write(pos(5), 0x2000, vec![20], 1);
        q.record_write(pos(9), 0x2000, vec![30], 2);

        let tl = q.address_timeline(0x2000);
        assert_eq!(tl.len(), 3);
        assert_eq!(tl[0].1, 10);
        assert_eq!(tl[2].1, 30);
    }

    #[test]
    fn test_write_frequency() {
        let mut q = TtdMemoryQuery::new();
        q.record_write(pos(1), 0x3000, vec![1, 2], 1);
        q.record_write(pos(2), 0x3000, vec![3, 4], 2);
        q.record_write(pos(3), 0x3001, vec![5], 1);

        let freq = q.write_frequency(pos(0), pos(10));
        assert_eq!(*freq.get(&0x3000).unwrap(), 2);
        assert_eq!(*freq.get(&0x3001).unwrap(), 3);
    }

    #[test]
    fn test_distinct_written_regions() {
        let mut q = TtdMemoryQuery::new();
        q.record_write(pos(1), 0x1000, vec![1, 2, 3], 1);
        q.record_write(pos(2), 0x2000, vec![4, 5], 1);
        assert_eq!(q.distinct_written_regions(), 2);
    }

    #[test]
    fn test_find_writes_of_pattern() {
        let mut q = TtdMemoryQuery::new();
        q.record_write(pos(1), 0x4000, b"MZPE".to_vec(), 1);
        q.record_write(pos(2), 0x5000, b"hello world".to_vec(), 1);

        let hits = q.find_writes_of_pattern(b"MZ");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].address, 0x4000);
    }

    #[test]
    fn test_multi_thread_writes() {
        let mut q = TtdMemoryQuery::new();
        q.record_write(pos(1), 0x6000, vec![1], 1);
        q.record_write(pos(2), 0x6000, vec![2], 2);
        q.record_write(pos(3), 0x7000, vec![3], 1);

        let races = q.multi_thread_writes(pos(0), pos(10));
        assert_eq!(races.len(), 1);
        assert_eq!(races[0].0, 0x6000);
        assert_eq!(races[0].1, vec![1, 2]);
    }
}
