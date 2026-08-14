//! `memory_access_navigator` — Navigate memory accesses in execution traces.
//!
//! Provides [`MemoryAccessNavigator`] which indexes all read and write operations
//! across an execution trace, supports range queries, value reconstruction, and
//! navigation to the next/previous access to any address.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Range;

use serde::{Deserialize, Serialize};

use crate::{AccessKind, Address, ExecutionTrace, bytes_to_u64};

// ─── MemAccess ───────────────────────────────────────────────────────────────

/// A single memory access record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemAccess {
    /// Trace index of the instruction that performed this access.
    pub trace_idx: usize,
    /// Address accessed.
    pub addr: Address,
    /// Size of the access in bytes.
    pub size: usize,
    /// Whether this was a read or write.
    pub kind: AccessKind,
    /// Value written (for writes). Zero for reads.
    pub value: u64,
    /// PC of the instruction that performed the access.
    pub insn_addr: Address,
    /// Thread ID.
    pub tid: u32,
}

impl MemAccess {
    /// Whether this access is a write.
    #[must_use]
    pub const fn is_write(&self) -> bool {
        matches!(self.kind, AccessKind::Write)
    }

    /// Whether this access is a read.
    #[must_use]
    pub const fn is_read(&self) -> bool {
        matches!(self.kind, AccessKind::Read)
    }

    /// Human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        match self.kind {
            AccessKind::Write => format!(
                "[{}] WRITE 0x{:x} ← 0x{:x} ({} bytes) @ pc=0x{:x}",
                self.trace_idx, self.addr, self.value, self.size, self.insn_addr
            ),
            AccessKind::Read => format!(
                "[{}] READ  0x{:x} ({} bytes) @ pc=0x{:x}",
                self.trace_idx, self.addr, self.size, self.insn_addr
            ),
        }
    }
}

impl std::fmt::Display for MemAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ─── AccessPattern ───────────────────────────────────────────────────────────

/// Characterises the access pattern to a memory address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPattern {
    /// The monitored address.
    pub addr: Address,
    /// Total number of reads.
    pub read_count: usize,
    /// Total number of writes.
    pub write_count: usize,
    /// Distinct values written.
    pub distinct_values: HashSet<u64>,
    /// First access trace index.
    pub first_access_idx: Option<usize>,
    /// Last access trace index.
    pub last_access_idx: Option<usize>,
    /// All trace indices of accesses, in order.
    pub access_indices: Vec<usize>,
}

impl AccessPattern {
    /// Whether this address was only ever read (never written).
    #[must_use]
    pub const fn read_only(&self) -> bool {
        self.write_count == 0 && self.read_count > 0
    }

    /// Whether this address was only ever written (never read).
    #[must_use]
    pub const fn write_only(&self) -> bool {
        self.read_count == 0 && self.write_count > 0
    }

    /// Whether this address had both reads and writes.
    #[must_use]
    pub const fn read_write(&self) -> bool {
        self.read_count > 0 && self.write_count > 0
    }

    /// Number of distinct values written to this address.
    #[must_use]
    pub fn value_change_count(&self) -> usize {
        self.distinct_values.len()
    }
}

// ─── MemoryRange ─────────────────────────────────────────────────────────────

/// A contiguous range of memory addresses to monitor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRange {
    /// First address in the range (inclusive).
    pub start: Address,
    /// One past the last address (exclusive).
    pub end: Address,
    /// Optional label.
    pub label: Option<String>,
}

impl MemoryRange {
    /// Create a new range.
    #[must_use]
    pub const fn new(start: Address, end: Address) -> Self {
        Self {
            start,
            end,
            label: None,
        }
    }

    /// Create a named range.
    #[must_use]
    pub fn named(start: Address, end: Address, label: impl Into<String>) -> Self {
        Self {
            start,
            end,
            label: Some(label.into()),
        }
    }

    /// Whether `addr` falls within this range.
    #[must_use]
    pub const fn contains(&self, addr: Address) -> bool {
        addr >= self.start && addr < self.end
    }

    /// Length in bytes.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Whether this is an empty range.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.end <= self.start
    }
}

// ─── MemoryAccessNavigator ───────────────────────────────────────────────────

/// Navigates memory accesses in an execution trace.
///
/// Provides:
/// - Timeline of all accesses to a single address
/// - Value reconstruction at any trace index
/// - Range queries (all accesses within an address range)
/// - Navigation to the next/previous access to an address
/// - Access frequency and pattern analysis
/// - Monitored ranges with labelling
pub struct MemoryAccessNavigator {
    /// All individual accesses, in trace order.
    all_accesses: Vec<MemAccess>,
    /// Address → sorted list of access indices in `all_accesses`.
    by_addr: BTreeMap<Address, Vec<usize>>,
    /// PC address → sorted list of access indices.
    by_insn: HashMap<Address, Vec<usize>>,
    /// Monitored ranges.
    monitored: Vec<MemoryRange>,
    /// Total trace length.
    trace_len: usize,
}

impl MemoryAccessNavigator {
    /// Build a navigator from an execution trace.
    #[must_use]
    pub fn build(trace: &ExecutionTrace) -> Self {
        let mut all_accesses: Vec<MemAccess> = Vec::new();
        let mut by_addr: BTreeMap<Address, Vec<usize>> = BTreeMap::new();
        let mut by_insn: HashMap<Address, Vec<usize>> = HashMap::new();

        for entry in &trace.entries {
            for (addr, bytes) in &entry.mem_writes {
                let value = bytes_to_u64(bytes);
                let idx = all_accesses.len();
                all_accesses.push(MemAccess {
                    trace_idx: entry.idx,
                    addr: *addr,
                    size: bytes.len(),
                    kind: AccessKind::Write,
                    value,
                    insn_addr: entry.pc,
                    tid: entry.tid,
                });
                by_addr.entry(*addr).or_default().push(idx);
                by_insn.entry(entry.pc).or_default().push(idx);
            }
            for (addr, size) in &entry.mem_reads {
                let idx = all_accesses.len();
                all_accesses.push(MemAccess {
                    trace_idx: entry.idx,
                    addr: *addr,
                    size: *size as usize,
                    kind: AccessKind::Read,
                    value: 0,
                    insn_addr: entry.pc,
                    tid: entry.tid,
                });
                by_addr.entry(*addr).or_default().push(idx);
                by_insn.entry(entry.pc).or_default().push(idx);
            }
        }

        Self {
            all_accesses,
            by_addr,
            by_insn,
            monitored: Vec::new(),
            trace_len: trace.len(),
        }
    }

    /// Total number of trace entries this navigator was built over.
    #[must_use]
    pub const fn trace_len(&self) -> usize {
        self.trace_len
    }

    // ── Basic timeline queries ─────────────────────────────────────────────

    /// All accesses to `addr` in trace order.
    #[must_use]
    pub fn accesses_to(&self, addr: Address) -> Vec<&MemAccess> {
        self.by_addr
            .get(&addr)
            .map(|idxs| idxs.iter().map(|&i| &self.all_accesses[i]).collect())
            .unwrap_or_default()
    }

    /// All write accesses to `addr`.
    #[must_use]
    pub fn writes_to(&self, addr: Address) -> Vec<&MemAccess> {
        self.accesses_to(addr)
            .into_iter()
            .filter(|a| a.is_write())
            .collect()
    }

    /// All read accesses to `addr`.
    #[must_use]
    pub fn reads_from(&self, addr: Address) -> Vec<&MemAccess> {
        self.accesses_to(addr)
            .into_iter()
            .filter(|a| a.is_read())
            .collect()
    }

    /// Reconstruct the value at `addr` just before trace index `at_idx`.
    /// Returns the most recent write at or before `at_idx`.
    #[must_use]
    pub fn value_at(&self, addr: Address, at_idx: usize) -> Option<u64> {
        self.writes_to(addr)
            .into_iter()
            .rev()
            .find(|a| a.trace_idx <= at_idx)
            .map(|a| a.value)
    }

    // ── Navigation ─────────────────────────────────────────────────────────

    /// Find the next access (read or write) to `addr` after trace index `after_idx`.
    #[must_use]
    pub fn next_access_after(&self, addr: Address, after_idx: usize) -> Option<&MemAccess> {
        self.accesses_to(addr)
            .into_iter()
            .find(|a| a.trace_idx > after_idx)
    }

    /// Find the previous access (read or write) to `addr` before `before_idx`.
    #[must_use]
    pub fn prev_access_before(&self, addr: Address, before_idx: usize) -> Option<&MemAccess> {
        self.accesses_to(addr)
            .into_iter()
            .rev()
            .find(|a| a.trace_idx < before_idx)
    }

    /// Find the next write to `addr` after `after_idx`.
    #[must_use]
    pub fn next_write_after(&self, addr: Address, after_idx: usize) -> Option<&MemAccess> {
        self.writes_to(addr)
            .into_iter()
            .find(|a| a.trace_idx > after_idx)
    }

    /// Find the previous write to `addr` before `before_idx`.
    #[must_use]
    pub fn prev_write_before(&self, addr: Address, before_idx: usize) -> Option<&MemAccess> {
        self.writes_to(addr)
            .into_iter()
            .rev()
            .find(|a| a.trace_idx < before_idx)
    }

    /// Find the first trace index where `addr` was written with `value`.
    #[must_use]
    pub fn find_first_write_of_value(&self, addr: Address, value: u64) -> Option<usize> {
        self.writes_to(addr)
            .into_iter()
            .find(|a| a.value == value)
            .map(|a| a.trace_idx)
    }

    /// Find the last trace index where `addr` was written with `value`.
    #[must_use]
    pub fn find_last_write_of_value(&self, addr: Address, value: u64) -> Option<usize> {
        self.writes_to(addr)
            .into_iter()
            .rev()
            .find(|a| a.value == value)
            .map(|a| a.trace_idx)
    }

    // ── Range queries ──────────────────────────────────────────────────────

    /// All accesses whose address falls within `[start, end)`.
    #[must_use]
    pub fn accesses_in_range(&self, start: Address, end: Address) -> Vec<&MemAccess> {
        self.by_addr
            .range(start..end)
            .flat_map(|(_, idxs)| idxs.iter().map(|&i| &self.all_accesses[i]))
            .collect()
    }

    /// All addresses that were accessed within a trace index range.
    #[must_use]
    pub fn addresses_accessed_between(&self, range: Range<usize>) -> HashSet<Address> {
        self.all_accesses
            .iter()
            .filter(|a| range.contains(&a.trace_idx))
            .map(|a| a.addr)
            .collect()
    }

    /// All accesses performed by the instruction at `insn_addr`.
    #[must_use]
    pub fn accesses_by_insn(&self, insn_addr: Address) -> Vec<&MemAccess> {
        self.by_insn
            .get(&insn_addr)
            .map(|idxs| idxs.iter().map(|&i| &self.all_accesses[i]).collect())
            .unwrap_or_default()
    }

    // ── Pattern analysis ───────────────────────────────────────────────────

    /// Compute the [`AccessPattern`] for `addr`.
    #[must_use]
    pub fn pattern_for(&self, addr: Address) -> AccessPattern {
        let accesses = self.accesses_to(addr);
        let read_count = accesses.iter().filter(|a| a.is_read()).count();
        let write_count = accesses.iter().filter(|a| a.is_write()).count();
        let distinct_values: HashSet<u64> = accesses
            .iter()
            .filter(|a| a.is_write())
            .map(|a| a.value)
            .collect();
        let first_access_idx = accesses.first().map(|a| a.trace_idx);
        let last_access_idx = accesses.last().map(|a| a.trace_idx);
        let access_indices: Vec<usize> = accesses.iter().map(|a| a.trace_idx).collect();
        AccessPattern {
            addr,
            read_count,
            write_count,
            distinct_values,
            first_access_idx,
            last_access_idx,
            access_indices,
        }
    }

    /// Find addresses with the most accesses (hot spots).
    #[must_use]
    pub fn hot_addresses(&self, top_n: usize) -> Vec<(Address, usize)> {
        let mut counts: Vec<(Address, usize)> = self
            .by_addr
            .iter()
            .map(|(addr, idxs)| (*addr, idxs.len()))
            .collect();
        counts.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        counts.truncate(top_n);
        counts
    }

    /// Find addresses that were both read and written (potential UAF / race spots).
    #[must_use]
    pub fn read_write_addresses(&self) -> Vec<Address> {
        self.by_addr
            .iter()
            .filter(|(_, idxs)| {
                let has_read = idxs.iter().any(|&i| self.all_accesses[i].is_read());
                let has_write = idxs.iter().any(|&i| self.all_accesses[i].is_write());
                has_read && has_write
            })
            .map(|(addr, _)| *addr)
            .collect()
    }

    /// Find addresses written more than once with different values.
    #[must_use]
    pub fn mutated_addresses(&self) -> Vec<(Address, usize)> {
        self.by_addr
            .iter()
            .filter_map(|(addr, idxs)| {
                let values: HashSet<u64> = idxs
                    .iter()
                    .filter(|&&i| self.all_accesses[i].is_write())
                    .map(|&i| self.all_accesses[i].value)
                    .collect();
                if values.len() > 1 {
                    Some((*addr, values.len()))
                } else {
                    None
                }
            })
            .collect()
    }

    // ── Monitored ranges ───────────────────────────────────────────────────

    /// Register a memory range to monitor.
    pub fn add_monitored_range(&mut self, range: MemoryRange) {
        self.monitored.push(range);
    }

    /// All accesses that fall within any monitored range.
    #[must_use]
    pub fn accesses_in_monitored_ranges(&self) -> Vec<&MemAccess> {
        self.all_accesses
            .iter()
            .filter(|a| self.monitored.iter().any(|r| r.contains(a.addr)))
            .collect()
    }

    /// Find which monitored range (if any) contains `addr`.
    #[must_use]
    pub fn containing_range(&self, addr: Address) -> Option<&MemoryRange> {
        self.monitored.iter().find(|r| r.contains(addr))
    }

    // ── Statistics ─────────────────────────────────────────────────────────

    /// Total number of memory access records.
    #[must_use]
    pub const fn total_access_count(&self) -> usize {
        self.all_accesses.len()
    }

    /// Number of distinct addresses accessed.
    #[must_use]
    pub fn distinct_address_count(&self) -> usize {
        self.by_addr.len()
    }

    /// Total write count.
    #[must_use]
    pub fn write_count(&self) -> usize {
        self.all_accesses.iter().filter(|a| a.is_write()).count()
    }

    /// Total read count.
    #[must_use]
    pub fn read_count(&self) -> usize {
        self.all_accesses.iter().filter(|a| a.is_read()).count()
    }

    /// All distinct addresses accessed.
    #[must_use]
    pub fn all_accessed_addresses(&self) -> Vec<Address> {
        self.by_addr.keys().copied().collect()
    }

    /// Snapshot of all addresses' most-recent written values at trace index `at_idx`.
    #[must_use]
    pub fn memory_snapshot_at(&self, at_idx: usize) -> HashMap<Address, u64> {
        let mut snap: HashMap<Address, u64> = HashMap::new();
        for a in &self.all_accesses {
            if a.is_write() && a.trace_idx <= at_idx {
                snap.insert(a.addr, a.value);
            }
        }
        snap
    }

    /// All accesses in a given trace index range.
    #[must_use]
    pub fn accesses_in_trace_range(&self, range: Range<usize>) -> Vec<&MemAccess> {
        self.all_accesses
            .iter()
            .filter(|a| range.contains(&a.trace_idx))
            .collect()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TraceBuilder;

    fn build_trace_with_mem() -> ExecutionTrace {
        let mut b = TraceBuilder::new("mem_test");
        b.insn(0x1000, 1, "mov [0x5000], 0x42");
        b.mem_write(0x5000, vec![0x42, 0, 0, 0, 0, 0, 0, 0]);
        b.insn(0x1010, 1, "mov [0x5000], 0xFF");
        b.mem_write(0x5000, vec![0xFF, 0, 0, 0, 0, 0, 0, 0]);
        b.insn(0x1020, 1, "mov rax, [0x5000]");
        b.build()
    }

    #[test]
    fn test_write_count() {
        let trace = build_trace_with_mem();
        let nav = MemoryAccessNavigator::build(&trace);
        assert_eq!(nav.writes_to(0x5000).len(), 2);
    }

    #[test]
    fn test_value_at() {
        let trace = build_trace_with_mem();
        let nav = MemoryAccessNavigator::build(&trace);
        // After first write (trace_idx=0) value should be 0x42
        let v = nav.value_at(0x5000, 0);
        assert_eq!(v, Some(0x42));
        // After second write (trace_idx=1) value should be 0xFF
        let v2 = nav.value_at(0x5000, 1);
        assert_eq!(v2, Some(0xFF));
    }

    #[test]
    fn test_next_write_after() {
        let trace = build_trace_with_mem();
        let nav = MemoryAccessNavigator::build(&trace);
        let next = nav.next_write_after(0x5000, 0);
        assert!(next.is_some());
        assert_eq!(next.unwrap().value, 0xFF);
    }

    #[test]
    fn test_prev_write_before() {
        let trace = build_trace_with_mem();
        let nav = MemoryAccessNavigator::build(&trace);
        let prev = nav.prev_write_before(0x5000, 2);
        assert!(prev.is_some());
    }

    #[test]
    fn test_find_first_write_of_value() {
        let trace = build_trace_with_mem();
        let nav = MemoryAccessNavigator::build(&trace);
        let idx = nav.find_first_write_of_value(0x5000, 0x42);
        assert_eq!(idx, Some(0));
    }

    #[test]
    fn test_find_last_write_of_value() {
        let trace = build_trace_with_mem();
        let nav = MemoryAccessNavigator::build(&trace);
        let idx = nav.find_last_write_of_value(0x5000, 0xFF);
        assert!(idx.is_some());
    }

    #[test]
    fn test_no_access_to_unknown_addr() {
        let trace = build_trace_with_mem();
        let nav = MemoryAccessNavigator::build(&trace);
        assert!(nav.accesses_to(0xDEAD).is_empty());
    }

    #[test]
    fn test_access_pattern() {
        let trace = build_trace_with_mem();
        let nav = MemoryAccessNavigator::build(&trace);
        let pat = nav.pattern_for(0x5000);
        assert_eq!(pat.write_count, 2);
        assert_eq!(pat.value_change_count(), 2);
    }

    #[test]
    fn test_mutated_addresses() {
        let trace = build_trace_with_mem();
        let nav = MemoryAccessNavigator::build(&trace);
        let mutated = nav.mutated_addresses();
        assert!(mutated.iter().any(|(a, _)| *a == 0x5000));
    }

    #[test]
    fn test_hot_addresses() {
        let trace = build_trace_with_mem();
        let nav = MemoryAccessNavigator::build(&trace);
        let hot = nav.hot_addresses(1);
        assert!(!hot.is_empty());
        assert_eq!(hot[0].0, 0x5000);
    }

    #[test]
    fn test_monitored_range() {
        let trace = build_trace_with_mem();
        let mut nav = MemoryAccessNavigator::build(&trace);
        nav.add_monitored_range(MemoryRange::named(0x5000, 0x5100, "heap_buf"));
        let accesses = nav.accesses_in_monitored_ranges();
        assert_eq!(accesses.len(), 2); // two writes
    }

    #[test]
    fn test_memory_snapshot_at() {
        let trace = build_trace_with_mem();
        let nav = MemoryAccessNavigator::build(&trace);
        let snap = nav.memory_snapshot_at(1);
        assert_eq!(snap.get(&0x5000), Some(&0xFF));
    }

    #[test]
    fn test_accesses_in_range() {
        let trace = build_trace_with_mem();
        let nav = MemoryAccessNavigator::build(&trace);
        let accesses = nav.accesses_in_range(0x4000, 0x6000);
        assert_eq!(accesses.len(), 2);
    }

    #[test]
    fn test_distinct_address_count() {
        let trace = build_trace_with_mem();
        let nav = MemoryAccessNavigator::build(&trace);
        assert_eq!(nav.distinct_address_count(), 1);
    }

    #[test]
    fn test_total_access_count() {
        let trace = build_trace_with_mem();
        let nav = MemoryAccessNavigator::build(&trace);
        assert_eq!(nav.total_access_count(), 2);
    }
}
