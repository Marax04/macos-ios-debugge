//! Omniscient backward-dataflow query layer (Tier 1, item 1 of
//! `rustre_debug_enhancement_plan.md`).
//!
//! Pernosco's killer feature is "click a wrong value → jump to the instruction
//! that wrote it". This module builds an address-indexed write log on top of
//! [`crate::debug_session_recorder::DebugSessionRecorder`] /
//! [`crate::time_travel_debug`] and answers two queries against it:
//! - [`OmniscientIndex::who_wrote`]: every write event that touched a given
//!   address at or before a given sequence number, most recent first.
//! - [`OmniscientIndex::trace_origin`]: walk backward through the writer chain
//!   for an address, following each write's source (if it copied from another
//!   address) until reaching a write with no known source (e.g. a register
//!   value, syscall result, or the start of the trace).
//!
//! The index is built once from a stream of [`MemoryWrite`] records (produced
//! by a recording backend or replayed from a [`crate::debug_session_recorder::SessionLog`])
//! and answers queries in `O(log n + k)` where `k` is the number of matching
//! writes, via a `BTreeMap<address, Vec<write index>>`.

use std::collections::BTreeMap;

use rustre_core::address::Address;
use serde::{Deserialize, Serialize};

use crate::ThreadId;

/// A single recorded write to memory, with enough provenance to support
/// backward dataflow queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryWrite {
    /// Sequence number in the recorded trace (matches
    /// [`crate::debug_session_recorder::SessionLogEntry::sequence`] when built
    /// from a session log).
    pub sequence: u64,
    /// Address written to.
    pub address: Address,
    /// Number of bytes written.
    pub size: u64,
    /// Thread that performed the write.
    pub tid: ThreadId,
    /// Instruction pointer of the writing instruction, if known.
    pub writer_pc: Option<Address>,
    /// If this write's value was copied verbatim from another memory
    /// address (e.g. a `mov [dst], [src]`-style transfer), the source
    /// address — enables [`OmniscientIndex::trace_origin`] to walk further
    /// back through the chain.
    pub source_address: Option<Address>,
}

impl MemoryWrite {
    /// Returns `true` if `addr` falls within `[address, address + size)`.
    #[must_use]
    /// The end is never materialised: `start + size` saturates at `u64::MAX`,
    /// which an EXCLUSIVE upper bound then excludes, losing the last byte of the
    /// address space. Comparing the offset is exact everywhere and cannot
    /// overflow after the lower-bound check. Third and fourth site of the shape
    /// first corrected in iter 273.
    
    pub const fn covers(&self, addr: Address) -> bool {
        let start = self.address.as_u64();
        let a = addr.as_u64();
        a >= start && a - start < self.size
    }
}

/// Why a [`OmniscientIndex::trace_origin_full`] walk stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OriginEnd {
    /// A write with no recorded source: the true origin of the value.
    Origin,
    /// No write to that address before that time — the value predates the
    /// recording, or was never written by anything this index saw.
    NoEarlierWriter,
    /// The walk hit [`MAX_ORIGIN_CHAIN`]. The last hop is NOT the origin.
    LimitReached,
}

/// A provenance chain and the reason it ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginTrace {
    /// The hops walked, most recent first.
    pub hops: Vec<OriginHop>,
    /// Why the walk stopped.
    pub end: OriginEnd,
}

impl OriginTrace {
    /// Whether the last hop is the value's true origin.
    ///
    /// `false` means the answer is a partial chain: reading its tail as "this
    /// is where the value came from" would be wrong.
    #[must_use]
    pub const fn reached_origin(&self) -> bool {
        matches!(self.end, OriginEnd::Origin)
    }
}

/// One hop in a [`OmniscientIndex::trace_origin`] result: the write that
/// produced the value at a given point, plus whether the chain continues.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginHop {
    /// The write responsible for the value at this point in the chain.
    pub write: MemoryWrite,
    /// The address queried to reach this hop.
    pub queried_address: Address,
}

/// Address-indexed write log supporting omniscient backward-dataflow queries.
#[derive(Debug, Default)]
pub struct OmniscientIndex {
    /// All writes in recording order.
    writes: Vec<MemoryWrite>,
    /// `address -> indices into `writes`` for exact-address writes, used to
    /// accelerate the common case of a single-byte-granularity or exactly
    /// aligned lookup. Range-covering writes (size > 1 whose start doesn't
    /// equal the queried address) are still found by the fallback scan in
    /// `who_wrote`, so this index is an optimization, not a correctness
    /// requirement.
    by_address: BTreeMap<u64, Vec<usize>>,
}

/// Maximum chain length walked by [`OmniscientIndex::trace_origin`] before
/// giving up — guards against cycles in malformed/adversarial input.
const MAX_ORIGIN_CHAIN: usize = 4096;

impl OmniscientIndex {
    /// Create an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build an index from an ordered sequence of writes.
    #[must_use]
    pub fn from_writes(writes: Vec<MemoryWrite>) -> Self {
        let mut idx = Self::new();
        for w in writes {
            idx.push(w);
        }
        idx
    }

    /// Record one more write, keeping the index up to date.
    pub fn push(&mut self, write: MemoryWrite) {
        let i = self.writes.len();
        self.by_address.entry(write.address.as_u64()).or_default().push(i);
        self.writes.push(write);
    }

    /// Total number of indexed writes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.writes.len()
    }

    /// All indexed writes in recording order — lets callers snapshot the log
    /// (e.g. to rebuild an index elsewhere or feed root-cause/dataflow queries).
    #[must_use]
    pub fn writes(&self) -> &[MemoryWrite] {
        &self.writes
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }

    /// `who_wrote(address, at_time)` — every write that touched `address` at
    /// or before sequence number `at_time`, most-recent-first.
    ///
    /// This is the core Pernosco-style query: given a wrong value observed at
    /// `address` at time `at_time`, the first element of the returned vector
    /// is the instruction that last wrote it.
    #[must_use]
    pub fn who_wrote(&self, address: Address, at_time: u64) -> Vec<&MemoryWrite> {
        // Fast path: writes whose start address exactly matches, via the
        // address index. Slow path: multi-byte writes that *cover* `address`
        // without starting at it still need a full scan; skip writes already
        // found by the fast path to avoid duplicates.
        let exact: Vec<usize> = self
            .by_address
            .get(&address.as_u64())
            .cloned()
            .unwrap_or_default();
        let mut hits: Vec<&MemoryWrite> = exact
            .iter()
            .map(|&i| &self.writes[i])
            .filter(|w| w.sequence <= at_time)
            .collect();
        for (i, write) in self.writes.iter().enumerate() {
            if exact.contains(&i) {
                continue;
            }
            if write.sequence <= at_time && write.size > 1 && write.covers(address) {
                hits.push(write);
            }
        }
        hits.sort_by_key(|b| std::cmp::Reverse(b.sequence));
        hits
    }

    /// The single most recent writer of `address` at or before `at_time`, if
    /// any — convenience wrapper around [`Self::who_wrote`].
    #[must_use]
    pub fn last_writer(&self, address: Address, at_time: u64) -> Option<&MemoryWrite> {
        self.who_wrote(address, at_time).into_iter().next()
    }

    /// Walk backward through the writer chain for `address` starting at
    /// `at_time`: find the last writer, then if that write copied its value
    /// from another address, find *that* address's last writer before the
    /// copy, and so on, until a write with no known source is reached (the
    /// true origin) or the chain exceeds [`MAX_ORIGIN_CHAIN`] hops.
    #[must_use]
    pub fn trace_origin(&self, address: Address, at_time: u64) -> Vec<OriginHop> {
        self.trace_origin_full(address, at_time).hops
    }

    /// [`Self::trace_origin`], plus WHY the walk stopped.
    ///
    /// The plain version returns only the hops, so a chain cut at
    /// [`MAX_ORIGIN_CHAIN`] is indistinguishable from one that reached a real
    /// origin: the last hop reads as "this is where the value came from" when
    /// the truth is "I stopped looking". For a provenance query that is the
    /// whole answer being wrong, not a detail — so the reason is now
    /// available.
    #[must_use]
    pub fn trace_origin_full(&self, address: Address, at_time: u64) -> OriginTrace {
        let mut hops = Vec::new();
        let mut cur_addr = address;
        let mut cur_time = at_time;
        let mut end = OriginEnd::LimitReached;

        for _ in 0..MAX_ORIGIN_CHAIN {
            let Some(w) = self.last_writer(cur_addr, cur_time) else {
                end = OriginEnd::NoEarlierWriter;
                break;
            };
            hops.push(OriginHop {
                write: w.clone(),
                queried_address: cur_addr,
            });
            let Some(src) = w.source_address else {
                end = OriginEnd::Origin;
                break;
            };
            // Continue STRICTLY before this write. At sequence 0 there is no
            // such time: `saturating_sub(1)` stayed at 0, so the next lookup
            // could re-find this very write and the walk repeated the same hop
            // until the limit — 4096 copies of one write, presented as a
            // provenance chain. Nothing precedes the first write in a trace,
            // so the honest answer is that the chain ends here.
            let Some(prev_time) = w.sequence.checked_sub(1) else {
                end = OriginEnd::NoEarlierWriter;
                break;
            };
            cur_time = prev_time;
            cur_addr = src;
        }
        OriginTrace { hops, end }
    }

    /// All distinct addresses that have at least one write in this index.
    #[must_use]
    pub fn all_addresses(&self) -> Vec<Address> {
        self.by_address
            .keys()
            .copied()
            .map(Address)
            .collect()
    }

    /// All writes performed by a given thread, in recording order.
    #[must_use]
    pub fn writes_by_thread(&self, tid: ThreadId) -> Vec<&MemoryWrite> {
        self.writes.iter().filter(|w| w.tid == tid).collect()
    }

    /// All writes whose `writer_pc` matches `pc` — "who writes through this
    /// instruction across the whole recording".
    #[must_use]
    pub fn writes_from_pc(&self, pc: Address) -> Vec<&MemoryWrite> {
        self.writes.iter().filter(|w| w.writer_pc == Some(pc)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tid() -> ThreadId {
        ThreadId(1)
    }

    fn w(seq: u64, addr: u64, size: u64, pc: u64, src: Option<u64>) -> MemoryWrite {
        MemoryWrite {
            sequence: seq,
            address: Address::new(addr),
            size,
            tid: tid(),
            writer_pc: Some(Address::new(pc)),
            source_address: src.map(Address::new),
        }
    }

    #[test]
    fn covers_checks_range() {
        let write = w(0, 0x1000, 4, 0x0040_0000, None);
        assert!(write.covers(Address::new(0x1000)));
        assert!(write.covers(Address::new(0x1003)));
        assert!(!write.covers(Address::new(0x1004)));
        assert!(!write.covers(Address::new(0x0fff)));
    }

    #[test]
    fn who_wrote_returns_most_recent_first() {
        let idx = OmniscientIndex::from_writes(vec![
            w(0, 0x1000, 8, 0x0040_1000, None),
            w(5, 0x1000, 8, 0x0040_1010, None),
            w(10, 0x1000, 8, 0x0040_1020, None),
        ]);
        let hits = idx.who_wrote(Address::new(0x1000), 100);
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0].sequence, 10);
        assert_eq!(hits[1].sequence, 5);
        assert_eq!(hits[2].sequence, 0);
    }

    #[test]
    fn who_wrote_respects_at_time_cutoff() {
        let idx = OmniscientIndex::from_writes(vec![
            w(0, 0x1000, 8, 0x0040_1000, None),
            w(5, 0x1000, 8, 0x0040_1010, None),
            w(10, 0x1000, 8, 0x0040_1020, None),
        ]);
        let hits = idx.who_wrote(Address::new(0x1000), 5);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].sequence, 5);
    }

    #[test]
    fn who_wrote_range_covering_write() {
        let idx = OmniscientIndex::from_writes(vec![w(0, 0x2000, 16, 0x0040_1000, None)]);
        let hits = idx.who_wrote(Address::new(0x2008), 100);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].address, Address::new(0x2000));
    }

    #[test]
    fn who_wrote_empty_when_no_writer() {
        let idx = OmniscientIndex::from_writes(vec![w(0, 0x1000, 8, 0x0040_1000, None)]);
        assert!(idx.who_wrote(Address::new(0x9999), 100).is_empty());
    }

    #[test]
    fn last_writer_is_most_recent() {
        let idx = OmniscientIndex::from_writes(vec![
            w(0, 0x1000, 8, 0x0040_1000, None),
            w(5, 0x1000, 8, 0x0040_1010, None),
        ]);
        let lw = idx.last_writer(Address::new(0x1000), 100).unwrap();
        assert_eq!(lw.sequence, 5);
    }

    #[test]
    fn trace_origin_follows_copy_chain() {
        // seq 0: 0x3000 written directly (e.g. from a register — true origin)
        // seq 4: 0x2000 <- copy of 0x3000
        // seq 8: 0x1000 <- copy of 0x2000
        let idx = OmniscientIndex::from_writes(vec![
            w(0, 0x3000, 8, 0x0040_1000, None),
            w(4, 0x2000, 8, 0x0040_1010, Some(0x3000)),
            w(8, 0x1000, 8, 0x0040_1020, Some(0x2000)),
        ]);
        let hops = idx.trace_origin(Address::new(0x1000), 100);
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[0].write.sequence, 8);
        assert_eq!(hops[0].queried_address, Address::new(0x1000));
        assert_eq!(hops[1].write.sequence, 4);
        assert_eq!(hops[1].queried_address, Address::new(0x2000));
        assert_eq!(hops[2].write.sequence, 0);
        assert_eq!(hops[2].queried_address, Address::new(0x3000));
        // final hop has no source: true origin reached.
        assert!(hops[2].write.source_address.is_none());
    }

    #[test]
    fn trace_origin_stops_when_no_writer_found() {
        let idx = OmniscientIndex::from_writes(vec![]);
        let hops = idx.trace_origin(Address::new(0x1000), 100);
        assert!(hops.is_empty());
    }

    #[test]
    fn trace_origin_single_hop_no_source() {
        let idx = OmniscientIndex::from_writes(vec![w(0, 0x1000, 8, 0x0040_1000, None)]);
        let hops = idx.trace_origin(Address::new(0x1000), 100);
        assert_eq!(hops.len(), 1);
        assert!(hops[0].write.source_address.is_none());
    }

    #[test]
    fn trace_origin_does_not_loop_forever_on_self_reference() {
        // Pathological: a write claims to source from its own address at an
        // earlier time than itself is impossible via `saturating_sub`, but
        // guard against A<-B<-A cycles terminating via the strict time cutoff.
        let idx = OmniscientIndex::from_writes(vec![
            w(0, 0x1000, 8, 0x0040_1000, Some(0x2000)),
            w(1, 0x2000, 8, 0x0040_1010, Some(0x1000)),
        ]);
        let hops = idx.trace_origin(Address::new(0x2000), 100);
        // seq1 (0x2000<-0x1000) -> search 0x1000 before seq1 -> seq0 (0x1000<-0x2000)
        // -> search 0x2000 before seq0 -> none found. Terminates, doesn't hang.
        assert!(hops.len() <= 2);
    }

    #[test]
    fn writes_by_thread_filters() {
        let mut w0 = w(0, 0x1000, 8, 0x0040_1000, None);
        w0.tid = ThreadId(1);
        let mut w1 = w(1, 0x1000, 8, 0x0040_1000, None);
        w1.tid = ThreadId(2);
        let idx = OmniscientIndex::from_writes(vec![w0, w1]);
        assert_eq!(idx.writes_by_thread(ThreadId(1)).len(), 1);
        assert_eq!(idx.writes_by_thread(ThreadId(2)).len(), 1);
    }

    #[test]
    fn writes_from_pc_filters() {
        let idx = OmniscientIndex::from_writes(vec![
            w(0, 0x1000, 8, 0x0040_1000, None),
            w(1, 0x1008, 8, 0x0040_1000, None),
            w(2, 0x1010, 8, 0x0040_1999, None),
        ]);
        assert_eq!(idx.writes_from_pc(Address::new(0x0040_1000)).len(), 2);
        assert_eq!(idx.writes_from_pc(Address::new(0x0040_1999)).len(), 1);
    }

    #[test]
    fn push_incrementally_builds_index() {
        let mut idx = OmniscientIndex::new();
        assert!(idx.is_empty());
        idx.push(w(0, 0x1000, 8, 0x0040_1000, None));
        idx.push(w(1, 0x1000, 8, 0x0040_1010, None));
        assert_eq!(idx.len(), 2);
        assert_eq!(idx.last_writer(Address::new(0x1000), 100).unwrap().sequence, 1);
    }

    /// The very first write in a trace cannot have a predecessor, and the walk
    /// must say so instead of re-finding itself.
    ///
    /// The step back was `sequence.saturating_sub(1)`, which at sequence 0
    /// stays at 0 - so the next lookup found the SAME write again, and the
    /// chain repeated one hop until the 4096-hop limit. Four thousand copies of
    /// a single write, returned as a provenance chain.
    #[test]
    fn a_write_at_sequence_zero_does_not_trace_back_into_itself() {
        // A self-referential first write: x = f(x), recorded at sequence 0.
        let idx = OmniscientIndex::from_writes(vec![w(0, 0x1000, 8, 0x0040_1000, Some(0x1000))]);
        let trace = idx.trace_origin_full(Address(0x1000), 10);
        assert_eq!(trace.hops.len(), 1, "one write can only produce one hop, not {} copies of itself", trace.hops.len());
        assert_eq!(trace.end, OriginEnd::NoEarlierWriter);
        assert!(!trace.reached_origin(), "nothing proved this is where the value came from");
    }

    /// A chain cut at the limit must not read as a completed one.
    ///
    /// `trace_origin` returns only the hops, so the tail of a truncated chain
    /// looks exactly like a true origin: "this is where the value came from",
    /// when the truth is "I stopped looking". For a provenance query that is
    /// the whole answer being wrong.
    #[test]
    fn a_truncated_origin_chain_is_reported_as_truncated() {
        // A long chain: each write copies from the address one below it.
        let mut writes = Vec::new();
        for i in 0..(MAX_ORIGIN_CHAIN as u64 + 50) {
            let addr = 0x1000 + i * 8;
            let src = if i == 0 { None } else { Some(addr - 8) };
            writes.push(w(i, addr, 8, 0x0040_1000 + i, src));
        }
        writes.reverse();
        let idx = OmniscientIndex::from_writes(writes);
        let top = 0x1000 + (MAX_ORIGIN_CHAIN as u64 + 49) * 8;
        let trace = idx.trace_origin_full(Address(top), u64::MAX);
        assert_eq!(trace.hops.len(), MAX_ORIGIN_CHAIN);
        assert_eq!(trace.end, OriginEnd::LimitReached);
        assert!(!trace.reached_origin(), "the walk gave up; it did not find the origin");

        // And a chain that DOES reach its origin says so - otherwise the flag
        // would be a constant.
        let short = OmniscientIndex::from_writes(vec![
            w(1, 0x2000, 8, 0x0040_1000, None),
            w(2, 0x2008, 8, 0x0040_1008, Some(0x2000)),
        ]);
        let trace = short.trace_origin_full(Address(0x2008), 10);
        assert_eq!(trace.hops.len(), 2);
        assert_eq!(trace.end, OriginEnd::Origin);
        assert!(trace.reached_origin());
    }

}
