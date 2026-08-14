//! Execution heatmap/flamegraph over a recorded session or TTD timeline.
//!
//! Aggregates per-address hit counts from a [`crate::debug_session_recorder::SessionLog`](crate::debug_session_recorder::SessionLog)
//! or a TTD [`recent_history`](crate::time_travel_debug::TtdSession::recent_history) sample into a
//! bucketed timeline, so a front-end can render a "hottest addresses over time" heatmap without
//! re-deriving bucket math itself.

use std::collections::BTreeMap;

use rustre_core::address::Address;

use crate::debug_session_recorder::{SessionEvent, SessionLog};
use crate::time_travel_debug::TracePosition;

/// Hit counts for a single time bucket, keyed by address.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HeatmapBucket {
    /// Index of this bucket in the timeline (0-based, chronological).
    pub index: usize,
    /// Total hits across all addresses in this bucket.
    pub total_hits: u64,
    /// Per-address hit counts within this bucket.
    pub address_hits: BTreeMap<u64, u64>,
}

impl HeatmapBucket {
    fn record(&mut self, addr: u64) {
        self.total_hits += 1;
        *self.address_hits.entry(addr).or_insert(0) += 1;
    }

    /// The addresses with the most hits in this bucket, hottest first.
    #[must_use]
    pub fn top_addresses(&self, n: usize) -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> = self.address_hits.iter().map(|(&a, &c)| (a, c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }
}

/// What the buckets of an [`ExecutionHeatmap`] are measured along.
///
/// The two constructors of this type do NOT bucket the same way, and nothing
/// recorded which one had been used: `from_session_log` divides by POSITION in
/// the log (every bucket holds the same number of events), while
/// `from_ttd_history` divides by trace TIME (every bucket spans the same range
/// of sequence numbers, so a quiet stretch produces an empty bucket and a busy
/// one a tall bar). Both are legitimate views and they are not comparable: two
/// heatmaps of the same execution, built by the two constructors, put different
/// addresses in bucket 3 — and a caller placing them side by side, or reading
/// "bucket 3 is the hot one", cannot tell.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HeatmapAxis {
    /// Buckets hold equal COUNTS of events; the x axis is log position.
    #[default]
    EventPosition,
    /// Buckets hold equal SPANS of trace time; the x axis is sequence number.
    TraceTime,
}

/// An execution heatmap: a fixed number of chronological buckets, each holding per-address
/// hit counts, plus a global rollup across the whole timeline.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExecutionHeatmap {
    pub buckets: Vec<HeatmapBucket>,
    pub global_hits: BTreeMap<u64, u64>,
    /// What the buckets are measured along. See [`HeatmapAxis`].
    #[serde(default)]
    pub axis: HeatmapAxis,
}

impl ExecutionHeatmap {
    fn empty(num_buckets: usize, axis: HeatmapAxis) -> Self {
        let buckets = (0..num_buckets.max(1))
            .map(|i| HeatmapBucket { index: i, ..HeatmapBucket::default() })
            .collect();
        Self { buckets, global_hits: BTreeMap::new(), axis }
    }

    /// Whether two heatmaps are measured along the same axis, i.e. whether
    /// their bucket `n`s describe comparable slices of the execution.
    ///
    /// Placing an event-position heatmap next to a trace-time one and reading
    /// off "bucket 3" compares two different things; this is what lets a caller
    /// refuse instead.
    #[must_use]
    pub const fn is_comparable_with(&self, other: &Self) -> bool {
        matches!(
            (self.axis, other.axis),
            (HeatmapAxis::EventPosition, HeatmapAxis::EventPosition)
                | (HeatmapAxis::TraceTime, HeatmapAxis::TraceTime)
        )
    }

    fn record(&mut self, bucket_idx: usize, addr: u64) {
        self.buckets[bucket_idx].record(addr);
        *self.global_hits.entry(addr).or_insert(0) += 1;
    }

    /// Build a heatmap from a session log, bucketing stop-like events (`Stopped`,
    /// `BreakpointHit`, `WatchpointHit`) evenly across `num_buckets` by log position.
    #[must_use]
    pub fn from_session_log(log: &SessionLog, num_buckets: usize) -> Self {
        let stop_addrs: Vec<Address> = log
            .iter()
            .filter_map(|entry| match &entry.event {
                SessionEvent::Stopped { address, .. }
                | SessionEvent::BreakpointHit { address, .. }
                | SessionEvent::WatchpointHit { address, .. } => Some(*address),
                _ => None,
            })
            .collect();

        let mut heatmap = Self::empty(num_buckets, HeatmapAxis::EventPosition);
        if stop_addrs.is_empty() {
            return heatmap;
        }
        let n = stop_addrs.len();
        let buckets = heatmap.buckets.len();
        for (i, addr) in stop_addrs.into_iter().enumerate() {
            let bucket_idx = (i * buckets) / n;
            let bucket_idx = bucket_idx.min(buckets - 1);
            heatmap.record(bucket_idx, addr.0);
        }
        heatmap
    }

    /// Build a heatmap from a TTD position history sample (as returned by
    /// [`TtdSession::recent_history`](crate::time_travel_debug::TtdSession::recent_history)),
    /// bucketing by `TracePosition::sequence` range rather than sample index, so buckets
    /// reflect actual trace time even when history sampling is uneven.
    #[must_use]
    pub fn from_ttd_history(history: &[(TracePosition, u64)], num_buckets: usize) -> Self {
        let mut heatmap = Self::empty(num_buckets, HeatmapAxis::TraceTime);
        if history.is_empty() {
            return heatmap;
        }
        let min_seq = history.iter().map(|(p, _)| p.sequence).min().unwrap_or(0);
        let max_seq = history.iter().map(|(p, _)| p.sequence).max().unwrap_or(0);
        let span = max_seq.saturating_sub(min_seq).max(1);
        let buckets = heatmap.buckets.len() as u64;
        for (pos, pc) in history {
            let offset = pos.sequence.saturating_sub(min_seq);
            let bucket_idx = ((offset * buckets) / (span + 1)).min(buckets - 1) as usize;
            heatmap.record(bucket_idx, *pc);
        }
        heatmap
    }

    /// The globally hottest addresses across the whole timeline, hottest first.
    #[must_use]
    pub fn hottest(&self, n: usize) -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> = self.global_hits.iter().map(|(&a, &c)| (a, c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }

    /// Total hits recorded across every bucket.
    #[must_use]
    pub fn total_hits(&self) -> u64 {
        self.global_hits.values().sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debug_session_recorder::{DebugSessionRecorder, SessionEvent};
    use crate::ThreadId;

    fn recorder_with_stops(addrs: &[u64]) -> DebugSessionRecorder {
        let mut rec = DebugSessionRecorder::default_capacity();
        rec.start();
        for &a in addrs {
            rec.record_always(SessionEvent::Stopped {
                tid: ThreadId(1),
                reason: crate::StopReason::SingleStep { address: Address(a) },
                address: Address(a),
            });
        }
        rec
    }

    #[test]
    fn empty_log_yields_empty_heatmap() {
        let rec = DebugSessionRecorder::default_capacity();
        let heatmap = ExecutionHeatmap::from_session_log(&rec.log, 4);
        assert_eq!(heatmap.buckets.len(), 4);
        assert_eq!(heatmap.total_hits(), 0);
        assert!(heatmap.hottest(5).is_empty());
    }

    #[test]
    fn hits_distribute_across_buckets_in_order() {
        let rec = recorder_with_stops(&[0x1000, 0x1000, 0x2000, 0x3000, 0x3000, 0x3000, 0x4000, 0x4000]);
        let heatmap = ExecutionHeatmap::from_session_log(&rec.log, 4);
        assert_eq!(heatmap.buckets.len(), 4);
        assert_eq!(heatmap.total_hits(), 8);
        // Every recorded stop lands in exactly one bucket.
        let bucketed: u64 = heatmap.buckets.iter().map(|b| b.total_hits).sum();
        assert_eq!(bucketed, 8);
    }

    #[test]
    fn hottest_ranks_by_count_then_address() {
        let rec = recorder_with_stops(&[0x1000, 0x2000, 0x2000, 0x3000, 0x3000, 0x3000]);
        let heatmap = ExecutionHeatmap::from_session_log(&rec.log, 2);
        let hottest = heatmap.hottest(2);
        assert_eq!(hottest, vec![(0x3000, 3), (0x2000, 2)]);
    }

    #[test]
    fn ttd_history_buckets_by_sequence_span() {
        let history = vec![
            (TracePosition::new(0, 0), 0xA),
            (TracePosition::new(0, 5), 0xA),
            (TracePosition::new(5, 0), 0xB),
            (TracePosition::new(10, 0), 0xC),
        ];
        let heatmap = ExecutionHeatmap::from_ttd_history(&history, 2);
        assert_eq!(heatmap.total_hits(), 4);
        assert_eq!(heatmap.global_hits.get(&0xA), Some(&2));
    }

    #[test]
    fn ttd_history_empty_is_empty() {
        let heatmap = ExecutionHeatmap::from_ttd_history(&[], 3);
        assert_eq!(heatmap.buckets.len(), 3);
        assert_eq!(heatmap.total_hits(), 0);
    }

    #[test]
    fn top_addresses_per_bucket() {
        let rec = recorder_with_stops(&[0x10, 0x10, 0x10, 0x20]);
        let heatmap = ExecutionHeatmap::from_session_log(&rec.log, 1);
        let top = heatmap.buckets[0].top_addresses(1);
        assert_eq!(top, vec![(0x10, 3)]);
    }
}

// ── Opt-5: roaring-bitmap tracepoint hit counter ──────────────────────────────
//
// `BTreeMap<u64, u64>` in `HeatmapBucket::address_hits` is O(log n) per
// insert/lookup and has high allocation overhead when tens-of-thousands of
// distinct addresses are hit (e.g. a full-program coverage trace).
//
// For the common case where hit count > 1 is the interesting signal but *which*
// addresses were hit at least once is the primary query, a roaring bitmap gives:
//
// • O(1) amortised `insert` (bit set in a dense or run-length-encoded chunk).
// • 64-bit coverage bitmaps compressed to ~1.5 bytes/element in the dense case,
//   vs. ≥ 24 bytes per `(u64, u64)` in the BTreeMap.
// • `contains` in O(1), `|` (union) in O(min(|A|,|B|)/64).
//
// `TraceHitBitmap` stores addresses as `u32` (the low 32 bits of the VA) which
// covers all common user-space address layouts on x86-64 Windows/Linux where
// the interesting code lives below 4 GiB; images loaded above 4 GiB can use
// the optional `base` field to subtract a page-aligned anchor first.

/// Opt-5: a roaring-bitmap-backed tracepoint hit counter.
///
/// Records which (low-32-bit) addresses have been hit at least once, and
/// the total hit count across all addresses.  When the hit rate is high
/// (≥ 1 hit per 64 addresses) roaring is 10–40× more memory-efficient than
/// `HashMap<u64, u64>`.
#[derive(Debug, Clone, Default)]
pub struct TraceHitBitmap {
    /// Addresses hit at least once, stored as `(addr - base) as u32`.
    pub bitmap: roaring::RoaringBitmap,
    /// Base address subtracted from every VA before storing (page-aligned).
    pub base: u64,
    /// Total number of hits recorded (includes repeated hits at the same addr).
    pub total_hits: u64,
}

impl TraceHitBitmap {
    /// Create a bitmap with `base` as the VA anchor.
    ///
    /// All addresses must satisfy `addr >= base` and
    /// `addr - base < u32::MAX` for correct storage.
    #[must_use]
    pub fn new(base: u64) -> Self {
        Self {
            bitmap: roaring::RoaringBitmap::new(),
            base,
            total_hits: 0,
        }
    }

    /// Record a hit at `addr`.
    ///
    /// Saturates silently if `addr - base >= 2^32`.
    pub fn record(&mut self, addr: u64) {
        self.total_hits += 1;
        let offset = addr.saturating_sub(self.base);
        if let Ok(key) = u32::try_from(offset) {
            self.bitmap.insert(key);
        }
    }

    /// Returns `true` if `addr` has been hit at least once.
    #[must_use]
    pub fn contains(&self, addr: u64) -> bool {
        let offset = addr.saturating_sub(self.base);
        u32::try_from(offset).is_ok_and(|k| self.bitmap.contains(k))
    }

    /// Number of distinct addresses hit.
    #[must_use]
    pub fn distinct_count(&self) -> u64 {
        self.bitmap.len()
    }

    /// Merge another bitmap into this one (union of hit sets, sum of counts).
    pub fn merge(&mut self, other: &Self) {
        self.bitmap |= &other.bitmap;
        self.total_hits += other.total_hits;
    }

    /// Build a `TraceHitBitmap` from a `SessionLog`, recording every
    /// stop/breakpoint/watchpoint hit address.
    #[must_use]
    pub fn from_session_log(
        log: &crate::debug_session_recorder::SessionLog,
        base: u64,
    ) -> Self {
        let mut bm = Self::new(base);
        for entry in log.iter() {
            let addr = match &entry.event {
                crate::debug_session_recorder::SessionEvent::Stopped { address, .. }
                | crate::debug_session_recorder::SessionEvent::BreakpointHit { address, .. }
                | crate::debug_session_recorder::SessionEvent::WatchpointHit { address, .. } => {
                    Some(address.0)
                }
                _ => None,
            };
            if let Some(a) = addr {
                bm.record(a);
            }
        }
        bm
    }
}

#[cfg(test)]
mod bitmap_tests {
    use super::*;
    use crate::debug_session_recorder::{DebugSessionRecorder, SessionEvent};
    use crate::{ThreadId, StopReason};
    use rustre_core::address::Address;

    #[test]
    fn bitmap_record_and_contains() {
        let mut bm = TraceHitBitmap::new(0x1000);
        bm.record(0x1004);
        bm.record(0x1008);
        assert!(bm.contains(0x1004));
        assert!(bm.contains(0x1008));
        assert!(!bm.contains(0x100C));
    }

    #[test]
    fn bitmap_distinct_count() {
        let mut bm = TraceHitBitmap::new(0);
        bm.record(0x10);
        bm.record(0x10); // duplicate — distinct count stays 1
        bm.record(0x20);
        assert_eq!(bm.distinct_count(), 2);
        assert_eq!(bm.total_hits, 3);
    }

    #[test]
    fn bitmap_merge() {
        let mut a = TraceHitBitmap::new(0);
        a.record(0x10);
        let mut b = TraceHitBitmap::new(0);
        b.record(0x10);
        b.record(0x20);
        a.merge(&b);
        assert_eq!(a.distinct_count(), 2);
        assert_eq!(a.total_hits, 3);
    }

    #[test]
    fn bitmap_from_session_log() {
        let mut rec = DebugSessionRecorder::default_capacity();
        rec.start();
        rec.record_always(SessionEvent::Stopped {
            tid: ThreadId(1),
            reason: StopReason::SingleStep { address: Address(0x4000) },
            address: Address(0x4000),
        });
        rec.record_always(SessionEvent::BreakpointHit {
            id: 1,
            tid: ThreadId(1),
            address: Address(0x4010),
        });
        rec.record_always(SessionEvent::Annotation { message: "ignored".into() });

        let bm = TraceHitBitmap::from_session_log(&rec.log, 0x4000);
        assert!(bm.contains(0x4000));
        assert!(bm.contains(0x4010));
        assert_eq!(bm.distinct_count(), 2);
        assert_eq!(bm.total_hits, 2);
    }

    /// The two constructors do not bucket the same way, and the heatmap must
    /// say which one built it.
    ///
    /// `from_session_log` divides by POSITION in the log — every bucket holds
    /// the same number of events. `from_ttd_history` divides by trace TIME —
    /// every bucket spans the same range of sequence numbers, so a quiet
    /// stretch leaves an empty bucket. Both are legitimate; they are not
    /// comparable. Nothing recorded which had been used, so two heatmaps of
    /// the same execution put different addresses in bucket 3 and a caller
    /// reading "bucket 3 is the hot one" had no way to notice.
    #[test]
    fn a_heatmap_records_which_axis_it_was_bucketed_on() {
        // Same execution, seen two ways: three events, the last far in the
        // future of the trace.
        let history = vec![
            (TracePosition::new(0, 0), 0xAAAA),
            (TracePosition::new(1, 0), 0xBBBB),
            (TracePosition::new(100, 0), 0xCCCC),
        ];
        let by_time = ExecutionHeatmap::from_ttd_history(&history, 4);
        assert_eq!(by_time.axis, HeatmapAxis::TraceTime);

        let by_position = ExecutionHeatmap::from_session_log(&SessionLog::new(16), 4);
        assert_eq!(by_position.axis, HeatmapAxis::EventPosition);

        assert!(
            !by_time.is_comparable_with(&by_position),
            "an event-position heatmap and a trace-time one describe different x axes"
        );
        assert!(by_time.is_comparable_with(&by_time));
        assert!(by_position.is_comparable_with(&by_position));

        // And the difference is real, not just a label: bucketed by TIME the
        // two early events share bucket 0 while the far one lands at the end.
        assert_eq!(by_time.buckets[0].total_hits, 2);
        assert_eq!(
            by_time.buckets.last().map(|b| b.total_hits),
            Some(1),
            "a gap in trace time must leave the middle buckets empty"
        );
    }

}
