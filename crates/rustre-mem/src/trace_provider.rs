//! TTD-style replay memory provider with snapshot caching and delta replay.
//!
//! # Overview
//!
//! `TraceMemoryProvider` reads memory state at a specific *trace position*
//! (a monotonically-increasing tick / sequence number).  Memory is stored as a
//! series of `MemorySnapshot` objects, each capturing the full (or differential)
//! memory image at a point in time.
//!
//! ## Key types
//!
//! | Type | Role |
//! |------|------|
//! | [`TracePosition`] | Identifies a point in the trace (tick + sequence) |
//! | [`MemorySnapshot`] | Full memory image at one tick |
//! | [`SnapshotCache`] | LRU cache of decoded snapshots |
//! | [`DeltaReplay`] | Applies a sequence of deltas on top of a base snapshot |
//! | [`TraceMemoryProvider`] | Implements `MemoryProvider` with seek semantics |

use crate::memory_provider::{MemError, MemoryProvider, MemoryRegion, RegionSource, SnapshotId};
use async_trait::async_trait;
use rustre_core::address::{Address, AddressRange};
use rustre_core::permissions::Permissions;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Mutex;

// ─────────────────────────────────────────────────────────────────────────────
// TracePosition
// ─────────────────────────────────────────────────────────────────────────────

/// A position within a recorded execution trace.
///
/// Positions are totally ordered: lower ticks come before higher ticks; within
/// the same tick, lower sequence numbers come first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TracePosition {
    /// Monotonically increasing event tick.
    pub tick: u64,
    /// Sub-tick sequence number (for multiple events at the same tick).
    pub sequence: u32,
}

impl TracePosition {
    /// Create a position at the start of `tick`.
    #[must_use]
    pub const fn at_tick(tick: u64) -> Self {
        Self { tick, sequence: 0 }
    }

    /// Create a position at `tick` and `sequence`.
    #[must_use]
    pub const fn new(tick: u64, sequence: u32) -> Self {
        Self { tick, sequence }
    }

    /// Return the position immediately before this one (at the same tick, seq-1,
    /// or the end of the previous tick).
    #[must_use]
    pub const fn predecessor(&self) -> Option<Self> {
        if self.sequence > 0 {
            Some(Self {
                tick: self.tick,
                sequence: self.sequence - 1,
            })
        } else if self.tick > 0 {
            Some(Self {
                tick: self.tick - 1,
                sequence: u32::MAX,
            })
        } else {
            None
        }
    }
}

impl std::fmt::Display for TracePosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "T{}:{}", self.tick, self.sequence)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryDelta
// ─────────────────────────────────────────────────────────────────────────────

/// A single memory write event in the trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryDelta {
    /// Virtual address of the write.
    pub address: u64,
    /// Bytes written.
    pub data: Vec<u8>,
}

impl MemoryDelta {
    /// Create a delta.
    #[must_use]
    pub const fn new(address: u64, data: Vec<u8>) -> Self {
        Self { address, data }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemorySnapshot
// ─────────────────────────────────────────────────────────────────────────────

/// A full memory image at a trace tick.
///
/// Stores byte contents as a map of `base_address → bytes`.  Permissions and
/// region names are optional per region.
#[derive(Debug, Clone)]
pub struct MemorySnapshot {
    /// The tick this snapshot was captured at.
    pub position: TracePosition,
    /// `base_address → bytes`.
    pub pages: HashMap<u64, Vec<u8>>,
    /// Optional permissions per region.
    pub perms: HashMap<u64, Permissions>,
    /// Optional name labels per region.
    pub names: HashMap<u64, String>,
}

impl MemorySnapshot {
    /// Create an empty snapshot at `position`.
    #[must_use]
    pub fn new(position: TracePosition) -> Self {
        Self {
            position,
            pages: HashMap::new(),
            perms: HashMap::new(),
            names: HashMap::new(),
        }
    }

    /// Convenience: create a snapshot at a pure tick position.
    #[must_use]
    pub fn at_tick(tick: u64) -> Self {
        Self::new(TracePosition::at_tick(tick))
    }

    /// Add a region at `base` with content `data` (read-only).
    pub fn add_region(&mut self, base: u64, data: Vec<u8>) {
        self.pages.insert(base, data);
    }

    /// Add a region with full metadata.
    pub fn add_region_full(
        &mut self,
        base: u64,
        data: Vec<u8>,
        perms: Permissions,
        name: Option<String>,
    ) {
        self.pages.insert(base, data);
        self.perms.insert(base, perms);
        if let Some(n) = name {
            self.names.insert(base, n);
        }
    }

    /// Apply a delta to a mutable clone of this snapshot.
    #[must_use]
    pub fn apply_delta(&self, delta: &MemoryDelta) -> Self {
        let mut cloned = self.clone();
        let addr = delta.address;
        let end = addr.saturating_add(delta.data.len() as u64);
        // Find and update the page(s) that contain this address.
        for (base, bytes) in &mut cloned.pages {
            let page_end = *base + bytes.len() as u64;
            if addr >= page_end || end <= *base {
                continue;
            }
            let copy_start = addr.max(*base);
            let copy_end = end.min(page_end);
            let dst_off = (copy_start - *base) as usize;
            let src_off = (copy_start - addr) as usize;
            let len = (copy_end - copy_start) as usize;
            bytes[dst_off..dst_off + len].copy_from_slice(&delta.data[src_off..src_off + len]);
        }
        cloned
    }

    /// Read `len` bytes at `addr` from this snapshot.
    #[must_use]
    pub fn read_at(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        let end = addr.checked_add(len as u64)?;
        let mut buf = vec![0u8; len];
        let mut filled = false;
        for (base, data) in &self.pages {
            let page_end = base.saturating_add(data.len() as u64);
            if addr >= page_end || end <= *base {
                continue;
            }
            let copy_start = addr.max(*base);
            let copy_end = end.min(page_end);
            let dst_off = (copy_start - addr) as usize;
            let src_off = (copy_start - base) as usize;
            let len2 = (copy_end - copy_start) as usize;
            let actual = len2.min(data.len().saturating_sub(src_off));
            if actual > 0 {
                buf[dst_off..dst_off + actual].copy_from_slice(&data[src_off..src_off + actual]);
                filled = true;
            }
        }
        if filled { Some(buf) } else { None }
    }

    /// Return `MemoryRegion` descriptors for all pages in this snapshot.
    #[must_use]
    pub fn regions(&self) -> Vec<MemoryRegion> {
        self.pages
            .iter()
            .map(|(base, data)| {
                let start = Address::new(*base);
                let end = Address::new(base + data.len() as u64);
                let perms = self.perms.get(base).copied().unwrap_or(Permissions::READ);
                let name = self.names.get(base).cloned();
                MemoryRegion {
                    range: AddressRange::new(start, end),
                    perms,
                    name,
                    source: RegionSource::Reconstructed,
                }
            })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SnapshotCache — LRU cache of decoded snapshots
// ─────────────────────────────────────────────────────────────────────────────

/// LRU cache for `MemorySnapshot` objects.
///
/// Evicts the least-recently-used entry when capacity is exceeded.
pub struct SnapshotCache {
    capacity: usize,
    map: HashMap<TracePosition, MemorySnapshot>,
    order: VecDeque<TracePosition>,
}

impl SnapshotCache {
    /// Create a cache with `capacity` slots.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Insert a snapshot.  If the cache is full, the LRU entry is evicted.
    pub fn insert(&mut self, snap: MemorySnapshot) {
        let pos = snap.position;
        if self.map.contains_key(&pos) {
            // Refresh LRU order.
            self.order.retain(|p| *p != pos);
        } else if self.map.len() >= self.capacity && self.capacity > 0 {
            // Evict LRU.
            if let Some(lru) = self.order.pop_front() {
                self.map.remove(&lru);
            }
        }
        self.map.insert(pos, snap);
        self.order.push_back(pos);
    }

    /// Retrieve a snapshot by position.
    pub fn get(&mut self, pos: &TracePosition) -> Option<&MemorySnapshot> {
        if self.map.contains_key(pos) {
            // Move to MRU.
            self.order.retain(|p| p != pos);
            self.order.push_back(*pos);
            self.map.get(pos)
        } else {
            None
        }
    }

    /// Remove the snapshot at `pos`. Returns `true` if it was present.
    pub fn remove(&mut self, pos: &TracePosition) -> bool {
        if self.map.remove(pos).is_some() {
            self.order.retain(|p| p != pos);
            true
        } else {
            false
        }
    }

    /// Number of cached snapshots.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Return `true` if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Clear all cached entries.
    pub fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }
}

impl std::fmt::Debug for SnapshotCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotCache")
            .field("capacity", &self.capacity)
            .field("len", &self.map.len())
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DeltaReplay
// ─────────────────────────────────────────────────────────────────────────────

/// Applies a sequence of `MemoryDelta` events on top of a base snapshot to
/// reconstruct the memory state at an arbitrary point in the trace.
#[derive(Debug, Default)]
pub struct DeltaReplay {
    /// Base snapshot (tick 0 or last full snapshot).
    base: Option<MemorySnapshot>,
    /// Ordered deltas: `(position, delta)`.
    deltas: BTreeMap<TracePosition, Vec<MemoryDelta>>,
}

impl DeltaReplay {
    /// Create an empty replayer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the base snapshot.
    pub fn set_base(&mut self, snap: MemorySnapshot) {
        self.base = Some(snap);
    }

    /// Append a delta at `position`.
    pub fn push_delta(&mut self, position: TracePosition, delta: MemoryDelta) {
        self.deltas.entry(position).or_default().push(delta);
    }

    /// Reconstruct the memory state at `target`.
    ///
    /// Applies all deltas with position ≤ `target` to the base snapshot.
    /// Returns `None` if no base snapshot is set.
    #[must_use]
    pub fn reconstruct(&self, target: TracePosition) -> Option<MemorySnapshot> {
        let mut state = self.base.as_ref()?.clone();
        for (pos, deltas) in self.deltas.range(..=target) {
            for delta in deltas {
                state = state.apply_delta(delta);
            }
            state.position = *pos;
        }
        Some(state)
    }

    /// Return the earliest position for which delta data is available.
    #[must_use]
    pub fn first_delta_position(&self) -> Option<TracePosition> {
        self.deltas.keys().next().copied()
    }

    /// Return the latest position for which delta data is available.
    #[must_use]
    pub fn last_delta_position(&self) -> Option<TracePosition> {
        self.deltas.keys().next_back().copied()
    }

    /// Total number of delta events.
    #[must_use]
    pub fn delta_count(&self) -> usize {
        self.deltas.values().map(Vec::len).sum()
    }

    /// Clear all deltas (base snapshot is retained).
    pub fn clear_deltas(&mut self) {
        self.deltas.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TraceMemoryProvider
// ─────────────────────────────────────────────────────────────────────────────

/// TTD-style replay memory provider.
///
/// Maintains a list of `MemorySnapshot` checkpoints and a `DeltaReplay` engine.
/// On read, it reconstructs the memory state at `current_position` by:
/// 1. Finding the latest snapshot at or before `current_position`.
/// 2. Applying all deltas between that snapshot's position and `current_position`.
/// 3. Returning bytes from the resulting state.
///
/// An LRU `SnapshotCache` avoids repeated delta replay for frequently-accessed
/// positions.
pub struct TraceMemoryProvider {
    /// All checkpoints sorted ascending by tick.
    snapshots: Vec<MemorySnapshot>,
    /// Delta replay engine for inter-checkpoint reconstruction.
    replayer: DeltaReplay,
    /// LRU cache of reconstructed states (interior mutability so `read(&self, ..)`
    /// can update the cache without unsound `&T → &mut T` casts). `Mutex` is used
    /// rather than `RefCell` so the provider remains `Sync`.
    cache: Mutex<SnapshotCache>,
    /// Current replay position.
    pub current_position: TracePosition,
}

impl TraceMemoryProvider {
    /// Create a provider from a list of full snapshots.
    ///
    /// Snapshots need not be sorted; they will be sorted internally by position.
    #[must_use]
    pub fn from_snapshots(mut snaps: Vec<MemorySnapshot>) -> Self {
        snaps.sort_by_key(|s| s.position);
        let last_pos = snaps
            .last()
            .map_or(TracePosition::at_tick(0), |s| s.position);
        Self {
            snapshots: snaps,
            replayer: DeltaReplay::new(),
            cache: Mutex::new(SnapshotCache::new(16)),
            current_position: last_pos,
        }
    }

    /// Create an empty provider.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            snapshots: Vec::new(),
            replayer: DeltaReplay::new(),
            cache: Mutex::new(SnapshotCache::new(16)),
            current_position: TracePosition::at_tick(0),
        }
    }

    /// Push a full snapshot. Keeps the snapshot list sorted.
    pub fn push_snapshot(&mut self, snap: MemorySnapshot) {
        let pos = snap.position;
        let insert_at = self.snapshots.partition_point(|s| s.position <= pos);
        self.snapshots.insert(insert_at, snap);
    }

    /// Push a delta event at `position`.
    pub fn push_delta(&mut self, position: TracePosition, delta: MemoryDelta) {
        self.replayer.push_delta(position, delta);
    }

    /// Seek to `position`.
    pub const fn seek(&mut self, position: TracePosition) {
        self.current_position = position;
    }

    /// Return the current position.
    #[must_use]
    pub const fn current_position(&self) -> TracePosition {
        self.current_position
    }

    /// Return the earliest recorded position, or `None` if no snapshots exist.
    #[must_use]
    pub fn first_position(&self) -> Option<TracePosition> {
        self.snapshots.first().map(|s| s.position)
    }

    /// Return the latest recorded position.
    #[must_use]
    pub fn last_position(&self) -> Option<TracePosition> {
        self.snapshots.last().map(|s| s.position)
    }

    /// Total number of checkpoints.
    #[must_use]
    pub const fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Total number of delta events.
    #[must_use]
    pub fn delta_count(&self) -> usize {
        self.replayer.delta_count()
    }

    /// Reconstruct the memory state at `position`.
    ///
    /// First checks the `SnapshotCache`.  On a miss, finds the closest preceding
    /// snapshot and applies deltas up to `position`.
    fn reconstruct(&self, position: TracePosition) -> Option<MemorySnapshot> {
        // Cache hit.
        if let Some(snap) = self.cache.lock().unwrap().get(&position).cloned() {
            return Some(snap);
        }
        // Find the latest snapshot at or before `position`.
        let idx = self.snapshots.partition_point(|s| s.position <= position);
        if idx == 0 {
            return None;
        }
        let base = self.snapshots[idx - 1].clone();
        // Apply deltas from base.position to position (inclusive).
        let mut state = base.clone();
        let from = base.position;
        // We only include deltas strictly after the base snapshot up to `position`.
        let range = (
            std::ops::Bound::Excluded(from),
            std::ops::Bound::Included(position),
        );
        for (_, deltas) in self.replayer.deltas.range(range) {
            for delta in deltas {
                state = state.apply_delta(delta);
            }
        }
        state.position = position;
        let result = state.clone();
        self.cache.lock().unwrap().insert(state);
        Some(result)
    }

    /// Invalidate the cache (e.g. after pushing a new snapshot).
    pub fn invalidate_cache(&mut self) {
        self.cache.lock().unwrap().clear();
    }
}

impl std::fmt::Debug for TraceMemoryProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraceMemoryProvider")
            .field("snapshots", &self.snapshots.len())
            .field("position", &self.current_position)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl MemoryProvider for TraceMemoryProvider {
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let snap = self
            .reconstruct(self.current_position)
            .ok_or_else(|| MemError::Other("no snapshot available at current position".into()))?;
        snap.read_at(addr.as_u64(), len)
            .ok_or(MemError::NotMapped(addr))
    }

    fn write(&mut self, _addr: Address, _data: &[u8]) -> Result<(), MemError> {
        Err(MemError::Unsupported)
    }

    fn regions(&self) -> Vec<MemoryRegion> {
        if let Some(snap) = self.reconstruct(self.current_position) {
            snap.regions()
        } else {
            Vec::new()
        }
    }

    fn is_live(&self) -> bool {
        false
    }

    async fn snapshot(&mut self) -> Result<SnapshotId, MemError> {
        Err(MemError::Unsupported)
    }

    async fn restore(&mut self, _id: SnapshotId) -> Result<(), MemError> {
        Err(MemError::Unsupported)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_snap(tick: u64, fill: u8) -> MemorySnapshot {
        let mut s = MemorySnapshot::at_tick(tick);
        s.add_region(0x1000, vec![fill; 0x100]);
        s
    }

    // ── TracePosition ─────────────────────────────────────────────────────────

    #[test]
    fn trace_position_ordering() {
        let a = TracePosition::new(5, 0);
        let b = TracePosition::new(5, 1);
        let c = TracePosition::new(6, 0);
        assert!(a < b);
        assert!(b < c);
        assert!(a < c);
    }

    #[test]
    fn trace_position_predecessor_same_tick() {
        let p = TracePosition::new(5, 3);
        assert_eq!(p.predecessor(), Some(TracePosition::new(5, 2)));
    }

    #[test]
    fn trace_position_predecessor_tick_boundary() {
        let p = TracePosition::at_tick(5);
        assert_eq!(p.predecessor(), Some(TracePosition::new(4, u32::MAX)));
    }

    #[test]
    fn trace_position_predecessor_origin() {
        let p = TracePosition::at_tick(0);
        assert!(p.predecessor().is_none());
    }

    #[test]
    fn trace_position_display() {
        let p = TracePosition::new(3, 7);
        assert_eq!(p.to_string(), "T3:7");
    }

    // ── MemorySnapshot ────────────────────────────────────────────────────────

    #[test]
    fn snapshot_read_at() {
        let mut s = MemorySnapshot::at_tick(0);
        s.add_region(0x1000, vec![0xAA; 4]);
        let data = s.read_at(0x1000, 4).unwrap();
        assert_eq!(data, [0xAA; 4]);
    }

    #[test]
    fn snapshot_read_at_miss() {
        let s = MemorySnapshot::at_tick(0);
        assert!(s.read_at(0xDEAD, 4).is_none());
    }

    #[test]
    fn snapshot_apply_delta() {
        let mut s = MemorySnapshot::at_tick(0);
        s.add_region(0x1000, vec![0x00; 8]);
        let delta = MemoryDelta::new(0x1002, vec![0xFF, 0xFF]);
        let s2 = s.apply_delta(&delta);
        let data = s2.read_at(0x1000, 8).unwrap();
        assert_eq!(data[2], 0xFF);
        assert_eq!(data[3], 0xFF);
        assert_eq!(data[0], 0x00);
    }

    #[test]
    fn snapshot_regions_reflect_pages() {
        let mut s = MemorySnapshot::at_tick(0);
        s.add_region_full(
            0x4000,
            vec![0u8; 64],
            Permissions::READ | Permissions::WRITE,
            Some("heap".into()),
        );
        let regions = s.regions();
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].name.as_deref(), Some("heap"));
        assert!(regions[0].perms.is_writable());
    }

    // ── SnapshotCache ─────────────────────────────────────────────────────────

    #[test]
    fn snapshot_cache_basic_insert_and_get() {
        let mut cache = SnapshotCache::new(4);
        let snap = make_snap(5, 0xAA);
        let pos = snap.position;
        cache.insert(snap);
        assert_eq!(cache.len(), 1);
        let retrieved = cache.get(&pos).unwrap();
        assert_eq!(retrieved.position, pos);
    }

    #[test]
    fn snapshot_cache_lru_eviction() {
        let mut cache = SnapshotCache::new(2);
        cache.insert(make_snap(1, 0x01));
        cache.insert(make_snap(2, 0x02));
        // Access tick 1 to make it MRU.
        cache.get(&TracePosition::at_tick(1));
        // Insert a third snapshot — tick 2 should be evicted (was LRU).
        cache.insert(make_snap(3, 0x03));
        assert!(cache.get(&TracePosition::at_tick(2)).is_none());
        assert!(cache.get(&TracePosition::at_tick(1)).is_some());
        assert!(cache.get(&TracePosition::at_tick(3)).is_some());
    }

    #[test]
    fn snapshot_cache_remove() {
        let mut cache = SnapshotCache::new(4);
        cache.insert(make_snap(1, 0xAA));
        let pos = TracePosition::at_tick(1);
        assert!(cache.remove(&pos));
        assert!(cache.is_empty());
        assert!(!cache.remove(&pos));
    }

    #[test]
    fn snapshot_cache_clear() {
        let mut cache = SnapshotCache::new(4);
        cache.insert(make_snap(1, 0x01));
        cache.insert(make_snap(2, 0x02));
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn snapshot_cache_capacity_zero_unlimited() {
        // Capacity 0 means unlimited.
        let mut cache = SnapshotCache::new(0);
        for i in 0..20u64 {
            cache.insert(make_snap(i, 0xAA));
        }
        assert_eq!(cache.len(), 20);
    }

    // ── DeltaReplay ───────────────────────────────────────────────────────────

    #[test]
    fn delta_replay_reconstruct_with_no_deltas() {
        let mut r = DeltaReplay::new();
        let base = make_snap(0, 0xAA);
        r.set_base(base);
        let state = r.reconstruct(TracePosition::at_tick(5)).unwrap();
        let data = state.read_at(0x1000, 4).unwrap();
        assert_eq!(data, [0xAA; 4]);
    }

    #[test]
    fn delta_replay_reconstruct_applies_deltas() {
        let mut r = DeltaReplay::new();
        let base = make_snap(0, 0x00);
        r.set_base(base);
        r.push_delta(
            TracePosition::at_tick(3),
            MemoryDelta::new(0x1010, vec![0xBB; 4]),
        );
        let state = r.reconstruct(TracePosition::at_tick(5)).unwrap();
        let data = state.read_at(0x1010, 4).unwrap();
        assert_eq!(data, [0xBB; 4]);
    }

    #[test]
    fn delta_replay_reconstruct_stops_at_target() {
        let mut r = DeltaReplay::new();
        r.set_base(make_snap(0, 0x00));
        r.push_delta(
            TracePosition::at_tick(2),
            MemoryDelta::new(0x1000, vec![0x11; 4]),
        );
        r.push_delta(
            TracePosition::at_tick(5),
            MemoryDelta::new(0x1000, vec![0x22; 4]),
        );
        // Reconstruct at tick 3 — should include tick-2 delta but not tick-5 delta.
        let state = r.reconstruct(TracePosition::at_tick(3)).unwrap();
        let data = state.read_at(0x1000, 4).unwrap();
        assert_eq!(data, [0x11; 4]);
    }

    #[test]
    fn delta_replay_no_base_returns_none() {
        let r = DeltaReplay::new();
        assert!(r.reconstruct(TracePosition::at_tick(0)).is_none());
    }

    #[test]
    fn delta_replay_first_last_position() {
        let mut r = DeltaReplay::new();
        r.push_delta(TracePosition::at_tick(3), MemoryDelta::new(0, vec![]));
        r.push_delta(TracePosition::at_tick(7), MemoryDelta::new(0, vec![]));
        assert_eq!(r.first_delta_position(), Some(TracePosition::at_tick(3)));
        assert_eq!(r.last_delta_position(), Some(TracePosition::at_tick(7)));
    }

    #[test]
    fn delta_replay_clear_deltas() {
        let mut r = DeltaReplay::new();
        r.push_delta(TracePosition::at_tick(1), MemoryDelta::new(0, vec![]));
        r.clear_deltas();
        assert_eq!(r.delta_count(), 0);
    }

    // ── TraceMemoryProvider ───────────────────────────────────────────────────

    #[test]
    fn trace_provider_reads_at_latest() {
        let snaps = vec![make_snap(0, 0xAA), make_snap(5, 0xBB), make_snap(10, 0xCC)];
        let p = TraceMemoryProvider::from_snapshots(snaps);
        let data = p.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(data, [0xCC; 4]);
    }

    #[test]
    fn trace_provider_seek_and_read() {
        let snaps = vec![make_snap(0, 0xAA), make_snap(10, 0xCC)];
        let mut p = TraceMemoryProvider::from_snapshots(snaps);
        p.seek(TracePosition::at_tick(0));
        let data = p.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(data, [0xAA; 4]);
    }

    #[test]
    fn trace_provider_write_returns_unsupported() {
        let mut p = TraceMemoryProvider::empty();
        assert!(matches!(
            p.write(Address::new(0x1000), &[0xFF]),
            Err(MemError::Unsupported)
        ));
    }

    #[test]
    fn trace_provider_is_not_live() {
        let p = TraceMemoryProvider::empty();
        assert!(!p.is_live());
    }

    #[test]
    fn trace_provider_regions_from_current() {
        let snaps = vec![make_snap(0, 0xAA)];
        let p = TraceMemoryProvider::from_snapshots(snaps);
        let r = p.regions();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].range.start, Address::new(0x1000));
    }

    #[test]
    fn trace_provider_zero_len_read() {
        let p = TraceMemoryProvider::from_snapshots(vec![make_snap(0, 0xAA)]);
        assert!(p.read(Address::new(0x1000), 0).unwrap().is_empty());
    }

    #[test]
    fn trace_provider_unmapped_address_error() {
        let p = TraceMemoryProvider::from_snapshots(vec![make_snap(0, 0xAA)]);
        assert!(matches!(
            p.read(Address::new(0xDEAD_0000), 4),
            Err(MemError::NotMapped(_))
        ));
    }

    #[test]
    fn trace_provider_empty_no_snapshot_error() {
        let p = TraceMemoryProvider::empty();
        assert!(p.read(Address::new(0x1000), 4).is_err());
    }

    #[test]
    fn trace_provider_push_snapshot() {
        let mut p = TraceMemoryProvider::from_snapshots(vec![make_snap(0, 0xAA)]);
        p.push_snapshot(make_snap(5, 0xBB));
        assert_eq!(p.snapshot_count(), 2);
        p.seek(TracePosition::at_tick(5));
        let data = p.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(data, [0xBB; 4]);
    }

    #[test]
    fn trace_provider_with_deltas() {
        let mut p = TraceMemoryProvider::from_snapshots(vec![make_snap(0, 0x00)]);
        p.push_delta(
            TracePosition::at_tick(3),
            MemoryDelta::new(0x1020, vec![0xFF; 4]),
        );
        p.seek(TracePosition::at_tick(3));
        let data = p.read(Address::new(0x1020), 4).unwrap();
        assert_eq!(data, [0xFF; 4]);
    }

    #[test]
    fn trace_provider_seek_between_snapshots_uses_earlier() {
        let snaps = vec![make_snap(0, 0x11), make_snap(10, 0x22)];
        let mut p = TraceMemoryProvider::from_snapshots(snaps);
        p.seek(TracePosition::at_tick(5));
        let data = p.read(Address::new(0x1000), 1).unwrap();
        assert_eq!(data[0], 0x11);
    }

    #[test]
    fn trace_provider_first_last_position() {
        let p = TraceMemoryProvider::from_snapshots(vec![make_snap(1, 0), make_snap(9, 0)]);
        assert_eq!(p.first_position(), Some(TracePosition::at_tick(1)));
        assert_eq!(p.last_position(), Some(TracePosition::at_tick(9)));
    }

    #[test]
    fn trace_provider_cache_invalidation() {
        let mut p = TraceMemoryProvider::from_snapshots(vec![make_snap(0, 0xAA)]);
        let _ = p.read(Address::new(0x1000), 1);
        p.invalidate_cache();
        assert!(p.cache.lock().unwrap().is_empty());
    }

    #[test]
    fn trace_provider_debug_format() {
        let p = TraceMemoryProvider::empty();
        let s = format!("{p:?}");
        assert!(s.contains("TraceMemoryProvider"));
    }
}
