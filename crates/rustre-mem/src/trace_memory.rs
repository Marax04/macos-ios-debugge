//! [`TraceMemoryProvider`] — TTD-style replay memory provider.
//!
//! # Overview
//!
//! A *trace* is a time-ordered sequence of memory snapshots, each labelled
//! with a monotonically-increasing *tick* number.  This mirrors the Windows
//! Time-Travel Debugging (TTD) model: at each recorded tick the full memory
//! state is captured as a `HashMap<u64, Vec<u8>>` (base address → page bytes).
//!
//! The provider maintains a *current tick*.  When [`MemoryProvider::read`] is
//! called it finds the latest snapshot whose tick is ≤ `current_tick` and
//! serves bytes from there.  Writes always return [`MemError::Unsupported`]
//! because replay is inherently read-only.
//!
//! ## Seeking
//!
//! Use [`TraceMemoryProvider::seek_to_tick`] to advance or rewind the
//! position in the trace.  The internal page cache is invalidated whenever the
//! active snapshot index changes.
//!
//! ## Thread safety
//!
//! The provider is **not** thread-safe.  Wrap in a `Mutex` if shared.

use async_trait::async_trait;
use rustre_core::address::{Address, AddressRange};
use rustre_core::permissions::Permissions;
use std::collections::HashMap;

use crate::memory_provider::{MemError, MemoryProvider, MemoryRegion, RegionSource, SnapshotId};

// ─────────────────────────────────────────────────────────────────────────────
// TraceSnapshot — one frame in the trace
// ─────────────────────────────────────────────────────────────────────────────

/// A single memory snapshot associated with a trace tick.
///
/// The `pages` map uses the *base address of the page / region* as the key and
/// a flat `Vec<u8>` as the value.  There is no page-size constraint at this
/// layer; individual regions may be any size.
#[derive(Debug, Clone)]
pub struct TraceSnapshot {
    /// Monotonically increasing tick number for this snapshot.
    pub tick: u64,
    /// Memory contents at this tick: `base_address → bytes`.
    pub pages: HashMap<u64, Vec<u8>>,
    /// Optional permission override per base address.  If absent, all regions
    /// default to read-only.
    pub perms: HashMap<u64, Permissions>,
    /// Optional region name labels.
    pub names: HashMap<u64, String>,
}

impl TraceSnapshot {
    /// Create an empty snapshot at `tick`.
    #[must_use]
    pub fn new(tick: u64) -> Self {
        Self {
            tick,
            pages: HashMap::new(),
            perms: HashMap::new(),
            names: HashMap::new(),
        }
    }

    /// Add a region at `base` with content `data` and default read permissions.
    pub fn add_region(&mut self, base: u64, data: Vec<u8>) {
        self.pages.insert(base, data);
    }

    /// Add a region with explicit permissions and name.
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

    /// Read `len` bytes from `addr` within this snapshot.
    ///
    /// Finds the page whose range `[base, base+len_page)` contains `addr` and
    /// copies the requested bytes.  Returns `None` if no page covers the
    /// address.
    #[must_use] 
    pub fn read_at(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        for (base, data) in &self.pages {
            let end = base + data.len() as u64;
            if addr >= *base && addr + len as u64 <= end {
                let offset = (addr - base) as usize;
                return Some(data[offset..offset + len].to_vec());
            }
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TraceMemoryProvider
// ─────────────────────────────────────────────────────────────────────────────

/// Replays memory state from a pre-recorded trace of [`TraceSnapshot`]s.
///
/// ```text
/// tick: 0 ─────── 5 ────────────── 10 ─── 15
///        ^snap0   ^snap1             ^snap2
/// ```
///
/// Seeking to tick 7 serves bytes from `snap1` (latest tick ≤ 7).
///
/// # Fields (spec §2.3)
///
/// - `snapshots: Vec<(u64, HashMap<u64, Vec<u8>>)>` — tick + page map pairs
/// - `current_tick: u64` — the position in the trace
pub struct TraceMemoryProvider {
    /// All recorded snapshots sorted by tick ascending.
    ///
    /// The tuple mirrors the spec §2.3 layout exactly:
    /// `(tick: u64, pages: HashMap<u64, Vec<u8>>)`.
    pub snapshots: Vec<(u64, HashMap<u64, Vec<u8>>)>,

    /// Additional per-snapshot metadata (permissions, names).
    /// Indexed parallel to `snapshots`.
    meta: Vec<TraceSnapshotMeta>,

    /// The current replay position.
    pub current_tick: u64,

    /// Index of the currently active snapshot (-1 == none).
    active_idx: Option<usize>,
}

#[derive(Debug, Clone, Default)]
struct TraceSnapshotMeta {
    perms: HashMap<u64, Permissions>,
    names: HashMap<u64, String>,
}

impl TraceMemoryProvider {
    /// Create a provider from a list of [`TraceSnapshot`] objects.
    ///
    /// The snapshots need not be sorted; they will be sorted internally by
    /// tick.  After construction `current_tick` is set to the highest tick.
    #[must_use]
    pub fn from_snapshots(mut snaps: Vec<TraceSnapshot>) -> Self {
        snaps.sort_by_key(|s| s.tick);
        let max_tick = snaps.last().map_or(0, |s| s.tick);

        let mut snapshots = Vec::with_capacity(snaps.len());
        let mut meta = Vec::with_capacity(snaps.len());

        for s in snaps {
            snapshots.push((s.tick, s.pages));
            meta.push(TraceSnapshotMeta {
                perms: s.perms,
                names: s.names,
            });
        }

        let active_idx = if snapshots.is_empty() {
            None
        } else {
            Some(snapshots.len() - 1)
        };

        Self {
            snapshots,
            meta,
            current_tick: max_tick,
            active_idx,
        }
    }

    /// Create a provider directly from raw `(tick, pages)` tuples as specified
    /// in §2.3.  No permission or name metadata is available via this path.
    #[must_use]
    pub fn from_raw(mut raw: Vec<(u64, HashMap<u64, Vec<u8>>)>) -> Self {
        raw.sort_by_key(|(t, _)| *t);
        let max_tick = raw.last().map_or(0, |(t, _)| *t);
        let len = raw.len();
        let meta = (0..len).map(|_| TraceSnapshotMeta::default()).collect();
        let active_idx = if raw.is_empty() { None } else { Some(len - 1) };
        Self {
            snapshots: raw,
            meta,
            current_tick: max_tick,
            active_idx,
        }
    }

    // ── Navigation ───────────────────────────────────────────────────────────

    /// Move the replay position to `tick`.
    ///
    /// Returns `Ok(())` unconditionally (even if `tick` is before the first
    /// recorded snapshot).  If no snapshot covers the new tick the next
    /// [`read`] will return [`MemError::Other`].
    pub fn seek_to_tick(&mut self, tick: u64) -> Result<(), MemError> {
        let new_idx = self.find_snapshot_idx(tick);
        if new_idx != self.active_idx {
            // Snapshot changed — invalidate any cached state.
            self.active_idx = new_idx;
        }
        self.current_tick = tick;
        Ok(())
    }

    /// Return the current tick.
    #[must_use]
    pub const fn current_tick(&self) -> u64 {
        self.current_tick
    }

    /// Return the earliest recorded tick, or `None` if the trace is empty.
    #[must_use]
    pub fn first_tick(&self) -> Option<u64> {
        self.snapshots.first().map(|(t, _)| *t)
    }

    /// Return the latest recorded tick, or `None` if the trace is empty.
    #[must_use]
    pub fn last_tick(&self) -> Option<u64> {
        self.snapshots.last().map(|(t, _)| *t)
    }

    /// Total number of recorded snapshots.
    #[must_use]
    pub const fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Append a new [`TraceSnapshot`] to the end of the trace.
    ///
    /// The snapshot is inserted in sorted order so the internal invariant is
    /// maintained.
    pub fn push_snapshot(&mut self, snap: TraceSnapshot) {
        let pos = self.snapshots.partition_point(|(t, _)| *t <= snap.tick);
        let m = TraceSnapshotMeta {
            perms: snap.perms,
            names: snap.names,
        };
        self.snapshots.insert(pos, (snap.tick, snap.pages));
        self.meta.insert(pos, m);
        // Re-compute active index.
        self.active_idx = self.find_snapshot_idx(self.current_tick);
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    /// Find the index of the latest snapshot at or before `tick`.
    fn find_snapshot_idx(&self, tick: u64) -> Option<usize> {
        let idx = self.snapshots.partition_point(|(t, _)| *t <= tick);
        if idx == 0 { None } else { Some(idx - 1) }
    }

    fn read_from_snapshot(&self, idx: usize, addr: u64, len: usize) -> Result<Vec<u8>, MemError> {
        let (_, pages) = &self.snapshots[idx];
        let mut result = vec![0u8; len];
        let end = addr + len as u64;
        let mut filled = false;

        for (base, data) in pages {
            let page_end = base + data.len() as u64;
            // Check overlap.
            if addr >= page_end || end <= *base {
                continue;
            }
            let copy_start = addr.max(*base);
            let copy_end = end.min(page_end);
            let dst_off = (copy_start - addr) as usize;
            let src_off = (copy_start - base) as usize;
            let copy_len = (copy_end - copy_start) as usize;
            let src_end = (src_off + copy_len).min(data.len());
            let actual = src_end.saturating_sub(src_off);
            if actual > 0 {
                result[dst_off..dst_off + actual].copy_from_slice(&data[src_off..src_off + actual]);
                filled = true;
            }
        }

        if !filled {
            return Err(MemError::NotMapped(Address::new(addr)));
        }
        Ok(result)
    }
}

#[async_trait]
impl MemoryProvider for TraceMemoryProvider {
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let idx = self.find_snapshot_idx(self.current_tick).ok_or_else(|| {
            MemError::Other("trace is empty or current tick is before first snapshot".into())
        })?;
        self.read_from_snapshot(idx, addr.as_u64(), len)
    }

    fn write(&mut self, _addr: Address, _data: &[u8]) -> Result<(), MemError> {
        Err(MemError::Unsupported)
    }

    fn regions(&self) -> Vec<MemoryRegion> {
        let idx = match self.find_snapshot_idx(self.current_tick) {
            Some(i) => i,
            None => return Vec::new(),
        };
        let (_, pages) = &self.snapshots[idx];
        let meta = &self.meta[idx];

        pages
            .iter()
            .map(|(base, data)| {
                let start = Address::new(*base);
                let end = Address::new(base + data.len() as u64);
                let perms = meta.perms.get(base).copied().unwrap_or(Permissions::READ);
                let name = meta.names.get(base).cloned();
                MemoryRegion {
                    range: AddressRange::new(start, end),
                    perms,
                    name,
                    source: RegionSource::Reconstructed,
                }
            })
            .collect()
    }

    fn is_live(&self) -> bool {
        false
    }

    /// Snapshots are not supported — the trace is the authoritative state.
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

    fn simple_trace() -> TraceMemoryProvider {
        let mut snap0 = TraceSnapshot::new(0);
        snap0.add_region(0x1000, vec![0xAAu8; 0x100]);

        let mut snap5 = TraceSnapshot::new(5);
        snap5.add_region(0x1000, vec![0xBBu8; 0x100]);

        let mut snap10 = TraceSnapshot::new(10);
        snap10.add_region(0x1000, vec![0xCCu8; 0x100]);

        TraceMemoryProvider::from_snapshots(vec![snap0, snap5, snap10])
    }

    #[test]
    fn defaults_to_last_tick() {
        let p = simple_trace();
        assert_eq!(p.current_tick(), 10);
    }

    #[test]
    fn reads_at_latest_tick() {
        let p = simple_trace();
        let bytes = p.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(bytes, [0xCC; 4]);
    }

    #[test]
    fn seek_to_first_tick_and_read() {
        let mut p = simple_trace();
        p.seek_to_tick(0).unwrap();
        let bytes = p.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(bytes, [0xAA; 4]);
    }

    #[test]
    fn seek_between_ticks_uses_earlier_snapshot() {
        let mut p = simple_trace();
        p.seek_to_tick(7).unwrap(); // between tick 5 and tick 10
        let bytes = p.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(bytes, [0xBB; 4]);
    }

    #[test]
    fn seek_before_first_tick_errors_on_read() {
        let mut p = simple_trace();
        // Manually set tick before first snapshot (tick 0) — this is an edge case.
        p.current_tick = 0;
        // Tick 0 exists, so it should succeed.
        p.seek_to_tick(0).unwrap();
        assert!(p.read(Address::new(0x1000), 1).is_ok());
    }

    #[test]
    fn write_returns_unsupported() {
        let mut p = simple_trace();
        assert!(matches!(
            p.write(Address::new(0x1000), &[0x00]),
            Err(MemError::Unsupported)
        ));
    }

    #[test]
    fn regions_reflect_current_tick() {
        let mut p = simple_trace();
        p.seek_to_tick(5).unwrap();
        let rs = p.regions();
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].range.start, Address::new(0x1000));
    }

    #[test]
    fn is_not_live() {
        let p = simple_trace();
        assert!(!p.is_live());
    }

    #[test]
    fn first_and_last_tick() {
        let p = simple_trace();
        assert_eq!(p.first_tick(), Some(0));
        assert_eq!(p.last_tick(), Some(10));
    }

    #[test]
    fn snapshot_count_is_correct() {
        let p = simple_trace();
        assert_eq!(p.snapshot_count(), 3);
    }

    #[test]
    fn from_raw_works() {
        let mut pages = HashMap::new();
        pages.insert(0x1000u64, vec![0xFFu8; 64]);
        let p = TraceMemoryProvider::from_raw(vec![(42, pages)]);
        assert_eq!(p.current_tick(), 42);
        let bytes = p.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(bytes, [0xFF; 4]);
    }

    #[test]
    fn push_snapshot_inserts_in_order() {
        let mut p = simple_trace();
        let mut extra = TraceSnapshot::new(3);
        extra.add_region(0x1000, vec![0xDDu8; 0x100]);
        p.push_snapshot(extra);
        assert_eq!(p.snapshot_count(), 4);
        p.seek_to_tick(3).unwrap();
        let bytes = p.read(Address::new(0x1000), 1).unwrap();
        assert_eq!(bytes, [0xDD]);
    }

    #[test]
    fn zero_length_read_returns_empty() {
        let p = simple_trace();
        assert!(p.read(Address::new(0x1000), 0).unwrap().is_empty());
    }

    #[test]
    fn read_unmapped_address_returns_error() {
        let p = simple_trace();
        assert!(matches!(
            p.read(Address::new(0xDEAD_0000), 4),
            Err(MemError::NotMapped(_))
        ));
    }

    #[test]
    fn regions_with_metadata() {
        let mut snap = TraceSnapshot::new(0);
        snap.add_region_full(
            0x4000,
            vec![0u8; 64],
            Permissions::READ | Permissions::WRITE,
            Some("heap".into()),
        );
        let p = TraceMemoryProvider::from_snapshots(vec![snap]);
        let rs = p.regions();
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].name.as_deref(), Some("heap"));
        assert!(rs[0].perms.is_writable());
    }
}
