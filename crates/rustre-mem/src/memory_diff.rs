//! Memory snapshot diffing utilities.
//!
//! Provides [`MemoryDiff`], [`DiffEntry`], [`DiffRegion`], [`diff_snapshots()`],
//! and [`apply_diff()`] for comparing two memory states and producing a
//! structured description of every change.

use std::collections::BTreeMap;
use std::fmt;

use rustre_core::address::{Address, AddressRange};
use rustre_core::permissions::Permissions;

// ─────────────────────────────────────────────────────────────────────────────
// ChangeKind
// ─────────────────────────────────────────────────────────────────────────────

/// The nature of a single change between two snapshots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeKind {
    /// Byte data changed in a mapped region that existed in both snapshots.
    Modified,
    /// A region is present in the new snapshot but absent in the old one.
    Added,
    /// A region is absent in the new snapshot but was present in the old one.
    Removed,
    /// Permissions changed but byte data did not.
    PermissionChanged,
    /// Both data and permissions changed.
    ModifiedAndPermissionChanged,
}

impl fmt::Display for ChangeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Modified => write!(f, "modified"),
            Self::Added => write!(f, "added"),
            Self::Removed => write!(f, "removed"),
            Self::PermissionChanged => write!(f, "perm-changed"),
            Self::ModifiedAndPermissionChanged => write!(f, "modified+perm-changed"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A single differing byte within a [`DiffRegion`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffEntry {
    /// Absolute address of the differing byte.
    pub address: Address,
    /// Value in the *before* snapshot (`None` if not mapped).
    pub before: Option<u8>,
    /// Value in the *after* snapshot (`None` if not mapped).
    pub after: Option<u8>,
}

impl DiffEntry {
    #[must_use] 
    pub const fn new(address: Address, before: Option<u8>, after: Option<u8>) -> Self {
        Self { address, before, after }
    }

    /// Returns `true` if the byte was written (after is `Some`).
    #[must_use] 
    pub const fn is_write(&self) -> bool {
        self.after.is_some()
    }

    /// Returns `true` if the byte was erased (before `Some`, after `None`).
    #[must_use] 
    pub const fn is_erasure(&self) -> bool {
        self.before.is_some() && self.after.is_none()
    }

    /// Returns `true` if both values are identical (the diff entry is a no-op).
    #[must_use] 
    pub fn is_unchanged(&self) -> bool {
        self.before == self.after
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffRegion
// ─────────────────────────────────────────────────────────────────────────────

/// A contiguous address range that changed between snapshots.
#[derive(Debug, Clone)]
pub struct DiffRegion {
    /// Address range covered by this diff region.
    pub range: AddressRange,
    /// High-level classification of the change.
    pub kind: ChangeKind,
    /// Per-byte difference entries (may be shorter than `range` if only some
    /// bytes changed within a large region).
    pub entries: Vec<DiffEntry>,
    /// Permissions before the change (`None` for `Added` regions).
    pub perms_before: Option<Permissions>,
    /// Permissions after the change (`None` for `Removed` regions).
    pub perms_after: Option<Permissions>,
}

impl DiffRegion {
    #[must_use] 
    pub const fn new(range: AddressRange, kind: ChangeKind) -> Self {
        Self {
            range,
            kind,
            entries: Vec::new(),
            perms_before: None,
            perms_after: None,
        }
    }

    /// Number of bytes that differ in this region.
    #[must_use] 
    pub fn changed_byte_count(&self) -> usize {
        self.entries.iter().filter(|e| !e.is_unchanged()).count()
    }

    /// Returns the contiguous span length of the region.
    #[must_use] 
    pub const fn span_len(&self) -> u64 {
        self.range.end.0.saturating_sub(self.range.start.0)
    }

    /// Returns `true` if the region contains no actual changes.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() || self.entries.iter().all(DiffEntry::is_unchanged)
    }

    /// Summary string for logging.
    #[must_use] 
    pub fn summary(&self) -> String {
        format!(
            "[{:#x}..{:#x}] {} — {} byte(s) changed",
            self.range.start.0,
            self.range.end.0,
            self.kind,
            self.changed_byte_count()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SnapshotRegion — input to the diff engine
// ─────────────────────────────────────────────────────────────────────────────

/// A single mapped region in a memory snapshot.
#[derive(Debug, Clone)]
pub struct SnapshotRegion {
    pub base: Address,
    pub bytes: Vec<u8>,
    pub perms: Permissions,
    pub label: Option<String>,
}

impl SnapshotRegion {
    #[must_use] 
    pub const fn new(base: Address, bytes: Vec<u8>, perms: Permissions) -> Self {
        Self { base, bytes, perms, label: None }
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    #[must_use] 
    pub const fn end_address(&self) -> Address {
        Address::new(self.base.0 + self.bytes.len() as u64)
    }

    #[must_use] 
    pub const fn address_range(&self) -> AddressRange {
        AddressRange::new(self.base, self.end_address())
    }

    #[must_use] 
    pub fn byte_at(&self, addr: Address) -> Option<u8> {
        let offset = addr.0.checked_sub(self.base.0)?;
        self.bytes.get(offset as usize).copied()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryDiff
// ─────────────────────────────────────────────────────────────────────────────

/// The complete diff between two memory snapshots.
#[derive(Debug, Default)]
pub struct MemoryDiff {
    /// Regions that changed (data, permissions, or both).
    pub changed: Vec<DiffRegion>,
    /// Regions that were added in the *after* snapshot.
    pub added: Vec<DiffRegion>,
    /// Regions that were removed in the *after* snapshot.
    pub removed: Vec<DiffRegion>,
    /// Total number of differing bytes across all changed regions.
    pub total_changed_bytes: u64,
    /// Total number of regions examined.
    pub regions_examined: usize,
}

impl MemoryDiff {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if there are no differences.
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.changed.is_empty() && self.added.is_empty() && self.removed.is_empty()
    }

    /// Total number of regions in the diff.
    #[must_use] 
    pub const fn region_count(&self) -> usize {
        self.changed.len() + self.added.len() + self.removed.len()
    }

    /// All diff regions combined into a single iterator.
    pub fn all_regions(&self) -> impl Iterator<Item = &DiffRegion> {
        self.changed.iter().chain(&self.added).chain(&self.removed)
    }

    /// Find all diff entries at a specific address across all regions.
    #[must_use] 
    pub fn entries_at(&self, addr: Address) -> Vec<&DiffEntry> {
        self.all_regions()
            .flat_map(|r| &r.entries)
            .filter(|e| e.address == addr)
            .collect()
    }

    /// Summary statistics as a human-readable string.
    #[must_use] 
    pub fn stats_summary(&self) -> String {
        format!(
            "diff: {} changed, {} added, {} removed regions; {} byte(s) changed",
            self.changed.len(),
            self.added.len(),
            self.removed.len(),
            self.total_changed_bytes,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// diff_snapshots
// ─────────────────────────────────────────────────────────────────────────────

/// Compare two memory snapshots and return a [`MemoryDiff`] describing every
/// difference.
///
/// The algorithm iterates over regions in both snapshots using a `BTreeMap`
/// keyed on the base address, then compares byte-by-byte within overlapping
/// spans.
#[must_use] 
pub fn diff_snapshots(before: &[SnapshotRegion], after: &[SnapshotRegion]) -> MemoryDiff {
    let mut diff = MemoryDiff::new();

    // Index regions by base address.
    let before_map: BTreeMap<u64, &SnapshotRegion> =
        before.iter().map(|r| (r.base.0, r)).collect();
    let after_map: BTreeMap<u64, &SnapshotRegion> =
        after.iter().map(|r| (r.base.0, r)).collect();

    diff.regions_examined = before_map.len() + after_map.len();

    // Find added regions (in after but not in before).
    for (base, region) in &after_map {
        if !before_map.contains_key(base) {
            let range = region.address_range();
            let mut dr = DiffRegion::new(range, ChangeKind::Added);
            dr.perms_after = Some(region.perms);
            for (i, &byte) in region.bytes.iter().enumerate() {
                dr.entries.push(DiffEntry::new(
                    Address::new(region.base.0 + i as u64),
                    None,
                    Some(byte),
                ));
            }
            diff.total_changed_bytes += region.bytes.len() as u64;
            diff.added.push(dr);
        }
    }

    // Find removed regions (in before but not in after).
    for (base, region) in &before_map {
        if !after_map.contains_key(base) {
            let range = region.address_range();
            let mut dr = DiffRegion::new(range, ChangeKind::Removed);
            dr.perms_before = Some(region.perms);
            for (i, &byte) in region.bytes.iter().enumerate() {
                dr.entries.push(DiffEntry::new(
                    Address::new(region.base.0 + i as u64),
                    Some(byte),
                    None,
                ));
            }
            diff.total_changed_bytes += region.bytes.len() as u64;
            diff.removed.push(dr);
        }
    }

    // Find modified regions (present in both).
    for (base, b_region) in &before_map {
        if let Some(a_region) = after_map.get(base) {
            let data_changed = b_region.bytes != a_region.bytes;
            let perms_changed = b_region.perms != a_region.perms;

            if !data_changed && !perms_changed {
                continue;
            }

            let kind = match (data_changed, perms_changed) {
                (true, true) => ChangeKind::ModifiedAndPermissionChanged,
                (true, false) => ChangeKind::Modified,
                (false, true) => ChangeKind::PermissionChanged,
                (false, false) => continue,
            };

            let range = AddressRange::new(b_region.base, b_region.end_address());
            let mut dr = DiffRegion::new(range, kind);
            dr.perms_before = Some(b_region.perms);
            dr.perms_after = Some(a_region.perms);

            let len = b_region.bytes.len().max(a_region.bytes.len());
            for i in 0..len {
                let addr = Address::new(b_region.base.0 + i as u64);
                let old = b_region.bytes.get(i).copied();
                let new = a_region.bytes.get(i).copied();
                if old != new {
                    diff.total_changed_bytes += 1;
                    dr.entries.push(DiffEntry::new(addr, old, new));
                }
            }

            diff.changed.push(dr);
        }
    }

    diff
}

// ─────────────────────────────────────────────────────────────────────────────
// apply_diff
// ─────────────────────────────────────────────────────────────────────────────

/// Apply a [`MemoryDiff`] to a mutable slice of [`SnapshotRegion`]s,
/// producing a new snapshot that matches the "after" state.
///
/// The function modifies `base_snapshot` in place:
/// - `Added` regions are inserted.
/// - `Removed` regions are deleted.
/// - `Modified` / `ModifiedAndPermissionChanged` entries overwrite bytes.
/// - `PermissionChanged` entries update region permissions.
pub fn apply_diff(base_snapshot: &mut Vec<SnapshotRegion>, diff: &MemoryDiff) {
    // Apply modifications and permission changes.
    for region in &diff.changed {
        if let Some(snap) = base_snapshot
            .iter_mut()
            .find(|r| r.base == region.range.start)
        {
            for entry in &region.entries {
                if let Some(new_byte) = entry.after {
                    let offset = entry.address.0.saturating_sub(snap.base.0) as usize;
                    if offset < snap.bytes.len() {
                        snap.bytes[offset] = new_byte;
                    }
                }
            }
            if let Some(perms) = region.perms_after {
                snap.perms = perms;
            }
        }
    }

    // Remove deleted regions.
    for region in &diff.removed {
        base_snapshot.retain(|r| r.base != region.range.start);
    }

    // Insert added regions.
    for region in &diff.added {
        let bytes: Vec<u8> = region.entries.iter().filter_map(|e| e.after).collect();
        let perms = region.perms_after.unwrap_or(Permissions::READ);
        base_snapshot.push(SnapshotRegion::new(region.range.start, bytes, perms));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffStats — aggregate statistics over a diff
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics computed from a [`MemoryDiff`].
#[derive(Debug, Clone, Default)]
pub struct DiffStats {
    pub total_regions: usize,
    pub changed_regions: usize,
    pub added_regions: usize,
    pub removed_regions: usize,
    pub total_changed_bytes: u64,
    pub max_bytes_in_single_region: u64,
}

impl DiffStats {
    #[must_use] 
    pub fn from_diff(diff: &MemoryDiff) -> Self {
        let max_bytes = diff
            .all_regions()
            .map(|r| r.changed_byte_count() as u64)
            .max()
            .unwrap_or(0);
        Self {
            total_regions: diff.region_count(),
            changed_regions: diff.changed.len(),
            added_regions: diff.added.len(),
            removed_regions: diff.removed.len(),
            total_changed_bytes: diff.total_changed_bytes,
            max_bytes_in_single_region: max_bytes,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn perm_rw() -> Permissions {
        Permissions::READ | Permissions::WRITE
    }

    fn perm_r() -> Permissions {
        Permissions::READ
    }

    fn region(base: u64, bytes: Vec<u8>) -> SnapshotRegion {
        SnapshotRegion::new(Address::new(base), bytes, perm_rw())
    }

    #[test]
    fn identical_snapshots_produce_empty_diff() {
        let snap: Vec<SnapshotRegion> = vec![region(0x1000, vec![1, 2, 3, 4])];
        let diff = diff_snapshots(&snap, &snap);
        assert!(diff.is_empty());
        assert_eq!(diff.total_changed_bytes, 0);
    }

    #[test]
    fn detects_modified_bytes() {
        let before = vec![region(0x1000, vec![0xAA, 0xBB, 0xCC])];
        let after = vec![region(0x1000, vec![0xAA, 0xFF, 0xCC])];
        let diff = diff_snapshots(&before, &after);
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.total_changed_bytes, 1);
        let entry = &diff.changed[0].entries[0];
        assert_eq!(entry.address, Address::new(0x1001));
        assert_eq!(entry.before, Some(0xBB));
        assert_eq!(entry.after, Some(0xFF));
    }

    #[test]
    fn detects_added_region() {
        let before: Vec<SnapshotRegion> = vec![];
        let after = vec![region(0x2000, vec![1, 2, 3])];
        let diff = diff_snapshots(&before, &after);
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].range.start, Address::new(0x2000));
        assert_eq!(diff.total_changed_bytes, 3);
    }

    #[test]
    fn detects_removed_region() {
        let before = vec![region(0x3000, vec![0xDE, 0xAD])];
        let after: Vec<SnapshotRegion> = vec![];
        let diff = diff_snapshots(&before, &after);
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.removed[0].entries.len(), 2);
    }

    #[test]
    fn detects_permission_change() {
        let before = vec![SnapshotRegion::new(
            Address::new(0x4000),
            vec![0u8; 4],
            perm_rw(),
        )];
        let after = vec![SnapshotRegion::new(
            Address::new(0x4000),
            vec![0u8; 4],
            perm_r(),
        )];
        let diff = diff_snapshots(&before, &after);
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].kind, ChangeKind::PermissionChanged);
    }

    #[test]
    fn apply_diff_adds_region() {
        let mut snap: Vec<SnapshotRegion> = vec![];
        let before: Vec<SnapshotRegion> = vec![];
        let after = vec![region(0x5000, vec![0xAA, 0xBB])];
        let diff = diff_snapshots(&before, &after);
        apply_diff(&mut snap, &diff);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].bytes, vec![0xAA, 0xBB]);
    }

    #[test]
    fn apply_diff_removes_region() {
        let mut snap = vec![region(0x6000, vec![1, 2, 3])];
        let before = snap.clone();
        let after: Vec<SnapshotRegion> = vec![];
        let diff = diff_snapshots(&before, &after);
        apply_diff(&mut snap, &diff);
        assert!(snap.is_empty());
    }

    #[test]
    fn apply_diff_modifies_bytes() {
        let mut snap = vec![region(0x7000, vec![0u8; 4])];
        let before = snap.clone();
        let mut after = snap.clone();
        after[0].bytes[2] = 0xFF;
        let diff = diff_snapshots(&before, &after);
        apply_diff(&mut snap, &diff);
        assert_eq!(snap[0].bytes[2], 0xFF);
    }

    #[test]
    fn diff_stats_correct() {
        let before = vec![region(0x1000, vec![1, 2, 3])];
        let after = vec![region(0x1000, vec![1, 9, 3])];
        let diff = diff_snapshots(&before, &after);
        let stats = DiffStats::from_diff(&diff);
        assert_eq!(stats.changed_regions, 1);
        assert_eq!(stats.total_changed_bytes, 1);
    }

    #[test]
    fn entries_at_returns_correct_entries() {
        let before = vec![region(0x8000, vec![0u8; 8])];
        let mut after = before.clone();
        after[0].bytes[3] = 0xAB;
        let diff = diff_snapshots(&before, &after);
        let entries = diff.entries_at(Address::new(0x8003));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].after, Some(0xAB));
    }

    #[test]
    fn diff_region_summary_contains_kind() {
        let range = AddressRange::new(Address::new(0x1000), Address::new(0x1010));
        let dr = DiffRegion::new(range, ChangeKind::Modified);
        let s = dr.summary();
        assert!(s.contains("modified"));
    }
}
