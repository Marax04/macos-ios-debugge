//! Virtual memory map operations: region merging, splitting, querying, and
//! serialization helpers.

use rustre_core::address::{Address, AddressRange};
use rustre_core::permissions::Permissions;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Error returned by vmmap split/protect operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmMapError;

impl std::fmt::Display for VmMapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("vmmap operation failed: address out of range or region not found")
    }
}

impl std::error::Error for VmMapError {}

// ─────────────────────────────────────────────────────────────────────────────
// VmRegionKind
// ─────────────────────────────────────────────────────────────────────────────

/// The semantic purpose of a virtual memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VmRegionKind {
    /// Executable code (`.text`, JIT pages …).
    Code,
    /// Initialized or zero-filled read-only data.
    ReadOnlyData,
    /// Mutable data (`.bss`, `.data`, heap allocations).
    Data,
    /// Thread-local storage block.
    Tls,
    /// Call/return stack.
    Stack,
    /// Process heap.
    Heap,
    /// Memory-mapped file region.
    MappedFile,
    /// Guard / unmapped page.
    Guard,
    /// Unknown / unclassified.
    Unknown,
}

impl std::fmt::Display for VmRegionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Code => "code",
            Self::ReadOnlyData => "rodata",
            Self::Data => "data",
            Self::Tls => "tls",
            Self::Stack => "stack",
            Self::Heap => "heap",
            Self::MappedFile => "mapped-file",
            Self::Guard => "guard",
            Self::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmRegion
// ─────────────────────────────────────────────────────────────────────────────

/// A single contiguous virtual-memory region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmRegion {
    /// Address range `[start, end)`.
    pub range: AddressRange,
    /// Page-level permissions.
    pub perms: Permissions,
    /// Semantic kind.
    pub kind: VmRegionKind,
    /// Human-readable label (module name, section name, etc.).
    pub label: Option<String>,
    /// Whether pages in this region are currently committed (i.e. backed by
    /// physical memory or swap).
    pub committed: bool,
}

impl VmRegion {
    /// Construct a new region.
    #[must_use]
    pub const fn new(range: AddressRange, perms: Permissions, kind: VmRegionKind) -> Self {
        Self {
            range,
            perms,
            kind,
            label: None,
            committed: true,
        }
    }

    /// Attach a human-readable label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Mark region as uncommitted (no physical backing yet).
    #[must_use]
    pub const fn uncommitted(mut self) -> Self {
        self.committed = false;
        self
    }

    /// Length of the region in bytes.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.range.len()
    }

    /// Whether the region is zero-sized.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.range.is_empty()
    }

    /// Returns `true` if `addr` falls within `[start, end)`.
    #[must_use]
    pub const fn contains(&self, addr: Address) -> bool {
        self.range.contains(addr)
    }

    /// Returns `true` if this region overlaps with `other`.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.range.start < other.range.end && other.range.start < self.range.end
    }

    /// Returns `true` if this region is adjacent to `other` (no gap, no overlap)
    /// and has identical permissions, kind, and committed state.
    #[must_use]
    pub fn is_mergeable_with(&self, other: &Self) -> bool {
        self.range.end == other.range.start
            && self.perms == other.perms
            && self.kind == other.kind
            && self.committed == other.committed
    }

    /// Attempt to merge `other` into `self`.  Returns `Some(merged)` on success
    /// or `None` if the regions are not mergeable.
    #[must_use]
    pub fn try_merge(&self, other: &Self) -> Option<Self> {
        if !self.is_mergeable_with(other) {
            return None;
        }
        let mut merged = Self {
            range: AddressRange::new(self.range.start, other.range.end),
            perms: self.perms,
            kind: self.kind,
            label: self.label.clone().or_else(|| other.label.clone()),
            committed: self.committed,
        };
        // Concatenate labels if both are set.
        if self.label.is_some() && other.label.is_some() {
            merged.label = Some(format!(
                "{}+{}",
                self.label.as_deref().unwrap_or(""),
                other.label.as_deref().unwrap_or("")
            ));
        }
        Some(merged)
    }

    /// Split at `split_addr`, returning `(left, right)`.  The address must be
    /// strictly inside this region (not equal to start or end).
    ///
    /// # Errors
    /// Returns `Err(())` if `split_addr` is outside `(start, end)`.
    pub fn split_at(&self, split_addr: Address) -> Result<(Self, Self), VmMapError> {
        if split_addr <= self.range.start || split_addr >= self.range.end {
            return Err(VmMapError);
        }
        let left = Self {
            range: AddressRange::new(self.range.start, split_addr),
            perms: self.perms,
            kind: self.kind,
            label: self.label.clone(),
            committed: self.committed,
        };
        let right = Self {
            range: AddressRange::new(split_addr, self.range.end),
            perms: self.perms,
            kind: self.kind,
            label: self.label.clone(),
            committed: self.committed,
        };
        Ok((left, right))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmMap
// ─────────────────────────────────────────────────────────────────────────────

/// An ordered, non-overlapping virtual memory map.
///
/// Regions are stored keyed by their start address in a `BTreeMap` for O(log n)
/// lookups and ordered iteration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VmMap {
    /// Start address → region.
    regions: BTreeMap<u64, VmRegion>,
}

impl VmMap {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of regions in the map.
    #[must_use]
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// Returns `true` if the map contains no regions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Total mapped bytes across all regions.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.regions.values().map(VmRegion::len).sum()
    }

    /// Insert a region.  Panics in debug mode if it would overlap an existing
    /// region; in release mode, the insertion is silently rejected.
    ///
    /// # Panics
    /// Panics in debug builds when `region` overlaps an existing entry.
    pub fn insert(&mut self, region: VmRegion) {
        debug_assert!(
            !self.overlaps(&region),
            "VmMap::insert: region {region:?} overlaps existing region"
        );
        if !self.overlaps(&region) {
            self.regions.insert(region.range.start.0, region);
        }
    }

    /// Remove the region starting at `addr`, if any.
    pub fn remove(&mut self, addr: Address) -> Option<VmRegion> {
        self.regions.remove(&addr.0)
    }

    /// Find the region that contains `addr`.
    #[must_use]
    pub fn find(&self, addr: Address) -> Option<&VmRegion> {
        // The region with start <= addr comes from a range query.
        let v = addr.0;
        self.regions
            .range(..=v)
            .next_back()
            .map(|(_, r)| r)
            .filter(|r| r.contains(addr))
    }

    /// Mutable reference to the region containing `addr`.
    #[must_use]
    pub fn find_mut(&mut self, addr: Address) -> Option<&mut VmRegion> {
        let v = addr.0;
        let key = self.regions.range(..=v).next_back().map(|(k, _)| *k)?;
        let region = self.regions.get_mut(&key)?;
        if region.contains(addr) {
            Some(region)
        } else {
            None
        }
    }

    /// All regions that intersect `range`.
    #[must_use]
    pub fn intersecting(&self, range: AddressRange) -> Vec<&VmRegion> {
        self.regions
            .values()
            .filter(|r| r.range.start < range.end && r.range.end > range.start)
            .collect()
    }

    /// Returns `true` if any existing region overlaps `region`.
    #[must_use]
    pub fn overlaps(&self, region: &VmRegion) -> bool {
        !self.intersecting(region.range).is_empty()
    }

    /// Merge adjacent regions that are identical in permissions, kind, and
    /// committed state.  Returns the number of merges performed.
    pub fn merge_adjacent(&mut self) -> usize {
        let mut merges = 0usize;
        loop {
            let keys: Vec<u64> = self.regions.keys().copied().collect();
            let mut merged_any = false;

            for pair in keys.windows(2) {
                let (k0, k1) = (pair[0], pair[1]);
                let r0 = match self.regions.get(&k0) {
                    Some(r) => r.clone(),
                    None => continue,
                };
                let r1 = match self.regions.get(&k1) {
                    Some(r) => r.clone(),
                    None => continue,
                };
                if let Some(merged) = r0.try_merge(&r1) {
                    self.regions.remove(&k0);
                    self.regions.remove(&k1);
                    self.regions.insert(merged.range.start.0, merged);
                    merges += 1;
                    merged_any = true;
                    break; // restart the loop since BTreeMap changed
                }
            }

            if !merged_any {
                break;
            }
        }
        merges
    }

    /// Split the region containing `split_addr` at `split_addr`.  Returns
    /// `true` on success.
    ///
    /// # Errors
    /// Returns `Err` if `split_addr` is not strictly inside any existing region.
    pub fn split_at(&mut self, split_addr: Address) -> Result<(), VmMapError> {
        let key = {
            let region = self.find(split_addr).ok_or(VmMapError)?;
            if split_addr <= region.range.start || split_addr >= region.range.end {
                return Err(VmMapError);
            }
            region.range.start.0
        };
        let region = self.regions.remove(&key).unwrap();
        let (left, right) = region.split_at(split_addr)?;
        self.regions.insert(left.range.start.0, left);
        self.regions.insert(right.range.start.0, right);
        Ok(())
    }

    /// Iterator over all regions in ascending address order.
    pub fn iter(&self) -> impl Iterator<Item = &VmRegion> {
        self.regions.values()
    }

    /// All regions with the given kind.
    #[must_use]
    pub fn by_kind(&self, kind: VmRegionKind) -> Vec<&VmRegion> {
        self.regions.values().filter(|r| r.kind == kind).collect()
    }

    /// All regions with the given permissions (exact match).
    #[must_use]
    pub fn by_perms(&self, perms: Permissions) -> Vec<&VmRegion> {
        self.regions.values().filter(|r| r.perms == perms).collect()
    }

    /// All executable regions.
    #[must_use]
    pub fn executable(&self) -> Vec<&VmRegion> {
        self.regions
            .values()
            .filter(|r| r.perms.is_executable())
            .collect()
    }

    /// All writable regions.
    #[must_use]
    pub fn writable(&self) -> Vec<&VmRegion> {
        self.regions
            .values()
            .filter(|r| r.perms.is_writable())
            .collect()
    }

    /// Compute the "holes" (unmapped ranges) between consecutive regions.
    #[must_use]
    pub fn holes(&self) -> Vec<AddressRange> {
        let mut result = Vec::new();
        let regions: Vec<&VmRegion> = self.regions.values().collect();
        for window in regions.windows(2) {
            let end = window[0].range.end;
            let start = window[1].range.start;
            if start > end {
                result.push(AddressRange::new(end, start));
            }
        }
        result
    }

    /// Change the permissions of all pages in `range` to `new_perms`.  Splits
    /// existing regions at `range` boundaries as needed.
    ///
    /// # Errors
    /// Returns `Err(())` if no region covers the entire `range`.
    pub fn mprotect(&mut self, range: AddressRange, new_perms: Permissions) -> Result<(), VmMapError> {
        // Split at range.start and range.end if they fall inside existing regions.
        let _ = self.split_at(range.start);
        let _ = self.split_at(range.end);

        let keys: Vec<u64> = self
            .regions
            .range(range.start.0..range.end.0)
            .map(|(k, _)| *k)
            .collect();

        if keys.is_empty() {
            return Err(VmMapError);
        }

        for k in keys {
            if let Some(r) = self.regions.get_mut(&k) {
                r.perms = new_perms;
            }
        }
        Ok(())
    }

    /// Remove all regions whose range is entirely within `range`.
    pub fn unmap(&mut self, range: AddressRange) {
        let _ = self.split_at(range.start);
        let _ = self.split_at(range.end);

        let keys: Vec<u64> = self
            .regions
            .range(range.start.0..range.end.0)
            .map(|(k, _)| *k)
            .collect();

        for k in keys {
            self.regions.remove(&k);
        }
    }

    /// Serialise to a JSON string.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialise from a JSON string.
    ///
    /// # Errors
    /// Returns an error if deserialization fails.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Statistics snapshot.
    #[must_use]
    pub fn stats(&self) -> VmMapStats {
        VmMapStats::compute(self)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VmMapStats
// ─────────────────────────────────────────────────────────────────────────────

/// High-level statistics for a `VmMap`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmMapStats {
    pub region_count: usize,
    pub total_bytes: u64,
    pub executable_bytes: u64,
    pub writable_bytes: u64,
    pub readable_bytes: u64,
    pub code_region_count: usize,
    pub stack_region_count: usize,
    pub heap_region_count: usize,
    pub hole_count: usize,
    pub total_hole_bytes: u64,
}

impl VmMapStats {
    /// Compute statistics for a `VmMap`.
    #[must_use]
    pub fn compute(map: &VmMap) -> Self {
        let mut stats = Self {
            region_count: map.len(),
            total_bytes: 0,
            executable_bytes: 0,
            writable_bytes: 0,
            readable_bytes: 0,
            code_region_count: 0,
            stack_region_count: 0,
            heap_region_count: 0,
            hole_count: 0,
            total_hole_bytes: 0,
        };

        for r in map.iter() {
            let len = r.len();
            stats.total_bytes += len;
            if r.perms.is_executable() {
                stats.executable_bytes += len;
            }
            if r.perms.is_writable() {
                stats.writable_bytes += len;
            }
            if r.perms.is_readable() {
                stats.readable_bytes += len;
            }
            match r.kind {
                VmRegionKind::Code => stats.code_region_count += 1,
                VmRegionKind::Stack => stats.stack_region_count += 1,
                VmRegionKind::Heap => stats.heap_region_count += 1,
                _ => {}
            }
        }

        let holes = map.holes();
        stats.hole_count = holes.len();
        stats.total_hole_bytes = holes.iter().map(AddressRange::len).sum();
        stats
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn rng(start: u64, end: u64) -> AddressRange {
        AddressRange::new(Address::new(start), Address::new(end))
    }

    fn code(start: u64, end: u64) -> VmRegion {
        VmRegion::new(
            rng(start, end),
            Permissions::READ | Permissions::EXECUTE,
            VmRegionKind::Code,
        )
    }

    fn data(start: u64, end: u64) -> VmRegion {
        VmRegion::new(
            rng(start, end),
            Permissions::READ | Permissions::WRITE,
            VmRegionKind::Data,
        )
    }

    #[test]
    fn test_vmregion_contains() {
        let r = code(0x1000, 0x2000);
        assert!(r.contains(Address::new(0x1000)));
        assert!(r.contains(Address::new(0x1FFF)));
        assert!(!r.contains(Address::new(0x2000)));
    }

    #[test]
    fn test_vmregion_overlaps() {
        let a = code(0x1000, 0x2000);
        let b = data(0x1800, 0x3000);
        assert!(a.overlaps(&b));
        let c = data(0x2000, 0x3000);
        assert!(!a.overlaps(&c));
    }

    #[test]
    fn test_vmregion_try_merge_success() {
        let a = code(0x1000, 0x2000);
        let b = code(0x2000, 0x3000);
        let m = a.try_merge(&b).expect("should merge");
        assert_eq!(m.range.start, Address::new(0x1000));
        assert_eq!(m.range.end, Address::new(0x3000));
    }

    #[test]
    fn test_vmregion_try_merge_fail_different_perms() {
        let a = code(0x1000, 0x2000);
        let b = data(0x2000, 0x3000);
        assert!(a.try_merge(&b).is_none());
    }

    #[test]
    fn test_vmregion_try_merge_fail_gap() {
        let a = code(0x1000, 0x2000);
        let b = code(0x3000, 0x4000);
        assert!(a.try_merge(&b).is_none());
    }

    #[test]
    fn test_vmregion_split_at() {
        let r = code(0x1000, 0x3000);
        let (l, rr) = r.split_at(Address::new(0x2000)).unwrap();
        assert_eq!(l.range.end, Address::new(0x2000));
        assert_eq!(rr.range.start, Address::new(0x2000));
    }

    #[test]
    fn test_vmregion_split_at_error() {
        let r = code(0x1000, 0x3000);
        assert!(r.split_at(Address::new(0x1000)).is_err()); // at start
        assert!(r.split_at(Address::new(0x3000)).is_err()); // at end
        assert!(r.split_at(Address::new(0x500)).is_err()); // before
    }

    #[test]
    fn test_vmmap_insert_find() {
        let mut map = VmMap::new();
        map.insert(code(0x1000, 0x2000));
        map.insert(data(0x3000, 0x4000));
        assert_eq!(map.len(), 2);
        assert!(map.find(Address::new(0x1500)).is_some());
        assert!(map.find(Address::new(0x2000)).is_none()); // exclusive end
        assert!(map.find(Address::new(0x3500)).is_some());
    }

    #[test]
    fn test_vmmap_merge_adjacent() {
        let mut map = VmMap::new();
        map.insert(code(0x1000, 0x2000));
        map.insert(code(0x2000, 0x3000));
        let merges = map.merge_adjacent();
        assert_eq!(merges, 1);
        assert_eq!(map.len(), 1);
        assert!(map.find(Address::new(0x2500)).is_some());
    }

    #[test]
    fn test_vmmap_split_at() {
        let mut map = VmMap::new();
        map.insert(code(0x1000, 0x4000));
        map.split_at(Address::new(0x2000)).unwrap();
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_vmmap_mprotect() {
        let mut map = VmMap::new();
        map.insert(code(0x1000, 0x4000));
        let range = rng(0x2000, 0x3000);
        map.mprotect(range, Permissions::READ | Permissions::WRITE)
            .unwrap();
        // Middle piece now has RW
        let r = map.find(Address::new(0x2500)).unwrap();
        assert!(r.perms.is_writable());
        assert!(!r.perms.is_executable());
    }

    #[test]
    fn test_vmmap_unmap() {
        let mut map = VmMap::new();
        map.insert(code(0x1000, 0x5000));
        map.unmap(rng(0x2000, 0x4000));
        assert!(map.find(Address::new(0x3000)).is_none());
        assert!(map.find(Address::new(0x1500)).is_some());
        assert!(map.find(Address::new(0x4500)).is_some());
    }

    #[test]
    fn test_vmmap_holes() {
        let mut map = VmMap::new();
        map.insert(code(0x1000, 0x2000));
        map.insert(data(0x4000, 0x5000));
        let holes = map.holes();
        assert_eq!(holes.len(), 1);
        assert_eq!(holes[0].start, Address::new(0x2000));
        assert_eq!(holes[0].end, Address::new(0x4000));
    }

    #[test]
    fn test_vmmap_stats() {
        let mut map = VmMap::new();
        map.insert(code(0x1000, 0x2000));
        map.insert(data(0x3000, 0x4000));
        let stats = map.stats();
        assert_eq!(stats.region_count, 2);
        assert_eq!(stats.total_bytes, 0x2000);
        assert_eq!(stats.executable_bytes, 0x1000);
        assert_eq!(stats.writable_bytes, 0x1000);
    }

    #[test]
    fn test_vmmap_json_roundtrip() {
        let mut map = VmMap::new();
        map.insert(code(0x1000, 0x2000));
        let json = map.to_json().unwrap();
        let back = VmMap::from_json(&json).unwrap();
        assert_eq!(back.len(), 1);
    }

    #[test]
    fn test_vmmap_by_kind() {
        let mut map = VmMap::new();
        map.insert(code(0x1000, 0x2000));
        map.insert(VmRegion::new(
            rng(0x3000, 0x4000),
            Permissions::READ | Permissions::WRITE,
            VmRegionKind::Heap,
        ));
        assert_eq!(map.by_kind(VmRegionKind::Code).len(), 1);
        assert_eq!(map.by_kind(VmRegionKind::Heap).len(), 1);
        assert_eq!(map.by_kind(VmRegionKind::Stack).len(), 0);
    }

    #[test]
    fn test_vmmap_intersecting() {
        let mut map = VmMap::new();
        map.insert(code(0x1000, 0x3000));
        map.insert(data(0x5000, 0x7000));
        let hits = map.intersecting(rng(0x2000, 0x6000));
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn test_vm_region_kind_display() {
        assert_eq!(VmRegionKind::Code.to_string(), "code");
        assert_eq!(VmRegionKind::Heap.to_string(), "heap");
    }
}
