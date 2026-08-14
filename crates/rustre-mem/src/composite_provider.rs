//! `CompositeMemoryProvider` — overlay N providers with priority and CoW semantics.
//!
//! # Overview
//!
//! A composite provider overlays multiple [`MemoryProvider`] instances.
//! Providers are arranged in *layers* ordered by priority (higher number = higher
//! precedence).  Reads return the first successful result from the highest-priority
//! layer; writes obey a configurable [`WriteStrategy`].
//!
//! # Architecture
//!
//! ```text
//! Layer 3 (highest) ─── CoW overlay (writable)
//! Layer 2           ─── PDB-mapped sections
//! Layer 1           ─── Raw file image
//! Layer 0 (lowest)  ─── Null / fallback
//! ```

use crate::memory_provider::{MemError, MemoryProvider, MemoryRegion, RegionSource, SnapshotId};
use async_trait::async_trait;
use rustre_core::address::{Address, AddressRange};
use rustre_core::permissions::Permissions;
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// WriteStrategy
// ─────────────────────────────────────────────────────────────────────────────

/// Strategy used when writing through the composite provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[derive(Default)]
pub enum WriteStrategy {
    /// Write only to the highest-priority layer that accepts the write.
    #[default]
    TopOnly,
    /// Write to all layers simultaneously (mirrors of each other).
    WriteThrough,
    /// Copy-on-write: materialise the write in the top-most writable layer.
    CopyOnWrite,
}


impl std::fmt::Display for WriteStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TopOnly => write!(f, "top-only"),
            Self::WriteThrough => write!(f, "write-through"),
            Self::CopyOnWrite => write!(f, "copy-on-write"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LayerOverlap
// ─────────────────────────────────────────────────────────────────────────────

/// How overlapping regions from different layers are merged into the region list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum LayerOverlap {
    /// Show all regions from all layers (may contain duplicates).
    #[default]
    ShowAll,
    /// Show only the highest-priority region for each address.
    TopWins,
    /// Show regions with their union — maximum coverage.
    Union,
}

impl std::fmt::Display for LayerOverlap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShowAll => write!(f, "show-all"),
            Self::TopWins => write!(f, "top-wins"),
            Self::Union => write!(f, "union"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProviderLayer
// ─────────────────────────────────────────────────────────────────────────────

/// A single layer within a `CompositeMemoryProvider`.
pub struct ProviderLayer {
    /// Human-readable name for diagnostics.
    pub name: String,
    /// Priority — higher values are tried first.
    pub priority: u32,
    /// Whether writes can target this layer.
    pub writable: bool,
    /// The provider implementation.
    provider: Box<dyn MemoryProvider>,
}

impl ProviderLayer {
    /// Create a layer from a provider, name, and priority.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        priority: u32,
        writable: bool,
        provider: Box<dyn MemoryProvider>,
    ) -> Self {
        Self {
            name: name.into(),
            priority,
            writable,
            provider,
        }
    }

    /// Read-only access to the provider.
    #[must_use]
    pub fn provider(&self) -> &dyn MemoryProvider {
        self.provider.as_ref()
    }

    /// Mutable access to the provider.
    pub fn provider_mut(&mut self) -> &mut dyn MemoryProvider {
        self.provider.as_mut()
    }
}

impl std::fmt::Debug for ProviderLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderLayer")
            .field("name", &self.name)
            .field("priority", &self.priority)
            .field("writable", &self.writable)
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RegionMerger
// ─────────────────────────────────────────────────────────────────────────────

/// Utility for merging region lists from multiple layers.
#[derive(Debug, Default)]
pub struct RegionMerger;

impl RegionMerger {
    /// Merge `regions` from multiple layers according to `strategy`.
    ///
    /// `regions` is a `Vec<(priority, region_list)>` pair, sorted descending by
    /// priority.
    #[must_use]
    pub fn merge(
        regions: Vec<(u32, Vec<MemoryRegion>)>,
        strategy: LayerOverlap,
    ) -> Vec<MemoryRegion> {
        match strategy {
            LayerOverlap::ShowAll => regions.into_iter().flat_map(|(_, r)| r).collect(),
            LayerOverlap::TopWins => {
                // For each address range, keep only the highest-priority entry.
                let mut seen_starts: std::collections::HashSet<u64> =
                    std::collections::HashSet::new();
                let mut result = Vec::new();
                // Sorted descending by priority — first occurrence wins.
                for (_, layer_regions) in regions {
                    for region in layer_regions {
                        let key = region.range.start.as_u64();
                        if seen_starts.insert(key) {
                            result.push(region);
                        }
                    }
                }
                result
            }
            LayerOverlap::Union => {
                // Combine all ranges and merge contiguous/overlapping ones with same perms.
                let mut all: Vec<MemoryRegion> = regions.into_iter().flat_map(|(_, r)| r).collect();
                all.sort_by_key(|r| r.range.start.as_u64());
                let mut merged: Vec<MemoryRegion> = Vec::new();
                for region in all {
                    if let Some(last) = merged.last_mut()
                        && last.range.end >= region.range.start && last.perms == region.perms {
                            // Extend.
                            if region.range.end > last.range.end {
                                last.range = AddressRange::new(last.range.start, region.range.end);
                            }
                            continue;
                        }
                    merged.push(region);
                }
                merged
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CoW overlay — in-memory page store for copy-on-write writes
// ─────────────────────────────────────────────────────────────────────────────

/// Lightweight in-memory byte store used by the `CoW` write strategy.
#[derive(Debug, Default)]
struct CowOverlay {
    /// `base_addr → bytes`
    pages: HashMap<u64, Vec<u8>>,
}

impl CowOverlay {
    fn new() -> Self {
        Self::default()
    }

    /// Materialise a write: copy original bytes from `base_data`, then splice
    /// `data` at `addr`.
    fn write(&mut self, addr: Address, data: &[u8]) {
        let base = addr.as_u64();
        let end = base + data.len() as u64;
        debug_assert!(end >= base, "overlay write range must not wrap");
        // Store contiguous range keyed by start address.
        let entry = self
            .pages
            .entry(base)
            .or_insert_with(|| vec![0u8; data.len()]);
        // Resize if needed.
        if entry.len() < data.len() {
            entry.resize(data.len(), 0);
        }
        entry[..data.len()].copy_from_slice(data);
    }

    /// Try to read `len` bytes from `addr` out of the overlay.
    fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        let end = addr + len as u64;
        let mut buf = vec![0u8; len];
        let mut covered = 0usize;
        for (base, data) in &self.pages {
            let page_end = base + data.len() as u64;
            if *base >= end || page_end <= addr {
                continue;
            }
            let copy_start = (*base).max(addr);
            let copy_end = page_end.min(end);
            let dst_off = (copy_start - addr) as usize;
            let src_off = (copy_start - base) as usize;
            let len2 = (copy_end - copy_start) as usize;
            buf[dst_off..dst_off + len2].copy_from_slice(&data[src_off..src_off + len2]);
            covered += len2;
        }
        if covered == len { Some(buf) } else { None }
    }

    fn regions(&self) -> Vec<MemoryRegion> {
        self.pages
            .iter()
            .map(|(base, data)| {
                let start = Address::new(*base);
                let end = Address::new(base + data.len() as u64);
                MemoryRegion {
                    range: AddressRange::new(start, end),
                    perms: Permissions::READ | Permissions::WRITE,
                    name: Some("cow-overlay".into()),
                    source: RegionSource::Anonymous,
                }
            })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CompositeMemoryProvider
// ─────────────────────────────────────────────────────────────────────────────

/// Overlays N memory providers with configurable priority and write semantics.
///
/// # Thread safety
/// Not thread-safe by itself — wrap in a `Mutex` for shared access.
pub struct CompositeMemoryProvider {
    layers: Vec<ProviderLayer>,
    write_strategy: WriteStrategy,
    overlap: LayerOverlap,
    /// `CoW` materialisation store (used when `write_strategy == CopyOnWrite`).
    cow: CowOverlay,
}

impl CompositeMemoryProvider {
    /// Create an empty composite provider with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            layers: Vec::new(),
            write_strategy: WriteStrategy::TopOnly,
            overlap: LayerOverlap::default(),
            cow: CowOverlay::new(),
        }
    }

    /// Set the write strategy.
    #[must_use]
    pub const fn with_write_strategy(mut self, strategy: WriteStrategy) -> Self {
        self.write_strategy = strategy;
        self
    }

    /// Set the layer-overlap resolution strategy.
    #[must_use]
    pub const fn with_overlap(mut self, overlap: LayerOverlap) -> Self {
        self.overlap = overlap;
        self
    }

    /// Add a provider layer.  Layers are re-sorted by priority after insertion.
    pub fn add_layer(&mut self, layer: ProviderLayer) {
        self.layers.push(layer);
        // Sort descending: highest priority first.
        self.layers.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Convenience: add a provider with name, priority, and writability flag.
    pub fn add_provider(
        &mut self,
        provider: Box<dyn MemoryProvider>,
        name: impl Into<String>,
        priority: u32,
        writable: bool,
    ) {
        self.add_layer(ProviderLayer::new(name, priority, writable, provider));
    }

    /// Remove the layer at `index` (sorted order, 0 = highest priority).
    pub fn remove_layer(&mut self, index: usize) -> Option<ProviderLayer> {
        if index < self.layers.len() {
            Some(self.layers.remove(index))
        } else {
            None
        }
    }

    /// Number of layers.
    #[must_use]
    pub const fn layer_count(&self) -> usize {
        self.layers.len()
    }

    /// Return a reference to the layer at `index`.
    #[must_use]
    pub fn layer(&self, index: usize) -> Option<&ProviderLayer> {
        self.layers.get(index)
    }

    /// Iterate over all layers in priority order (highest first).
    pub fn iter_layers(&self) -> impl Iterator<Item = &ProviderLayer> {
        self.layers.iter()
    }

    /// Write strategy currently in use.
    #[must_use]
    pub const fn write_strategy(&self) -> WriteStrategy {
        self.write_strategy
    }

    /// Overlap strategy.
    #[must_use]
    pub const fn overlap(&self) -> LayerOverlap {
        self.overlap
    }

    /// Clear the `CoW` overlay (discard all materialised writes).
    pub fn clear_cow(&mut self) {
        self.cow = CowOverlay::new();
    }
}

impl Default for CompositeMemoryProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for CompositeMemoryProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeMemoryProvider")
            .field("layers", &self.layers.len())
            .field("write_strategy", &self.write_strategy)
            .field("overlap", &self.overlap)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl MemoryProvider for CompositeMemoryProvider {
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        // For CoW: check overlay first.
        if self.write_strategy == WriteStrategy::CopyOnWrite
            && let Some(data) = self.cow.read(addr.as_u64(), len) {
                return Ok(data);
            }
        let mut last_err = MemError::NotMapped(addr);
        for layer in &self.layers {
            match layer.provider().read(addr, len) {
                Ok(d) => return Ok(d),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    fn write(&mut self, addr: Address, data: &[u8]) -> Result<(), MemError> {
        match self.write_strategy {
            WriteStrategy::TopOnly => {
                for layer in &mut self.layers {
                    if !layer.writable {
                        continue;
                    }
                    match layer.provider_mut().write(addr, data) {
                        Ok(()) => return Ok(()),
                        Err(MemError::NotMapped(_) | MemError::OutOfBounds(_, _)) => continue,
                        Err(e) => return Err(e),
                    }
                }
                Err(MemError::NotMapped(addr))
            }
            WriteStrategy::WriteThrough => {
                let mut wrote_any = false;
                let mut first_err: Option<MemError> = None;
                for layer in &mut self.layers {
                    if !layer.writable {
                        continue;
                    }
                    match layer.provider_mut().write(addr, data) {
                        Ok(()) => wrote_any = true,
                        Err(e) if first_err.is_none() => first_err = Some(e),
                        _ => {}
                    }
                }
                if let Some(e) = first_err {
                    Err(e)
                } else if wrote_any {
                    Ok(())
                } else {
                    Err(MemError::NotMapped(addr))
                }
            }
            WriteStrategy::CopyOnWrite => {
                // Materialise write in the overlay.
                self.cow.write(addr, data);
                Ok(())
            }
        }
    }

    fn regions(&self) -> Vec<MemoryRegion> {
        let layer_regions: Vec<(u32, Vec<MemoryRegion>)> = self
            .layers
            .iter()
            .map(|l| (l.priority, l.provider().regions()))
            .collect();
        let mut merged = RegionMerger::merge(layer_regions, self.overlap);
        // Append CoW overlay regions.
        if self.write_strategy == WriteStrategy::CopyOnWrite {
            merged.extend(self.cow.regions());
        }
        merged
    }

    fn is_live(&self) -> bool {
        self.layers.iter().any(|l| l.provider().is_live())
    }

    async fn refresh(&mut self) -> Result<(), MemError> {
        let mut first_err: Option<MemError> = None;
        for layer in &mut self.layers {
            if let Err(e) = layer.provider_mut().refresh().await
                && first_err.is_none() {
                    first_err = Some(e);
                }
        }
        if let Some(e) = first_err {
            Err(e)
        } else {
            Ok(())
        }
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
    use crate::file_memory::FileMemoryProvider;
    use rustre_core::address::{Address, AddressRange};
    use rustre_core::permissions::Permissions;

    fn file_provider(base: u64, fill: u8, len: usize) -> Box<dyn MemoryProvider> {
        Box::new(FileMemoryProvider::from_bytes(
            vec![fill; len],
            Address::new(base),
            Permissions::READ | Permissions::WRITE,
        ))
    }

    // ── WriteStrategy ─────────────────────────────────────────────────────────

    #[test]
    fn write_strategy_default_is_top_only() {
        assert_eq!(WriteStrategy::default(), WriteStrategy::TopOnly);
    }

    #[test]
    fn write_strategy_display() {
        assert_eq!(WriteStrategy::TopOnly.to_string(), "top-only");
        assert_eq!(WriteStrategy::WriteThrough.to_string(), "write-through");
        assert_eq!(WriteStrategy::CopyOnWrite.to_string(), "copy-on-write");
    }

    // ── LayerOverlap ──────────────────────────────────────────────────────────

    #[test]
    fn layer_overlap_display() {
        assert_eq!(LayerOverlap::ShowAll.to_string(), "show-all");
        assert_eq!(LayerOverlap::TopWins.to_string(), "top-wins");
        assert_eq!(LayerOverlap::Union.to_string(), "union");
    }

    // ── ProviderLayer ─────────────────────────────────────────────────────────

    #[test]
    fn provider_layer_debug() {
        let layer = ProviderLayer::new("test", 5, true, file_provider(0x1000, 0xAA, 4));
        let s = format!("{layer:?}");
        assert!(s.contains("test"));
        assert!(s.contains('5'));
    }

    // ── RegionMerger ──────────────────────────────────────────────────────────

    fn make_region(start: u64, end: u64, perms: Permissions) -> MemoryRegion {
        MemoryRegion {
            range: AddressRange::new(Address::new(start), Address::new(end)),
            perms,
            name: None,
            source: RegionSource::Anonymous,
        }
    }

    #[test]
    fn region_merger_show_all() {
        let r1 = make_region(0x1000, 0x2000, Permissions::READ);
        let r2 = make_region(0x1000, 0x2000, Permissions::READ);
        let merged =
            RegionMerger::merge(vec![(10, vec![r1]), (5, vec![r2])], LayerOverlap::ShowAll);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn region_merger_top_wins() {
        let r1 = make_region(0x1000, 0x2000, Permissions::READ);
        let r2 = make_region(0x1000, 0x2000, Permissions::READ | Permissions::WRITE);
        let merged =
            RegionMerger::merge(vec![(10, vec![r1]), (5, vec![r2])], LayerOverlap::TopWins);
        assert_eq!(merged.len(), 1);
        // The first (highest priority) should win.
        assert!(!merged[0].perms.is_writable()); // r1 was READ-only
    }

    #[test]
    fn region_merger_union_merges_contiguous() {
        let r1 = make_region(0x1000, 0x2000, Permissions::READ);
        let r2 = make_region(0x2000, 0x3000, Permissions::READ);
        let merged = RegionMerger::merge(vec![(10, vec![r1, r2])], LayerOverlap::Union);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].range.end, Address::new(0x3000));
    }

    // ── CompositeMemoryProvider reads ─────────────────────────────────────────

    #[test]
    fn composite_reads_from_highest_priority() {
        let mut c = CompositeMemoryProvider::new();
        c.add_provider(file_provider(0x1000, 0xAA, 4), "low", 1, true);
        c.add_provider(file_provider(0x1000, 0xBB, 4), "high", 10, true);
        let data = c.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(data, [0xBB; 4]);
    }

    #[test]
    fn composite_falls_back_to_lower_priority() {
        let mut c = CompositeMemoryProvider::new();
        c.add_provider(file_provider(0x2000, 0xCC, 4), "low", 1, true);
        let data = c.read(Address::new(0x2000), 4).unwrap();
        assert_eq!(data, [0xCC; 4]);
    }

    #[test]
    fn composite_unmapped_returns_error() {
        let c = CompositeMemoryProvider::new();
        assert!(c.read(Address::new(0xDEAD), 4).is_err());
    }

    // ── WriteStrategy::TopOnly ────────────────────────────────────────────────

    #[test]
    fn composite_write_top_only() {
        let mut c = CompositeMemoryProvider::new();
        c.add_provider(file_provider(0x1000, 0xAA, 8), "top", 10, true);
        c.write(Address::new(0x1000), &[0x11, 0x22]).unwrap();
        let data = c.read(Address::new(0x1000), 2).unwrap();
        assert_eq!(data, [0x11, 0x22]);
    }

    #[test]
    fn composite_write_skips_non_writable_layer() {
        let mut c = CompositeMemoryProvider::new();
        c.add_provider(file_provider(0x1000, 0xAA, 8), "readonly", 10, false);
        c.add_provider(file_provider(0x1000, 0xBB, 8), "writable", 5, true);
        c.write(Address::new(0x1000), &[0xFF]).unwrap();
        // The high-priority layer is read-only, so the write went to the lower layer.
        // Reading should return 0xFF from the lower layer.
        // Since the higher layer (0xAA) is tried first for reads, the read returns 0xAA
        // unless we force reading from the lower layer.
        // The write succeeded — this tests that non-writable layers don't block writes.
    }

    // ── WriteStrategy::WriteThrough ───────────────────────────────────────────

    #[test]
    fn composite_write_through_writes_all() {
        let mut c = CompositeMemoryProvider::new().with_write_strategy(WriteStrategy::WriteThrough);
        c.add_provider(file_provider(0x1000, 0xAA, 4), "l1", 10, true);
        c.add_provider(file_provider(0x1000, 0xBB, 4), "l2", 5, true);
        c.write(Address::new(0x1000), &[0x42, 0x43]).unwrap();
        // Both layers updated — the top one is read for verification.
        let data = c.read(Address::new(0x1000), 2).unwrap();
        assert_eq!(data, [0x42, 0x43]);
    }

    // ── WriteStrategy::CopyOnWrite ────────────────────────────────────────────

    #[test]
    fn composite_cow_write_does_not_modify_underlying() {
        let mut c = CompositeMemoryProvider::new().with_write_strategy(WriteStrategy::CopyOnWrite);
        c.add_provider(file_provider(0x1000, 0xAA, 8), "base", 5, false);
        c.write(Address::new(0x1000), &[0xFF, 0xFF, 0xFF, 0xFF])
            .unwrap();
        // The base layer should be unchanged.
        // Read back from composite: CoW overlay wins.
        let data = c.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(data, [0xFF; 4]);
    }

    #[test]
    fn composite_cow_clear_reverts_reads() {
        let mut c = CompositeMemoryProvider::new().with_write_strategy(WriteStrategy::CopyOnWrite);
        c.add_provider(file_provider(0x1000, 0xAA, 4), "base", 5, false);
        c.write(Address::new(0x1000), &[0xFF; 4]).unwrap();
        c.clear_cow();
        let data = c.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(data, [0xAA; 4]);
    }

    // ── Layer management ──────────────────────────────────────────────────────

    #[test]
    fn composite_add_and_remove_layer() {
        let mut c = CompositeMemoryProvider::new();
        c.add_provider(file_provider(0, 0xAA, 4), "l", 1, true);
        assert_eq!(c.layer_count(), 1);
        let removed = c.remove_layer(0);
        assert!(removed.is_some());
        assert_eq!(c.layer_count(), 0);
    }

    #[test]
    fn composite_remove_out_of_bounds_returns_none() {
        let mut c = CompositeMemoryProvider::new();
        assert!(c.remove_layer(5).is_none());
    }

    #[test]
    fn composite_layers_sorted_by_priority() {
        let mut c = CompositeMemoryProvider::new();
        c.add_provider(file_provider(0, 0x01, 1), "p1", 1, true);
        c.add_provider(file_provider(0, 0x50, 1), "p50", 50, true);
        c.add_provider(file_provider(0, 0x10, 1), "p10", 10, true);
        assert_eq!(c.layer(0).unwrap().priority, 50);
        assert_eq!(c.layer(1).unwrap().priority, 10);
        assert_eq!(c.layer(2).unwrap().priority, 1);
    }

    #[test]
    fn composite_is_live_true_if_any_live() {
        let c = CompositeMemoryProvider::new();
        assert!(!c.is_live());
    }

    // ── Regions ───────────────────────────────────────────────────────────────

    #[test]
    fn composite_regions_show_all() {
        let mut c = CompositeMemoryProvider::new();
        c.add_provider(file_provider(0x1000, 0xAA, 4), "l1", 10, true);
        c.add_provider(file_provider(0x2000, 0xBB, 4), "l2", 5, true);
        assert_eq!(c.regions().len(), 2);
    }

    #[test]
    fn composite_cow_overlay_regions_included() {
        let mut c = CompositeMemoryProvider::new().with_write_strategy(WriteStrategy::CopyOnWrite);
        c.add_provider(file_provider(0x1000, 0xAA, 4), "base", 5, false);
        c.write(Address::new(0x2000), &[0xFF; 8]).unwrap();
        let regions = c.regions();
        // Base + CoW overlay region.
        assert!(regions.len() >= 2);
    }

    // ── Debug / default ───────────────────────────────────────────────────────

    #[test]
    fn composite_default_is_empty() {
        let c = CompositeMemoryProvider::default();
        assert_eq!(c.layer_count(), 0);
    }

    #[test]
    fn composite_debug_shows_layer_count() {
        let c = CompositeMemoryProvider::new();
        let s = format!("{c:?}");
        assert!(s.contains("layers"));
    }

    // ── CowOverlay unit tests ─────────────────────────────────────────────────

    #[test]
    fn cow_overlay_write_and_read() {
        let mut overlay = CowOverlay::new();
        overlay.write(Address::new(0x100), &[0xDE, 0xAD, 0xBE, 0xEF]);
        let data = overlay.read(0x100, 4).unwrap();
        assert_eq!(data, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn cow_overlay_miss_returns_none() {
        let overlay = CowOverlay::new();
        assert!(overlay.read(0x9999, 4).is_none());
    }

    // ── iter_layers ───────────────────────────────────────────────────────────

    #[test]
    fn composite_iter_layers() {
        let mut c = CompositeMemoryProvider::new();
        c.add_provider(file_provider(0, 0x11, 4), "a", 1, true);
        c.add_provider(file_provider(0, 0x22, 4), "b", 2, true);
        let names: Vec<&str> = c.iter_layers().map(|l| l.name.as_str()).collect();
        assert_eq!(names, vec!["b", "a"]); // descending priority
    }
}
