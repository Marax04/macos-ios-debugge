//! `PatchedMemoryProvider` — applies a `PatchSet` on top of any provider.
//!
//! # Overview
//!
//! A `PatchedMemoryProvider` wraps an inner [`MemoryProvider`] and applies
//! byte-level patches before returning read results.  Writes pass through to
//! the inner provider; overlapping patches are updated in-place to stay
//! consistent with writes.
//!
//! # Key types
//!
//! | Type | Role |
//! |------|------|
//! | [`Patch`] | Address, original bytes, and replacement bytes |
//! | [`PatchConflict`] | Error returned when patches overlap |
//! | [`PatchOverlay`] | Per-address patch store with conflict detection |
//! | [`PatchExport`] | Binary diff format (sequence of `(addr, before, after)`) |
//! | [`PatchedMemoryProvider`] | Full `MemoryProvider` wrapping a base provider |

use crate::memory_provider::{MemError, MemoryProvider, MemoryRegion, SnapshotId};
use async_trait::async_trait;
use rustre_core::address::Address;
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Patch
// ─────────────────────────────────────────────────────────────────────────────

/// A single binary patch: address, original bytes, and replacement bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch {
    /// Virtual address of the patched region.
    pub address: u64,
    /// Bytes originally at `address` (before the patch was applied).
    pub original: Vec<u8>,
    /// Replacement bytes written over the original.
    pub replacement: Vec<u8>,
    /// Optional human-readable annotation.
    pub annotation: Option<String>,
    /// Whether this patch is currently applied (active).
    pub active: bool,
}

impl Patch {
    /// Create a new, active patch.
    #[must_use]
    pub const fn new(address: u64, original: Vec<u8>, replacement: Vec<u8>) -> Self {
        Self {
            address,
            original,
            replacement,
            annotation: None,
            active: true,
        }
    }

    /// Attach an annotation.
    #[must_use]
    pub fn with_annotation(mut self, ann: impl Into<String>) -> Self {
        self.annotation = Some(ann.into());
        self
    }

    /// Mark the patch as inactive (will not be applied on reads).
    #[must_use]
    pub const fn disabled(mut self) -> Self {
        self.active = false;
        self
    }

    /// Number of bytes affected.
    #[must_use]
    pub fn len(&self) -> usize {
        self.replacement.len().max(self.original.len())
    }

    /// Returns `true` when [`len`](Self::len) is zero.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Exclusive end address of the patch.
    #[must_use]
    pub fn end_address(&self) -> u64 {
        self.address + self.len() as u64
    }

    /// Return `true` if `addr` falls within `[address, end_address)`.
    #[must_use]
    pub fn covers(&self, addr: u64) -> bool {
        addr >= self.address && addr < self.end_address()
    }

    /// Return `true` if this patch overlaps byte-range `[other_start, other_end)`.
    #[must_use]
    pub fn overlaps_range(&self, other_start: u64, other_end: u64) -> bool {
        self.address < other_end && self.end_address() > other_start
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatchConflict
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned when two patches overlap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchConflict {
    /// Address of the incoming patch.
    pub incoming_address: u64,
    /// Address of the conflicting existing patch.
    pub existing_address: u64,
    /// Annotation of the existing patch (for diagnostics).
    pub existing_annotation: Option<String>,
}

impl std::fmt::Display for PatchConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "patch at {:#x} conflicts with existing patch at {:#x}",
            self.incoming_address, self.existing_address
        )
    }
}

impl std::error::Error for PatchConflict {}

// ─────────────────────────────────────────────────────────────────────────────
// PatchOverlay
// ─────────────────────────────────────────────────────────────────────────────

/// In-memory patch store with conflict detection.
///
/// Patches are keyed by start address.  Overlapping patches are rejected
/// unless `force_insert` is used.
#[derive(Debug, Default)]
pub struct PatchOverlay {
    patches: HashMap<u64, Patch>,
}

impl PatchOverlay {
    /// Create an empty overlay.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a patch.  Returns `Err(PatchConflict)` if it overlaps with an
    /// existing patch.
    pub fn insert(&mut self, patch: Patch) -> Result<(), PatchConflict> {
        let start = patch.address;
        let end = patch.end_address();
        for existing in self.patches.values() {
            if existing.overlaps_range(start, end) {
                return Err(PatchConflict {
                    incoming_address: start,
                    existing_address: existing.address,
                    existing_annotation: existing.annotation.clone(),
                });
            }
        }
        self.patches.insert(start, patch);
        Ok(())
    }

    /// Force-insert a patch, removing any overlapping patches first.
    pub fn force_insert(&mut self, patch: Patch) {
        let start = patch.address;
        let end = patch.end_address();
        self.patches
            .retain(|_, existing| !existing.overlaps_range(start, end));
        self.patches.insert(start, patch);
    }

    /// Remove the patch at `address`. Returns the removed patch.
    pub fn remove(&mut self, address: u64) -> Option<Patch> {
        self.patches.remove(&address)
    }

    /// Enable or disable the patch at `address`.  Returns `true` if found.
    pub fn set_active(&mut self, address: u64, active: bool) -> bool {
        if let Some(p) = self.patches.get_mut(&address) {
            p.active = active;
            true
        } else {
            false
        }
    }

    /// Return the patch at `address`, if any.
    #[must_use]
    pub fn get(&self, address: u64) -> Option<&Patch> {
        self.patches.get(&address)
    }

    /// Return an iterator over all patches.
    pub fn iter(&self) -> impl Iterator<Item = &Patch> {
        self.patches.values()
    }

    /// Return all patches sorted by start address.
    #[must_use]
    pub fn sorted(&self) -> Vec<&Patch> {
        let mut v: Vec<&Patch> = self.patches.values().collect();
        v.sort_by_key(|p| p.address);
        v
    }

    /// Number of patches.
    #[must_use]
    pub fn len(&self) -> usize {
        self.patches.len()
    }

    /// Return `true` if no patches are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }

    /// Clear all patches.
    pub fn clear(&mut self) {
        self.patches.clear();
    }

    /// Apply all active patches to a mutable buffer starting at `buf_base`.
    pub fn apply_to_buf(&self, buf: &mut [u8], buf_base: u64) {
        let buf_end = buf_base + buf.len() as u64;
        for patch in self.patches.values() {
            if !patch.active {
                continue;
            }
            let p_start = patch.address;
            let p_end = p_start + patch.replacement.len() as u64;
            if p_end <= buf_base || p_start >= buf_end {
                continue;
            }
            let copy_start = p_start.max(buf_base);
            let copy_end = p_end.min(buf_end);
            let src_off = (copy_start - p_start) as usize;
            let dst_off = (copy_start - buf_base) as usize;
            let len = (copy_end - copy_start) as usize;
            buf[dst_off..dst_off + len].copy_from_slice(&patch.replacement[src_off..src_off + len]);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatchExport — binary diff format
// ─────────────────────────────────────────────────────────────────────────────

/// An entry in a binary diff export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchDiffEntry {
    /// Start address of the patch.
    pub address: u64,
    /// Original bytes.
    pub before: Vec<u8>,
    /// Replacement bytes.
    pub after: Vec<u8>,
    /// Optional annotation.
    pub annotation: Option<String>,
}

/// Exporter for patches in a binary diff format.
#[derive(Debug, Default)]
pub struct PatchExport;

impl PatchExport {
    /// Export all patches from `overlay` as a sorted `Vec<PatchDiffEntry>`.
    #[must_use]
    pub fn export(overlay: &PatchOverlay) -> Vec<PatchDiffEntry> {
        let mut entries: Vec<PatchDiffEntry> = overlay
            .patches
            .values()
            .map(|p| PatchDiffEntry {
                address: p.address,
                before: p.original.clone(),
                after: p.replacement.clone(),
                annotation: p.annotation.clone(),
            })
            .collect();
        entries.sort_by_key(|e| e.address);
        entries
    }

    /// Import patches from a diff and insert them into `overlay`.
    ///
    /// Returns the number of successfully imported entries; skips conflicting ones.
    pub fn import(overlay: &mut PatchOverlay, entries: &[PatchDiffEntry]) -> usize {
        let mut count = 0;
        for entry in entries {
            let patch = Patch::new(entry.address, entry.before.clone(), entry.after.clone());
            let patch = if let Some(ann) = &entry.annotation {
                patch.with_annotation(ann.clone())
            } else {
                patch
            };
            if overlay.insert(patch).is_ok() {
                count += 1;
            }
        }
        count
    }

    /// Serialize `entries` to a simple text format:
    /// `<hex_addr> <hex_before> -> <hex_after>`
    #[must_use]
    pub fn to_text(entries: &[PatchDiffEntry]) -> String {
        entries
            .iter()
            .map(|e| {
                let before: String = e
                    .before
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let after: String = e
                    .after
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                format!("{:#010x}: [{before}] -> [{after}]", e.address)
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PatchedMemoryProvider
// ─────────────────────────────────────────────────────────────────────────────

/// Wraps an inner `MemoryProvider` and overlays byte-level patches.
///
/// Reads are intercepted and patched transparently.  Writes pass through to the
/// inner provider; overlapping patches are updated in-place to remain consistent.
pub struct PatchedMemoryProvider<P: MemoryProvider> {
    inner: P,
    overlay: PatchOverlay,
}

impl<P: MemoryProvider> PatchedMemoryProvider<P> {
    /// Wrap `inner` with an empty patch set.
    #[must_use]
    pub fn new(inner: P) -> Self {
        Self {
            inner,
            overlay: PatchOverlay::new(),
        }
    }

    /// Add a patch.
    ///
    /// Returns `Err(PatchConflict)` if the patch overlaps with an existing one.
    pub fn add_patch(&mut self, patch: Patch) -> Result<(), PatchConflict> {
        self.overlay.insert(patch)
    }

    /// Force-add a patch, removing any overlapping ones.
    pub fn force_add_patch(&mut self, patch: Patch) {
        self.overlay.force_insert(patch);
    }

    /// Remove the patch at `address`. Returns the removed patch.
    pub fn remove_patch(&mut self, address: u64) -> Option<Patch> {
        self.overlay.remove(address)
    }

    /// Enable or disable a patch at `address`.
    pub fn set_patch_active(&mut self, address: u64, active: bool) -> bool {
        self.overlay.set_active(address, active)
    }

    /// Return the patch at `address`, if any.
    #[must_use]
    pub fn patch_at(&self, address: u64) -> Option<&Patch> {
        self.overlay.get(address)
    }

    /// Number of registered patches.
    #[must_use]
    pub fn patch_count(&self) -> usize {
        self.overlay.len()
    }

    /// Clear all patches.
    pub fn clear_patches(&mut self) {
        self.overlay.clear();
    }

    /// Read original (pre-patch) bytes directly from the inner provider.
    pub fn read_original(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        self.inner.read(addr, len)
    }

    /// Immutable reference to the inner provider.
    #[must_use]
    pub const fn inner(&self) -> &P {
        &self.inner
    }

    /// Mutable reference to the inner provider.
    pub const fn inner_mut(&mut self) -> &mut P {
        &mut self.inner
    }

    /// Export all patches as diff entries.
    #[must_use]
    pub fn export_patches(&self) -> Vec<PatchDiffEntry> {
        PatchExport::export(&self.overlay)
    }

    /// Import patches from diff entries.  Returns the count of imported patches.
    pub fn import_patches(&mut self, entries: &[PatchDiffEntry]) -> usize {
        PatchExport::import(&mut self.overlay, entries)
    }
}

#[async_trait]
impl<P: MemoryProvider + Send + Sync> MemoryProvider for PatchedMemoryProvider<P> {
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        let mut buf = self.inner.read(addr, len)?;
        self.overlay.apply_to_buf(&mut buf, addr.as_u64());
        Ok(buf)
    }

    fn write(&mut self, addr: Address, data: &[u8]) -> Result<(), MemError> {
        self.inner.write(addr, data)?;
        // Update any overlapping active patches so reads stay consistent.
        let write_start = addr.as_u64();
        let write_end = write_start + data.len() as u64;
        for patch in self.overlay.patches.values_mut() {
            if !patch.active {
                continue;
            }
            let p_start = patch.address;
            let p_end = p_start + patch.replacement.len() as u64;
            if p_end <= write_start || p_start >= write_end {
                continue;
            }
            let overlap_start = p_start.max(write_start);
            let overlap_end = p_end.min(write_end);
            let patch_off = (overlap_start - p_start) as usize;
            let write_off = (overlap_start - write_start) as usize;
            let len = (overlap_end - overlap_start) as usize;
            patch.replacement[patch_off..patch_off + len]
                .copy_from_slice(&data[write_off..write_off + len]);
        }
        Ok(())
    }

    fn regions(&self) -> Vec<MemoryRegion> {
        self.inner.regions()
    }

    fn is_live(&self) -> bool {
        self.inner.is_live()
    }

    async fn refresh(&mut self) -> Result<(), MemError> {
        self.inner.refresh().await
    }

    async fn snapshot(&mut self) -> Result<SnapshotId, MemError> {
        self.inner.snapshot().await
    }

    async fn restore(&mut self, id: SnapshotId) -> Result<(), MemError> {
        self.inner.restore(id).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_memory::FileMemoryProvider;
    use rustre_core::permissions::Permissions;

    fn base(base_addr: u64, fill: u8, len: usize) -> FileMemoryProvider {
        FileMemoryProvider::from_bytes(
            vec![fill; len],
            Address::new(base_addr),
            Permissions::READ | Permissions::WRITE,
        )
    }

    // ── Patch ─────────────────────────────────────────────────────────────────

    #[test]
    fn patch_covers() {
        let p = Patch::new(0x1000, vec![0xAA; 4], vec![0xBB; 4]);
        assert!(p.covers(0x1000));
        assert!(p.covers(0x1003));
        assert!(!p.covers(0x1004));
        assert!(!p.covers(0x0FFF));
    }

    #[test]
    fn patch_overlaps_range() {
        let p = Patch::new(0x1000, vec![0xAA; 8], vec![0xBB; 8]);
        assert!(p.overlaps_range(0x1004, 0x1010));
        assert!(p.overlaps_range(0x0FFC, 0x1004));
        assert!(!p.overlaps_range(0x1008, 0x1010));
        assert!(!p.overlaps_range(0x0FF0, 0x1000));
    }

    #[test]
    fn patch_len_and_end_address() {
        let p = Patch::new(0x100, vec![0xAA; 4], vec![0xBB; 6]);
        assert_eq!(p.len(), 6);
        assert_eq!(p.end_address(), 0x106);
    }

    #[test]
    fn patch_with_annotation() {
        let p = Patch::new(0, vec![], vec![]).with_annotation("nop sled");
        assert_eq!(p.annotation.as_deref(), Some("nop sled"));
    }

    #[test]
    fn patch_disabled() {
        let p = Patch::new(0, vec![], vec![]).disabled();
        assert!(!p.active);
    }

    // ── PatchConflict ─────────────────────────────────────────────────────────

    #[test]
    fn patch_conflict_display() {
        let c = PatchConflict {
            incoming_address: 0x1004,
            existing_address: 0x1000,
            existing_annotation: None,
        };
        let s = c.to_string();
        assert!(s.contains("0x1004"));
        assert!(s.contains("0x1000"));
    }

    // ── PatchOverlay ──────────────────────────────────────────────────────────

    #[test]
    fn overlay_insert_and_get() {
        let mut ov = PatchOverlay::new();
        ov.insert(Patch::new(0x1000, vec![0xAA; 4], vec![0xBB; 4]))
            .unwrap();
        assert!(ov.get(0x1000).is_some());
        assert_eq!(ov.len(), 1);
    }

    #[test]
    fn overlay_conflict_detected() {
        let mut ov = PatchOverlay::new();
        ov.insert(Patch::new(0x1000, vec![0xAA; 8], vec![0xBB; 8]))
            .unwrap();
        let result = ov.insert(Patch::new(0x1004, vec![0xCC; 4], vec![0xDD; 4]));
        assert!(result.is_err());
    }

    #[test]
    fn overlay_force_insert_removes_conflicting() {
        let mut ov = PatchOverlay::new();
        ov.insert(Patch::new(0x1000, vec![0xAA; 8], vec![0xBB; 8]))
            .unwrap();
        ov.force_insert(Patch::new(0x1000, vec![0xCC; 4], vec![0xDD; 4]));
        assert_eq!(ov.len(), 1);
        assert_eq!(ov.get(0x1000).unwrap().replacement, vec![0xDD; 4]);
    }

    #[test]
    fn overlay_remove() {
        let mut ov = PatchOverlay::new();
        ov.insert(Patch::new(0x100, vec![0xAA], vec![0xBB]))
            .unwrap();
        assert!(ov.remove(0x100).is_some());
        assert!(ov.is_empty());
    }

    #[test]
    fn overlay_set_active() {
        let mut ov = PatchOverlay::new();
        ov.insert(Patch::new(0x100, vec![0xAA], vec![0xBB]))
            .unwrap();
        ov.set_active(0x100, false);
        assert!(!ov.get(0x100).unwrap().active);
        ov.set_active(0x100, true);
        assert!(ov.get(0x100).unwrap().active);
    }

    #[test]
    fn overlay_apply_to_buf() {
        let mut ov = PatchOverlay::new();
        ov.insert(Patch::new(0x1002, vec![0x00; 2], vec![0xFF; 2]))
            .unwrap();
        let mut buf = vec![0u8; 8];
        ov.apply_to_buf(&mut buf, 0x1000);
        assert_eq!(buf[2], 0xFF);
        assert_eq!(buf[3], 0xFF);
        assert_eq!(buf[0], 0x00);
    }

    #[test]
    fn overlay_inactive_patch_not_applied() {
        let mut ov = PatchOverlay::new();
        ov.insert(Patch::new(0x1000, vec![0x00; 4], vec![0xFF; 4]).disabled())
            .unwrap();
        let mut buf = vec![0xAAu8; 4];
        ov.apply_to_buf(&mut buf, 0x1000);
        assert_eq!(buf, [0xAA; 4]); // unchanged
    }

    #[test]
    fn overlay_sorted() {
        let mut ov = PatchOverlay::new();
        ov.insert(Patch::new(0x3000, vec![0xCC], vec![0xDD]))
            .unwrap();
        ov.insert(Patch::new(0x1000, vec![0xAA], vec![0xBB]))
            .unwrap();
        ov.insert(Patch::new(0x2000, vec![0x11], vec![0x22]))
            .unwrap();
        let sorted = ov.sorted();
        assert_eq!(sorted[0].address, 0x1000);
        assert_eq!(sorted[1].address, 0x2000);
        assert_eq!(sorted[2].address, 0x3000);
    }

    #[test]
    fn overlay_clear() {
        let mut ov = PatchOverlay::new();
        ov.insert(Patch::new(0, vec![0xAA], vec![0xBB])).unwrap();
        ov.clear();
        assert!(ov.is_empty());
    }

    // ── PatchExport ───────────────────────────────────────────────────────────

    #[test]
    fn patch_export_round_trip() {
        let mut ov = PatchOverlay::new();
        ov.insert(Patch::new(0x100, vec![0xAA, 0xBB], vec![0xCC, 0xDD]).with_annotation("test"))
            .unwrap();
        let exported = PatchExport::export(&ov);
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].address, 0x100);
        assert_eq!(exported[0].before, vec![0xAA, 0xBB]);
        assert_eq!(exported[0].after, vec![0xCC, 0xDD]);
        assert_eq!(exported[0].annotation.as_deref(), Some("test"));

        let mut ov2 = PatchOverlay::new();
        let count = PatchExport::import(&mut ov2, &exported);
        assert_eq!(count, 1);
        assert_eq!(ov2.len(), 1);
    }

    #[test]
    fn patch_export_import_skips_conflicts() {
        let entries = vec![
            PatchDiffEntry {
                address: 0x1000,
                before: vec![0xAA; 8],
                after: vec![0xBB; 8],
                annotation: None,
            },
            PatchDiffEntry {
                address: 0x1004,
                before: vec![0xCC; 4],
                after: vec![0xDD; 4],
                annotation: None,
            },
        ];
        let mut ov = PatchOverlay::new();
        let count = PatchExport::import(&mut ov, &entries);
        assert_eq!(count, 1); // second one conflicts
    }

    #[test]
    fn patch_export_to_text() {
        let entries = vec![PatchDiffEntry {
            address: 0x1000,
            before: vec![0xAA, 0xBB],
            after: vec![0xCC, 0xDD],
            annotation: None,
        }];
        let text = PatchExport::to_text(&entries);
        assert!(text.contains("0x00001000"));
        assert!(text.contains("aa bb"));
        assert!(text.contains("cc dd"));
    }

    // ── PatchedMemoryProvider ─────────────────────────────────────────────────

    #[test]
    fn patched_read_without_patches_passthrough() {
        let p = PatchedMemoryProvider::new(base(0x1000, 0xAA, 8));
        let data = p.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(data, [0xAA; 4]);
    }

    #[test]
    fn patched_read_applies_patch() {
        let mut p = PatchedMemoryProvider::new(base(0x1000, 0xAA, 16));
        p.add_patch(Patch::new(0x1002, vec![0x00; 2], vec![0xFF; 2]))
            .unwrap();
        let data = p.read(Address::new(0x1000), 6).unwrap();
        assert_eq!(data[0], 0xAA);
        assert_eq!(data[1], 0xAA);
        assert_eq!(data[2], 0xFF);
        assert_eq!(data[3], 0xFF);
        assert_eq!(data[4], 0xAA);
    }

    #[test]
    fn patched_read_inactive_patch_not_applied() {
        let mut p = PatchedMemoryProvider::new(base(0x1000, 0x00, 4));
        p.add_patch(Patch::new(0x1000, vec![0x00; 4], vec![0xFF; 4]))
            .unwrap();
        p.set_patch_active(0x1000, false);
        let data = p.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(data, [0x00; 4]);
    }

    #[test]
    fn patched_remove_patch_reverts() {
        let mut p = PatchedMemoryProvider::new(base(0x1000, 0xAA, 8));
        p.add_patch(Patch::new(0x1000, vec![0xAA; 4], vec![0xFF; 4]))
            .unwrap();
        p.remove_patch(0x1000);
        let data = p.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(data, [0xAA; 4]);
    }

    #[test]
    fn patched_write_through_to_inner() {
        let mut p = PatchedMemoryProvider::new(base(0x1000, 0xAA, 8));
        p.write(Address::new(0x1000), &[0x11, 0x22]).unwrap();
        let orig = p.read_original(Address::new(0x1000), 2).unwrap();
        assert_eq!(orig, [0x11, 0x22]);
    }

    #[test]
    fn patched_write_updates_overlapping_patch() {
        let mut p = PatchedMemoryProvider::new(base(0x1000, 0xAA, 8));
        p.add_patch(Patch::new(0x1000, vec![0xAA; 4], vec![0xFF; 4]))
            .unwrap();
        p.write(Address::new(0x1000), &[0x11, 0x22]).unwrap();
        // After the write, reading through the patch should show the write merged in.
        let data = p.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(data[0], 0x11);
        assert_eq!(data[1], 0x22);
        assert_eq!(data[2], 0xFF);
        assert_eq!(data[3], 0xFF);
    }

    #[test]
    fn patched_conflict_detection() {
        let mut p = PatchedMemoryProvider::new(base(0x1000, 0xAA, 16));
        p.add_patch(Patch::new(0x1000, vec![0xAA; 8], vec![0xBB; 8]))
            .unwrap();
        let result = p.add_patch(Patch::new(0x1004, vec![0xCC; 4], vec![0xDD; 4]));
        assert!(result.is_err());
    }

    #[test]
    fn patched_force_add_replaces_conflicting() {
        let mut p = PatchedMemoryProvider::new(base(0x1000, 0xAA, 16));
        p.add_patch(Patch::new(0x1000, vec![0xAA; 8], vec![0xBB; 8]))
            .unwrap();
        p.force_add_patch(Patch::new(0x1000, vec![0xCC; 4], vec![0xDD; 4]));
        assert_eq!(p.patch_count(), 1);
        let data = p.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(data, [0xDD; 4]);
    }

    #[test]
    fn patched_clear_patches() {
        let mut p = PatchedMemoryProvider::new(base(0x1000, 0xAA, 8));
        p.add_patch(Patch::new(0x1000, vec![0xAA], vec![0xBB]))
            .unwrap();
        p.clear_patches();
        assert_eq!(p.patch_count(), 0);
    }

    #[test]
    fn patched_export_import_roundtrip() {
        let mut p = PatchedMemoryProvider::new(base(0x1000, 0x00, 8));
        p.add_patch(Patch::new(0x1000, vec![0x00; 4], vec![0xAB; 4]).with_annotation("test"))
            .unwrap();
        let exported = p.export_patches();
        assert_eq!(exported.len(), 1);

        let mut p2 = PatchedMemoryProvider::new(base(0x1000, 0x00, 8));
        let count = p2.import_patches(&exported);
        assert_eq!(count, 1);
        let data = p2.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(data, [0xAB; 4]);
    }

    #[test]
    fn patched_regions_delegates_to_inner() {
        let p = PatchedMemoryProvider::new(base(0x1000, 0xAA, 8));
        let regions = p.regions();
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].range.start, Address::new(0x1000));
    }

    #[test]
    fn patched_multiple_patches() {
        let mut p = PatchedMemoryProvider::new(base(0x1000, 0x00, 16));
        p.add_patch(Patch::new(0x1000, vec![0x00], vec![0x01]))
            .unwrap();
        p.add_patch(Patch::new(0x1004, vec![0x00], vec![0x04]))
            .unwrap();
        p.add_patch(Patch::new(0x1008, vec![0x00], vec![0x08]))
            .unwrap();
        let data = p.read(Address::new(0x1000), 16).unwrap();
        assert_eq!(data[0], 0x01);
        assert_eq!(data[4], 0x04);
        assert_eq!(data[8], 0x08);
    }

    #[test]
    fn patched_partial_overlap_at_end() {
        let mut p = PatchedMemoryProvider::new(base(0x1000, 0xAA, 16));
        p.add_patch(Patch::new(0x100E, vec![0x00; 4], vec![0x01; 4]))
            .unwrap();
        let data = p.read(Address::new(0x1000), 16).unwrap();
        assert_eq!(data[14], 0x01);
        assert_eq!(data[15], 0x01);
    }

    #[test]
    fn patched_inner_ref_access() {
        let p = PatchedMemoryProvider::new(base(0x1000, 0xAA, 4));
        let _ = p.inner();
    }
}
