//! `rustre-ttd-replay::memory_snapshot`
//!
//! High-fidelity memory snapshot diffing at page granularity.
//!
//! Key types:
//! * [`MemorySnapshot`] — a point-in-time capture of all memory regions.
//! * [`SnapshotDiff`] — describes what changed between two snapshots.
//! * [`PageBitmap`] — compact dirty-page tracking bitmap.
//! * [`RegionChange`] — a per-region summary of added/removed/modified pages.
//! * [`MemoryRegion`] — contiguous range of pages with common protection flags.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

use rustre_ttd::TracePosition;
use serde::{Deserialize, Serialize};

use crate::{MemDiff, MemoryState, PAGE_SIZE};

// ─── ProtectionFlags ──────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Windows-style memory protection flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct ProtectionFlags: u32 {
        const READ    = 0x01;
        const WRITE   = 0x02;
        const EXECUTE = 0x04;
        const GUARD   = 0x08;
        const NOCACHE = 0x10;
    }
}

impl Default for ProtectionFlags {
    fn default() -> Self {
        Self::READ | Self::WRITE
    }
}

impl fmt::Display for ProtectionFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if self.contains(Self::READ) {
            parts.push("R");
        }
        if self.contains(Self::WRITE) {
            parts.push("W");
        }
        if self.contains(Self::EXECUTE) {
            parts.push("X");
        }
        if self.contains(Self::GUARD) {
            parts.push("G");
        }
        write!(f, "{}", parts.join(""))
    }
}

// ─── MemoryRegion ─────────────────────────────────────────────────────────────

/// A contiguous range of mapped pages sharing protection attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
    pub protection: ProtectionFlags,
    pub label: Option<String>,
}

impl MemoryRegion {
    #[must_use]
    pub const fn new(base: u64, size: u64, protection: ProtectionFlags) -> Self {
        Self {
            base,
            size,
            protection,
            label: None,
        }
    }

    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    #[must_use]
    pub const fn end(&self) -> u64 {
        self.base.saturating_add(self.size)
    }
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }
    #[must_use]
    pub fn page_count(&self) -> usize {
        (usize::try_from(self.size).unwrap_or(usize::MAX)).div_ceil(PAGE_SIZE)
    }

    /// Page-aligned base.
    #[must_use]
    pub const fn page_base(&self) -> u64 {
        self.base & !(PAGE_SIZE as u64 - 1)
    }

    /// Overlaps with another region.
    #[must_use]
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.base < other.end() && other.base < self.end()
    }
}

impl fmt::Display for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Region[{:#x}..{:#x} {} {}]",
            self.base,
            self.end(),
            self.protection,
            self.label.as_deref().unwrap_or("")
        )
    }
}

// ─── PageBitmap ───────────────────────────────────────────────────────────────

/// A compact dirty-page bitmap tracking which pages have been written since
/// the last snapshot.
///
/// The bitmap covers pages in a contiguous range `[base_page, base_page + n_pages)`.
/// Internally the bits are packed into `u64` words.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageBitmap {
    /// Page-aligned base address of the first tracked page.
    pub base_page: u64,
    /// Number of tracked pages.
    pub n_pages: usize,
    /// Packed bit words — `word[i] bit j` = page `i*64 + j`.
    words: Vec<u64>,
}

impl PageBitmap {
    #[must_use]
    pub fn new(base_page: u64, n_pages: usize) -> Self {
        let n_words = n_pages.div_ceil(64);
        Self {
            base_page,
            n_pages,
            words: vec![0u64; n_words],
        }
    }

    fn page_index(&self, page_base: u64) -> Option<usize> {
        if page_base < self.base_page {
            return None;
        }
        let idx = usize::try_from((page_base - self.base_page) / PAGE_SIZE as u64).unwrap_or(usize::MAX);
        if idx >= self.n_pages { None } else { Some(idx) }
    }

    /// Mark page containing `addr` as dirty.
    pub fn mark_dirty(&mut self, addr: u64) {
        let page = addr & !(PAGE_SIZE as u64 - 1);
        if let Some(idx) = self.page_index(page) {
            self.words[idx / 64] |= 1u64 << (idx % 64);
        }
    }

    /// Check if the page containing `addr` is dirty.
    #[must_use]
    pub fn is_dirty(&self, addr: u64) -> bool {
        let page = addr & !(PAGE_SIZE as u64 - 1);
        self.page_index(page).is_some_and(|idx| (self.words[idx / 64] >> (idx % 64)) & 1 == 1)
    }

    /// Clear all dirty bits.
    pub fn clear(&mut self) {
        for w in &mut self.words {
            *w = 0;
        }
    }

    /// Return addresses of all dirty pages.
    #[must_use]
    pub fn dirty_pages(&self) -> Vec<u64> {
        let mut result = Vec::with_capacity(self.dirty_count());
        for (wi, &word) in self.words.iter().enumerate() {
            if word == 0 {
                continue;
            }
            for bit in 0..64u64 {
                if (word >> bit) & 1 == 1 {
                    let page_idx = wi as u64 * 64 + bit;
                    if page_idx < self.n_pages as u64 {
                        result.push(self.base_page + page_idx * PAGE_SIZE as u64);
                    }
                }
            }
        }
        result
    }

    /// Number of dirty pages.
    #[must_use]
    pub fn dirty_count(&self) -> usize {
        // Popcount over the bitmap words; cheaper than materializing a Vec.
        // Trailing bits past `n_pages` are guaranteed zero by `mark_dirty`.
        self.words
            .iter()
            .map(|w| w.count_ones() as usize)
            .sum()
    }

    /// Total number of tracked pages.
    #[must_use]
    pub const fn total_pages(&self) -> usize {
        self.n_pages
    }

    /// Merge another bitmap into this one (union of dirty sets).
    pub fn merge(&mut self, other: &Self) {
        for (i, &w) in other.words.iter().enumerate() {
            if i < self.words.len() {
                self.words[i] |= w;
            }
        }
    }
}

impl fmt::Display for PageBitmap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PageBitmap[base={:#x}, pages={}, dirty={}]",
            self.base_page,
            self.n_pages,
            self.dirty_count()
        )
    }
}

// ─── MemorySnapshot ───────────────────────────────────────────────────────────

/// A point-in-time capture of the memory state at a specific trace position,
/// enriched with region metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySnapshot {
    /// Position in the trace where this snapshot was taken.
    pub position: TracePosition,
    /// Page data indexed by page-aligned base address.
    pub pages: BTreeMap<u64, Vec<u8>>,
    /// Known memory regions at this position.
    pub regions: Vec<MemoryRegion>,
    /// Dirty-page bitmap (set by [`MemorySnapshot::mark_writes`]).
    pub dirty: PageBitmap,
}

impl MemorySnapshot {
    /// Create an empty snapshot at `position`.
    #[must_use]
    pub fn empty(position: TracePosition) -> Self {
        Self {
            position,
            pages: BTreeMap::new(),
            regions: Vec::new(),
            dirty: PageBitmap::new(0, 0),
        }
    }

    /// Build from an existing `MemoryState`.
    #[must_use]
    pub fn from_memory_state(pos: TracePosition, state: &MemoryState) -> Self {
        let mut snap = Self::empty(pos);
        for (base, page) in &state.pages {
            snap.pages.insert(*base, page.data.clone());
        }
        snap
    }

    /// Add a region descriptor.
    pub fn add_region(&mut self, region: MemoryRegion) {
        self.regions.push(region);
    }

    /// Read `len` bytes from `addr`.  Returns `None` if any byte is unmapped.
    #[must_use]
    pub fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        if len == 0 {
            return Some(vec![]);
        }
        let mut result = Vec::with_capacity(len);
        let mut offset = 0usize;
        let mut cur = addr;
        while offset < len {
            let base = cur & !(PAGE_SIZE as u64 - 1);
            let page = self.pages.get(&base)?;
            let page_off = usize::try_from(cur - base).unwrap_or(usize::MAX);
            let can = PAGE_SIZE - page_off;
            let to = (len - offset).min(can);
            result.extend_from_slice(&page[page_off..page_off + to]);
            offset += to;
            cur += to as u64;
        }
        Some(result)
    }

    /// Write bytes at `addr`, creating pages as needed.
    pub fn write(&mut self, addr: u64, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let mut offset = 0usize;
        let mut cur = addr;
        while offset < data.len() {
            let base = cur & !(PAGE_SIZE as u64 - 1);
            let page = self
                .pages
                .entry(base)
                .or_insert_with(|| vec![0u8; PAGE_SIZE]);
            let page_off = usize::try_from(cur - base).unwrap_or(usize::MAX);
            let can = PAGE_SIZE - page_off;
            let to = (data.len() - offset).min(can);
            page[page_off..page_off + to].copy_from_slice(&data[offset..offset + to]);
            offset += to;
            cur += to as u64;
        }
    }

    /// Mark every page that was touched by writes applied since last snapshot
    /// by scanning `writes` — a list of `(addr, data)` pairs.
    ///
    /// # Panics
    /// Panics if internal invariants are violated.
    pub fn mark_writes(&mut self, writes: &[(u64, Vec<u8>)]) {
        // Extend or rebuild the bitmap to cover all written pages.
        let all_bases: BTreeSet<u64> = writes
            .iter()
            .flat_map(|(addr, data)| {
                let start_page = addr & !(PAGE_SIZE as u64 - 1);
                let end_page =
                    addr.saturating_add(data.len() as u64).saturating_sub(1) & !(PAGE_SIZE as u64 - 1);
                (start_page..=end_page)
                    .step_by(PAGE_SIZE)
                    .collect::<Vec<_>>()
            })
            .collect();

        if all_bases.is_empty() {
            return;
        }
        let min_page = *all_bases.iter().next().unwrap();
        let max_page = *all_bases.iter().next_back().unwrap();
        let old_has_pages = self.dirty.n_pages > 0;
        let old_base = self.dirty.base_page;
        let old_end = old_base
            .saturating_add((self.dirty.n_pages as u64).saturating_mul(PAGE_SIZE as u64));
        let new_end = max_page.saturating_add(PAGE_SIZE as u64);
        let need_base = if old_has_pages { old_base.min(min_page) } else { min_page };
        let need_end = if old_has_pages { old_end.max(new_end) } else { new_end };
        // need_end >= need_base is guaranteed by construction; saturating_sub for safety.
        let need_n = usize::try_from(need_end.saturating_sub(need_base) / PAGE_SIZE as u64).unwrap_or(usize::MAX);
        if !old_has_pages || need_base < old_base || need_n > self.dirty.n_pages {
            let prev_dirty = self.dirty.dirty_pages();
            self.dirty = PageBitmap::new(need_base, need_n);
            for p in prev_dirty {
                self.dirty.mark_dirty(p);
            }
        }
        for page_base in all_bases {
            self.dirty.mark_dirty(page_base);
        }
    }

    /// Number of mapped pages.
    #[must_use]
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    /// Total mapped bytes.
    #[must_use]
    pub fn mapped_bytes(&self) -> usize {
        self.pages.len() * PAGE_SIZE
    }

    /// Region containing `addr`, if any.
    #[must_use]
    pub fn region_for(&self, addr: u64) -> Option<&MemoryRegion> {
        self.regions.iter().find(|r| r.contains(addr))
    }

    /// Convert back to a [`MemoryState`].
    #[must_use]
    pub fn to_memory_state(&self) -> MemoryState {
        use crate::MemPage;
        let mut ms = MemoryState::new();
        for (&base, data) in &self.pages {
            let mut page = MemPage::new(base);
            let copy_len = data.len().min(PAGE_SIZE);
            page.data[..copy_len].copy_from_slice(&data[..copy_len]);
            ms.pages.insert(base, page);
        }
        ms
    }
}

impl fmt::Display for MemorySnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MemorySnapshot[pos={}, pages={}, regions={}, dirty={}]",
            self.position,
            self.page_count(),
            self.regions.len(),
            self.dirty.dirty_count()
        )
    }
}

// ─── RegionChange ─────────────────────────────────────────────────────────────

/// Summary of how a single region changed between two snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionChange {
    pub base: u64,
    pub size: u64,
    pub kind: RegionChangeKind,
    pub modified_pages: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionChangeKind {
    /// Region existed in both snapshots; some pages changed.
    Modified,
    /// Region was added (not in the older snapshot).
    Added,
    /// Region was removed (not in the newer snapshot).
    Removed,
    /// Protection flags changed.
    ProtectionChanged {
        before: ProtectionFlags,
        after: ProtectionFlags,
    },
}

impl fmt::Display for RegionChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RegionChange[{:#x}+{:#x} {:?}, {} pages changed]",
            self.base,
            self.size,
            self.kind,
            self.modified_pages.len()
        )
    }
}

// ─── SnapshotDiff ─────────────────────────────────────────────────────────────

/// Describes all differences between two [`MemorySnapshot`]s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotDiff {
    pub before_position: TracePosition,
    pub after_position: TracePosition,
    /// Page-granular diffs.
    pub page_diffs: Vec<MemDiff>,
    /// Region-level changes.
    pub region_changes: Vec<RegionChange>,
    /// Bytes added (new pages only).
    pub bytes_added: u64,
    /// Bytes removed (pages that disappeared).
    pub bytes_removed: u64,
    /// Pages that changed content.
    pub modified_page_count: usize,
}

impl SnapshotDiff {
    /// Compute a diff between `before` and `after`.
    #[must_use]
    pub fn compute(before: &MemorySnapshot, after: &MemorySnapshot) -> Self {
        let mut page_diffs = Vec::new();
        let all_bases: BTreeSet<u64> = before
            .pages
            .keys()
            .chain(after.pages.keys())
            .copied()
            .collect();

        let empty = vec![0u8; PAGE_SIZE];
        let mut bytes_added = 0u64;
        let mut bytes_removed = 0u64;
        let mut modified = 0usize;

        for base in &all_bases {
            let b_page = before.pages.get(base).unwrap_or(&empty);
            let a_page = after.pages.get(base).unwrap_or(&empty);
            let was_present = before.pages.contains_key(base);
            let is_present = after.pages.contains_key(base);
            if b_page != a_page || was_present != is_present {
                if !was_present && is_present {
                    bytes_added += PAGE_SIZE as u64;
                }
                if was_present && !is_present {
                    bytes_removed += PAGE_SIZE as u64;
                }
                modified += 1;
                page_diffs.push(MemDiff {
                    address: *base,
                    before: b_page.clone(),
                    after: a_page.clone(),
                });
            }
        }

        // Region-level analysis
        let region_changes =
            Self::compute_region_changes(&before.regions, &after.regions, &page_diffs);

        Self {
            before_position: before.position,
            after_position: after.position,
            page_diffs,
            region_changes,
            bytes_added,
            bytes_removed,
            modified_page_count: modified,
        }
    }

    fn compute_region_changes(
        before_regions: &[MemoryRegion],
        after_regions: &[MemoryRegion],
        page_diffs: &[MemDiff],
    ) -> Vec<RegionChange> {
        let mut changes = Vec::new();
        let diff_pages: BTreeSet<u64> = page_diffs.iter().map(|d| d.address).collect();

        // Check existing / modified regions
        for br in before_regions {
            let matching = after_regions.iter().find(|ar| ar.base == br.base);
            if let Some(ar) = matching {
                let modified: Vec<u64> = diff_pages
                    .iter()
                    .copied()
                    .filter(|&p| p >= br.base && p < br.end())
                    .collect();
                if ar.protection != br.protection {
                    changes.push(RegionChange {
                        base: br.base,
                        size: br.size,
                        kind: RegionChangeKind::ProtectionChanged {
                            before: br.protection,
                            after: ar.protection,
                        },
                        modified_pages: modified,
                    });
                } else if !modified.is_empty() {
                    changes.push(RegionChange {
                        base: br.base,
                        size: br.size,
                        kind: RegionChangeKind::Modified,
                        modified_pages: modified,
                    });
                }
            } else {
                changes.push(RegionChange {
                    base: br.base,
                    size: br.size,
                    kind: RegionChangeKind::Removed,
                    modified_pages: vec![],
                });
            }
        }

        // New regions
        for ar in after_regions {
            if !before_regions.iter().any(|br| br.base == ar.base) {
                changes.push(RegionChange {
                    base: ar.base,
                    size: ar.size,
                    kind: RegionChangeKind::Added,
                    modified_pages: diff_pages
                        .iter()
                        .copied()
                        .filter(|&p| p >= ar.base && p < ar.end())
                        .collect(),
                });
            }
        }
        changes
    }

    /// Whether any bytes changed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.page_diffs.is_empty()
    }

    /// Total changed bytes (counting all modified pages, not just the diff parts).
    #[must_use]
    pub const fn total_changed_bytes(&self) -> u64 {
        self.modified_page_count as u64 * PAGE_SIZE as u64
    }

    /// Find specific byte-granular differences within a sub-range `[addr, addr+len)`.
    #[must_use]
    pub fn byte_diffs_in_range(&self, addr: u64, len: usize) -> Vec<(u64, u8, u8)> {
        let end = addr.saturating_add(len as u64);
        let mut result = Vec::new();
        for diff in &self.page_diffs {
            let page_end = diff.address.saturating_add(PAGE_SIZE as u64);
            if diff.address >= end || page_end <= addr {
                continue;
            }
            let start_off = usize::try_from(addr.saturating_sub(diff.address)).unwrap_or(usize::MAX);
            let end_off = usize::try_from((end - diff.address).min(PAGE_SIZE as u64)).unwrap_or(usize::MAX);
            for i in start_off..end_off.min(diff.before.len()).min(diff.after.len()) {
                if diff.before[i] != diff.after[i] {
                    result.push((diff.address + i as u64, diff.before[i], diff.after[i]));
                }
            }
        }
        result
    }
}

impl fmt::Display for SnapshotDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SnapshotDiff[{} -> {}, {} page diffs, +{}B -{}B]",
            self.before_position,
            self.after_position,
            self.modified_page_count,
            self.bytes_added,
            self.bytes_removed
        )
    }
}

// ─── SnapshotStore ────────────────────────────────────────────────────────────

/// An ordered store of named snapshots, supporting diff queries.
#[derive(Debug, Default)]
pub struct SnapshotStore {
    snapshots: BTreeMap<TracePosition, MemorySnapshot>,
    labels: HashMap<String, TracePosition>,
}

impl SnapshotStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, snap: MemorySnapshot) {
        self.snapshots.insert(snap.position, snap);
    }

    pub fn insert_labeled(&mut self, label: impl Into<String>, snap: MemorySnapshot) {
        let pos = snap.position;
        self.snapshots.insert(pos, snap);
        self.labels.insert(label.into(), pos);
    }

    #[must_use]
    pub fn get(&self, pos: TracePosition) -> Option<&MemorySnapshot> {
        self.snapshots.get(&pos)
    }

    #[must_use]
    pub fn get_by_label(&self, label: &str) -> Option<&MemorySnapshot> {
        let pos = self.labels.get(label)?;
        self.snapshots.get(pos)
    }

    #[must_use]
    pub fn nearest_before(&self, pos: TracePosition) -> Option<&MemorySnapshot> {
        self.snapshots.range(..=pos).next_back().map(|(_, s)| s)
    }

    #[must_use]
    pub fn nearest_after(&self, pos: TracePosition) -> Option<&MemorySnapshot> {
        self.snapshots.range(pos..).next().map(|(_, s)| s)
    }

    /// Compute the diff between the snapshots immediately before and after `pos`.
    #[must_use]
    pub fn diff_around(&self, pos: TracePosition) -> Option<SnapshotDiff> {
        let before = self.nearest_before(pos)?;
        let after = self.nearest_after(pos.next_sequence())?;
        Some(SnapshotDiff::compute(before, after))
    }

    /// Compute the diff between two named snapshots.
    #[must_use]
    pub fn diff_between_labels(&self, a: &str, b: &str) -> Option<SnapshotDiff> {
        let sa = self.get_by_label(a)?;
        let sb = self.get_by_label(b)?;
        Some(SnapshotDiff::compute(sa, sb))
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.snapshots.len()
    }

    #[must_use]
    pub fn positions(&self) -> Vec<TracePosition> {
        self.snapshots.keys().copied().collect()
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_ttd::TracePosition;

    fn pos(seq: u64) -> TracePosition {
        TracePosition::new(seq, 0)
    }

    fn make_snap(seq: u64, writes: &[(u64, &[u8])]) -> MemorySnapshot {
        let mut s = MemorySnapshot::empty(pos(seq));
        for &(addr, data) in writes {
            s.write(addr, data);
        }
        s
    }

    // ── PageBitmap ────────────────────────────────────────────────────────────

    #[test]
    fn page_bitmap_mark_and_check() {
        let mut bm = PageBitmap::new(0x1000, 10);
        bm.mark_dirty(0x1000);
        bm.mark_dirty(0x3000);
        assert!(bm.is_dirty(0x1000));
        assert!(bm.is_dirty(0x3000));
        assert!(!bm.is_dirty(0x2000));
    }

    #[test]
    fn page_bitmap_dirty_pages() {
        let mut bm = PageBitmap::new(0x0, 128);
        bm.mark_dirty(0x0);
        bm.mark_dirty(0x5000);
        let dirty = bm.dirty_pages();
        assert!(dirty.contains(&0x0));
        assert!(dirty.contains(&0x5000));
    }

    #[test]
    fn page_bitmap_clear() {
        let mut bm = PageBitmap::new(0x0, 10);
        bm.mark_dirty(0x0);
        bm.clear();
        assert_eq!(bm.dirty_count(), 0);
    }

    #[test]
    fn page_bitmap_merge() {
        let mut a = PageBitmap::new(0x0, 64);
        let mut b = PageBitmap::new(0x0, 64);
        a.mark_dirty(0x1000);
        b.mark_dirty(0x2000);
        a.merge(&b);
        assert!(a.is_dirty(0x1000));
        assert!(a.is_dirty(0x2000));
    }

    #[test]
    fn page_bitmap_display() {
        let bm = PageBitmap::new(0x1000, 8);
        assert!(bm.to_string().contains("base=0x1000"));
    }

    // ── MemorySnapshot ────────────────────────────────────────────────────────

    #[test]
    fn snapshot_read_write() {
        let mut s = MemorySnapshot::empty(pos(0));
        s.write(0x1000, &[1, 2, 3, 4]);
        let bytes = s.read(0x1000, 4).unwrap();
        assert_eq!(bytes, vec![1, 2, 3, 4]);
    }

    #[test]
    fn snapshot_read_unmapped() {
        let s = MemorySnapshot::empty(pos(0));
        assert!(s.read(0xDEAD_0000, 4).is_none());
    }

    #[test]
    fn snapshot_cross_page_read_write() {
        let mut s = MemorySnapshot::empty(pos(0));
        let addr = PAGE_SIZE as u64 - 2;
        s.write(addr, &[0xAA, 0xBB, 0xCC, 0xDD]);
        let bytes = s.read(addr, 4).unwrap();
        assert_eq!(bytes, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn snapshot_page_count() {
        let s = make_snap(0, &[(0x1000, &[1]), (0x5000, &[2])]);
        assert_eq!(s.page_count(), 2);
    }

    #[test]
    fn snapshot_mapped_bytes() {
        let s = make_snap(0, &[(0x1000, &[1])]);
        assert_eq!(s.mapped_bytes(), PAGE_SIZE);
    }

    #[test]
    fn snapshot_region_for() {
        let mut s = MemorySnapshot::empty(pos(0));
        s.add_region(MemoryRegion::new(
            0x1000,
            0x1000,
            ProtectionFlags::default(),
        ));
        assert!(s.region_for(0x1500).is_some());
        assert!(s.region_for(0x3000).is_none());
    }

    #[test]
    fn snapshot_to_memory_state_roundtrip() {
        let mut s = MemorySnapshot::empty(pos(0));
        s.write(0x2000, &[0xDE, 0xAD, 0xBE, 0xEF]);
        let ms = s.to_memory_state();
        let bytes = ms.read(0x2000, 4).unwrap();
        assert_eq!(bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn snapshot_from_memory_state() {
        let mut ms = MemoryState::new();
        ms.apply_write(0x3000, &[1, 2, 3]);
        let snap = MemorySnapshot::from_memory_state(pos(5), &ms);
        assert_eq!(snap.position, pos(5));
        assert_eq!(snap.read(0x3000, 3).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn snapshot_mark_writes() {
        let mut s = MemorySnapshot::empty(pos(0));
        let writes = vec![(0x2000u64, vec![0xAA; 16])];
        s.mark_writes(&writes);
        assert!(s.dirty.dirty_count() > 0);
    }

    #[test]
    fn snapshot_display() {
        let s = MemorySnapshot::empty(pos(0));
        assert!(s.to_string().contains("MemorySnapshot"));
    }

    // ── SnapshotDiff ──────────────────────────────────────────────────────────

    #[test]
    fn diff_empty_snapshots() {
        let a = MemorySnapshot::empty(pos(0));
        let b = MemorySnapshot::empty(pos(1));
        let diff = SnapshotDiff::compute(&a, &b);
        assert!(diff.is_empty());
    }

    #[test]
    fn diff_detects_changes() {
        let a = make_snap(0, &[(0x1000, &[1, 2, 3, 4])]);
        let b = make_snap(1, &[(0x1000, &[5, 6, 7, 8])]);
        let diff = SnapshotDiff::compute(&a, &b);
        assert!(!diff.is_empty());
        assert_eq!(diff.modified_page_count, 1);
    }

    #[test]
    fn diff_added_page() {
        let a = MemorySnapshot::empty(pos(0));
        let b = make_snap(1, &[(0x5000, &[9; 16])]);
        let diff = SnapshotDiff::compute(&a, &b);
        assert_eq!(diff.bytes_added, PAGE_SIZE as u64);
        assert_eq!(diff.bytes_removed, 0);
    }

    #[test]
    fn diff_removed_page() {
        let a = make_snap(0, &[(0x5000, &[9; 16])]);
        let b = MemorySnapshot::empty(pos(1));
        let diff = SnapshotDiff::compute(&a, &b);
        assert_eq!(diff.bytes_removed, PAGE_SIZE as u64);
    }

    #[test]
    fn diff_byte_diffs_in_range() {
        let a = make_snap(0, &[(0x1000, &[1, 2, 3, 4])]);
        let b = make_snap(1, &[(0x1000, &[1, 99, 3, 4])]);
        let diff = SnapshotDiff::compute(&a, &b);
        let byte_diffs = diff.byte_diffs_in_range(0x1000, 4);
        assert_eq!(byte_diffs.len(), 1);
        assert_eq!(byte_diffs[0], (0x1001, 2u8, 99u8));
    }

    #[test]
    fn diff_display() {
        let a = MemorySnapshot::empty(pos(0));
        let b = MemorySnapshot::empty(pos(1));
        let diff = SnapshotDiff::compute(&a, &b);
        assert!(diff.to_string().contains("SnapshotDiff"));
    }

    #[test]
    fn diff_region_modified() {
        let mut a = make_snap(0, &[(0x1000, &[1u8; 8])]);
        a.add_region(MemoryRegion::new(
            0x1000,
            0x1000,
            ProtectionFlags::default(),
        ));
        let mut b = make_snap(1, &[(0x1000, &[2u8; 8])]);
        b.add_region(MemoryRegion::new(
            0x1000,
            0x1000,
            ProtectionFlags::default(),
        ));
        let diff = SnapshotDiff::compute(&a, &b);
        assert!(
            diff.region_changes
                .iter()
                .any(|c| c.kind == RegionChangeKind::Modified)
        );
    }

    // ── SnapshotStore ─────────────────────────────────────────────────────────

    #[test]
    fn store_insert_and_get() {
        let mut store = SnapshotStore::new();
        let snap = MemorySnapshot::empty(pos(10));
        store.insert(snap);
        assert!(store.get(pos(10)).is_some());
        assert!(store.get(pos(11)).is_none());
    }

    #[test]
    fn store_labeled() {
        let mut store = SnapshotStore::new();
        store.insert_labeled("before_exploit", MemorySnapshot::empty(pos(5)));
        assert!(store.get_by_label("before_exploit").is_some());
        assert!(store.get_by_label("nonexistent").is_none());
    }

    #[test]
    fn store_nearest_before_after() {
        let mut store = SnapshotStore::new();
        store.insert(MemorySnapshot::empty(pos(10)));
        store.insert(MemorySnapshot::empty(pos(30)));
        assert_eq!(store.nearest_before(pos(20)).unwrap().position, pos(10));
        assert_eq!(store.nearest_after(pos(20)).unwrap().position, pos(30));
    }

    #[test]
    fn store_count_and_positions() {
        let mut store = SnapshotStore::new();
        store.insert(MemorySnapshot::empty(pos(1)));
        store.insert(MemorySnapshot::empty(pos(2)));
        assert_eq!(store.count(), 2);
        assert_eq!(store.positions(), vec![pos(1), pos(2)]);
    }

    // ── MemoryRegion ──────────────────────────────────────────────────────────

    #[test]
    fn region_contains_and_overlap() {
        let r = MemoryRegion::new(0x1000, 0x1000, ProtectionFlags::default());
        assert!(r.contains(0x1500));
        assert!(!r.contains(0x0500));
        let r2 = MemoryRegion::new(0x1800, 0x800, ProtectionFlags::default());
        assert!(r.overlaps(&r2));
    }

    #[test]
    fn region_page_count() {
        let r = MemoryRegion::new(0x0, 3 * PAGE_SIZE as u64, ProtectionFlags::default());
        assert_eq!(r.page_count(), 3);
    }

    #[test]
    fn region_display() {
        let r = MemoryRegion::new(
            0x1000,
            0x1000,
            ProtectionFlags::READ | ProtectionFlags::WRITE,
        )
        .with_label("stack");
        let s = r.to_string();
        assert!(s.contains("0x1000"));
        assert!(s.contains("stack") || s.contains("RW"));
    }

    #[test]
    fn protection_flags_display() {
        let f = ProtectionFlags::READ | ProtectionFlags::EXECUTE;
        assert!(f.to_string().contains('R'));
        assert!(f.to_string().contains('X'));
    }
}
