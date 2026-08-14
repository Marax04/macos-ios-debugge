//! VM snapshot management: full snapshots, delta snapshots, snapshot tree,
//! restore, diff between snapshots, memory region tracking.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::recorder_engine::{MemoryDiff, ModuleInfo, ThreadState, TracePos};

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("snapshot not found: {0}")]
    NotFound(SnapshotId),
    #[error("parent snapshot not found: {0}")]
    ParentNotFound(SnapshotId),
    #[error("cannot restore: snapshot chain broken at {0}")]
    ChainBroken(SnapshotId),
    #[error("memory region overlap: addr=0x{0:016x}")]
    RegionOverlap(u64),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, SnapshotError>;

// ── Snapshot identity ─────────────────────────────────────────────────────────

/// Unique snapshot identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SnapshotId(pub u64);

impl std::fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "snap:{}", self.0)
    }
}

static NEXT_SNAP_ID: AtomicU64 = AtomicU64::new(1);

fn next_id() -> SnapshotId {
    SnapshotId(NEXT_SNAP_ID.fetch_add(1, Ordering::Relaxed))
}

// ── Memory region ─────────────────────────────────────────────────────────────

/// Permission bits for a memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemPerm(pub u8);

impl MemPerm {
    pub const NONE:  Self = Self(0);
    pub const READ:  Self = Self(1);
    pub const WRITE: Self = Self(2);
    pub const EXEC:  Self = Self(4);
    pub const RW:    Self = Self(3);
    pub const RX:    Self = Self(5);
    pub const RWX:   Self = Self(7);

    #[must_use] pub const fn readable(self) -> bool  { self.0 & 1 != 0 }
    #[must_use] pub const fn writable(self) -> bool  { self.0 & 2 != 0 }
    #[must_use] pub const fn executable(self) -> bool { self.0 & 4 != 0 }
}

impl std::fmt::Display for MemPerm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}{}",
            if self.readable() { 'r' } else { '-' },
            if self.writable() { 'w' } else { '-' },
            if self.executable() { 'x' } else { '-' },
        )
    }
}

/// A contiguous virtual memory region with its backing data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// Start virtual address.
    pub base: u64,
    /// Region size in bytes.
    pub size: u64,
    /// Permission bits.
    pub perm: MemPerm,
    /// Region tag / description (e.g. heap, stack, mapped file name).
    pub tag: String,
    /// Backing bytes. Length must equal `size`.
    pub data: Vec<u8>,
}

impl MemoryRegion {
    /// Create a zeroed region.
    ///
    /// # Panics
    /// Panics if `size` exceeds `isize::MAX` (which would overflow the
    /// allocator) or if `size as usize` would truncate on 32-bit targets.
    #[must_use]
    pub fn zeroed(base: u64, size: u64, perm: MemPerm, tag: impl Into<String>) -> Self {
        // On 32-bit targets `usize` is 4 bytes; guard against silent truncation
        // and against allocations that would immediately OOM.
        const MAX_REGION_BYTES: u64 = 512 * 1024 * 1024; // 512 MB
        assert!(
            size <= MAX_REGION_BYTES,
            "MemoryRegion::zeroed: size {size} exceeds maximum {MAX_REGION_BYTES}"
        );
        Self {
            base,
            size,
            perm,
            tag: tag.into(),
            data: vec![0u8; usize::try_from(size).unwrap_or(0)],
        }
    }

    /// Return true if `addr` is within this region.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base + self.size
    }

    /// Read `len` bytes starting at `addr`.
    ///
    /// # Errors
    /// Returns `None` if the range is out of bounds.
    #[must_use]
    pub fn read(&self, addr: u64, len: usize) -> Option<&[u8]> {
        let off = usize::try_from(addr.checked_sub(self.base)?).ok()?;
        let end = off.checked_add(len)?;
        self.data.get(off..end)
    }

    /// Write `bytes` at `addr`.
    ///
    /// # Errors
    /// Returns `false` if the range is out of bounds.
    pub fn write(&mut self, addr: u64, bytes: &[u8]) -> bool {
        let Some(raw_off) = addr.checked_sub(self.base) else { return false; };
        let Ok(off) = usize::try_from(raw_off) else { return false; };
        let Some(end) = off.checked_add(bytes.len()) else { return false; };
        if end > self.data.len() {
            return false;
        }
        self.data[off..end].copy_from_slice(bytes);
        true
    }
}

// ── Memory map ────────────────────────────────────────────────────────────────

/// A map of all virtual memory regions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryMap {
    /// Sorted by base address.
    regions: BTreeMap<u64, MemoryRegion>,
}

impl MemoryMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a region.
    ///
    /// # Errors
    /// Returns `SnapshotError::RegionOverlap` if the range overlaps an existing region.
    pub fn add_region(&mut self, region: MemoryRegion) -> Result<()> {
        let end = region.base + region.size;
        // Check for overlap with neighbours.
        for (&base, existing) in self.regions.range(..end) {
            if base + existing.size > region.base {
                return Err(SnapshotError::RegionOverlap(region.base));
            }
        }
        self.regions.insert(region.base, region);
        Ok(())
    }

    /// Remove a region by base address.
    pub fn remove_region(&mut self, base: u64) -> Option<MemoryRegion> {
        self.regions.remove(&base)
    }

    /// Find the region containing `addr`.
    #[must_use]
    pub fn region_at(&self, addr: u64) -> Option<&MemoryRegion> {
        self.regions
            .range(..=addr)
            .next_back()
            .map(|(_, r)| r)
            .filter(|r| r.contains(addr))
    }

    /// Mutable access to the region containing `addr`.
    pub fn region_at_mut(&mut self, addr: u64) -> Option<&mut MemoryRegion> {
        // Find the key first, then return mutable ref.
        let key = self.regions
            .range(..=addr)
            .next_back()
            .map(|(k, r)| (*k, r.contains(addr)));
        if let Some((k, true)) = key {
            self.regions.get_mut(&k)
        } else {
            None
        }
    }

    /// Read `len` bytes at `addr`.
    #[must_use]
    pub fn read(&self, addr: u64, len: usize) -> Option<&[u8]> {
        self.region_at(addr)?.read(addr, len)
    }

    /// Write `bytes` at `addr`.
    pub fn write(&mut self, addr: u64, bytes: &[u8]) -> bool {
        self.region_at_mut(addr)
            .is_some_and(|r| r.write(addr, bytes))
    }

    /// Return total mapped bytes.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.regions.values().map(|r| r.size).sum()
    }

    /// Return a list of all regions.
    #[must_use]
    pub fn regions(&self) -> Vec<&MemoryRegion> {
        self.regions.values().collect()
    }

    /// Diff self against `other`, returning a list of byte changes.
    #[must_use]
    pub fn diff(&self, other: &Self, pos: TracePos, tid: u32) -> Vec<MemoryDiff> {
        let mut diffs = Vec::new();
        for (&base, region) in &self.regions {
            if let Some(other_region) = other.regions.get(&base) {
                let min_len = region.data.len().min(other_region.data.len());
                let mut i = 0;
                while i < min_len {
                    if region.data[i] == other_region.data[i] {
                        i += 1;
                    } else {
                        let start = i;
                        while i < min_len && region.data[i] != other_region.data[i] {
                            i += 1;
                        }
                        diffs.push(MemoryDiff {
                            addr: base + u64::try_from(start).unwrap_or(u64::MAX),
                            before: region.data[start..i].to_vec(),
                            after: other_region.data[start..i].to_vec(),
                            position: pos,
                            tid,
                        });
                    }
                }
            }
        }
        diffs
    }
}

// ── Snapshot kinds ────────────────────────────────────────────────────────────

/// Full snapshot: contains the entire process state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullSnapshot {
    pub memory: MemoryMap,
    pub threads: Vec<ThreadState>,
    pub modules: Vec<ModuleInfo>,
}

/// Delta snapshot: records only changes relative to the parent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaSnapshot {
    /// Changes to memory.
    pub memory_diffs: Vec<MemoryDiff>,
    /// Threads that changed (full state of changed threads only).
    pub changed_threads: Vec<ThreadState>,
    /// Modules added since the parent snapshot.
    pub added_modules: Vec<ModuleInfo>,
    /// Base addresses of modules unloaded since the parent.
    pub removed_modules: Vec<u64>,
}

/// Snapshot content (full or delta).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SnapshotContent {
    Full(FullSnapshot),
    Delta(DeltaSnapshot),
}

// ── Snapshot metadata ─────────────────────────────────────────────────────────

/// Metadata associated with a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMeta {
    pub id: SnapshotId,
    pub parent_id: Option<SnapshotId>,
    pub label: String,
    pub position: TracePos,
    pub created_at: u64,
    pub size_bytes: u64,
    pub is_full: bool,
}

/// A complete snapshot node in the tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub meta: SnapshotMeta,
    pub content: SnapshotContent,
}

impl Snapshot {
    /// Estimated serialised size in bytes.
    #[must_use]
    pub fn estimated_size(&self) -> u64 {
        match &self.content {
            SnapshotContent::Full(f) => f.memory.total_size() + 4096,
            SnapshotContent::Delta(d) => {
                d.memory_diffs.iter().map(|md| u64::try_from(md.len()).unwrap_or(u64::MAX) * 2 + 24).sum::<u64>() + 512
            }
        }
    }
}

// ── Snapshot tree ─────────────────────────────────────────────────────────────

/// A tree of snapshots with parent-child relationships.
#[derive(Debug, Default)]
pub struct SnapshotTree {
    snapshots: HashMap<SnapshotId, Snapshot>,
    /// children[id] = list of child IDs.
    children: HashMap<SnapshotId, Vec<SnapshotId>>,
}

impl SnapshotTree {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a snapshot into the tree.
    ///
    /// # Errors
    /// Returns `SnapshotError::ParentNotFound` if the parent ID is set but doesn't exist.
    pub fn insert(&mut self, snap: Snapshot) -> Result<SnapshotId> {
        let id = snap.meta.id;
        if let Some(parent) = snap.meta.parent_id {
            if !self.snapshots.contains_key(&parent) {
                return Err(SnapshotError::ParentNotFound(parent));
            }
            self.children.entry(parent).or_default().push(id);
        }
        self.snapshots.insert(id, snap);
        Ok(id)
    }

    /// Get a snapshot by ID.
    #[must_use]
    pub fn get(&self, id: SnapshotId) -> Option<&Snapshot> {
        self.snapshots.get(&id)
    }

    /// Remove a snapshot and all its descendants.
    pub fn prune(&mut self, id: SnapshotId) {
        if let Some(children) = self.children.remove(&id) {
            for child in children {
                self.prune(child);
            }
        }
        self.snapshots.remove(&id);
    }

    /// Return all snapshot IDs in insertion (BFS) order.
    #[must_use]
    pub fn all_ids(&self) -> Vec<SnapshotId> {
        let mut ids: Vec<SnapshotId> = self.snapshots.keys().copied().collect();
        ids.sort();
        ids
    }

    /// Return the ancestor chain from `id` up to the root (inclusive).
    ///
    /// # Errors
    /// Returns `SnapshotError::ChainBroken` if a parent is missing.
    pub fn ancestor_chain(&self, id: SnapshotId) -> Result<Vec<SnapshotId>> {
        let mut chain = Vec::new();
        let mut current = id;
        loop {
            chain.push(current);
            let snap = self.snapshots.get(&current)
                .ok_or(SnapshotError::ChainBroken(current))?;
            match snap.meta.parent_id {
                Some(parent) => current = parent,
                None => break,
            }
        }
        Ok(chain)
    }

    /// Return the total number of snapshots.
    #[must_use]
    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }
}

// ── Snapshot manager ──────────────────────────────────────────────────────────

/// High-level snapshot manager: creates, stores, and restores snapshots.
pub struct SnapshotManager {
    tree: RwLock<SnapshotTree>,
    current_memory: RwLock<MemoryMap>,
    current_threads: RwLock<Vec<ThreadState>>,
    current_modules: RwLock<Vec<ModuleInfo>>,
    /// Maximum number of full snapshots to keep; oldest are pruned when exceeded.
    max_full_snapshots: usize,
}

impl SnapshotManager {
    /// Create a manager with an initial memory map and default limits.
    #[must_use]
    pub fn new(initial_memory: MemoryMap) -> Self {
        Self {
            tree: RwLock::new(SnapshotTree::new()),
            current_memory: RwLock::new(initial_memory),
            current_threads: RwLock::new(vec![ThreadState::new(1)]),
            current_modules: RwLock::new(Vec::new()),
            max_full_snapshots: 8,
        }
    }

    /// Set the maximum number of retained full snapshots.
    pub const fn set_max_full_snapshots(&mut self, n: usize) {
        self.max_full_snapshots = n;
    }

    /// Update the live memory map by applying a diff.
    pub fn apply_diff(&self, diff: &MemoryDiff) {
        self.current_memory.write().write(diff.addr, &diff.after);
    }

    /// Update a thread's state.
    pub fn update_thread(&self, ts: ThreadState) {
        let mut threads = self.current_threads.write();
        if let Some(existing) = threads.iter_mut().find(|t| t.tid == ts.tid) {
            *existing = ts;
        } else {
            threads.push(ts);
        }
    }

    /// Add a loaded module.
    pub fn add_module(&self, module: ModuleInfo) {
        self.current_modules.write().push(module);
    }

    /// Remove a module by base address.
    pub fn remove_module(&self, base: u64) {
        self.current_modules.write().retain(|m| m.base != base);
    }

    /// Take a full snapshot at `position`.
    ///
    /// # Errors
    /// Returns `SnapshotError` on failure.
    pub fn take_full_snapshot(
        &self,
        position: TracePos,
        label: impl Into<String>,
    ) -> Result<SnapshotId> {
        let id = next_id();
        let memory = self.current_memory.read().clone();
        let threads = self.current_threads.read().clone();
        let modules = self.current_modules.read().clone();
        let size = memory.total_size();
        let snap = Snapshot {
            meta: SnapshotMeta {
                id,
                parent_id: None,
                label: label.into(),
                position,
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()),
                size_bytes: size,
                is_full: true,
            },
            content: SnapshotContent::Full(FullSnapshot { memory, threads, modules }),
        };
        self.tree.write().insert(snap)?;
        self.enforce_full_snapshot_limit();
        Ok(id)
    }

    /// Take a delta snapshot relative to `parent_id`.
    ///
    /// # Errors
    /// Returns `SnapshotError::ParentNotFound` if the parent does not exist.
    pub fn take_delta_snapshot(
        &self,
        parent_id: SnapshotId,
        position: TracePos,
        label: impl Into<String>,
        diffs: Vec<MemoryDiff>,
        changed_threads: Vec<ThreadState>,
    ) -> Result<SnapshotId> {
        let id = next_id();
        let modules_added: Vec<ModuleInfo> = Vec::new();
        let size: u64 = diffs.iter().map(|d| u64::try_from(d.len()).unwrap_or(u64::MAX) * 2 + 24).sum();
        let snap = Snapshot {
            meta: SnapshotMeta {
                id,
                parent_id: Some(parent_id),
                label: label.into(),
                position,
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()),
                size_bytes: size,
                is_full: false,
            },
            content: SnapshotContent::Delta(DeltaSnapshot {
                memory_diffs: diffs,
                changed_threads,
                added_modules: modules_added,
                removed_modules: Vec::new(),
            }),
        };
        self.tree.write().insert(snap)
    }

    /// Restore a snapshot, rebuilding the full process state by replaying the
    /// ancestor chain from the nearest full snapshot.
    ///
    /// # Errors
    /// Returns `SnapshotError::NotFound` or `SnapshotError::ChainBroken` on failure.
    pub fn restore(&self, id: SnapshotId) -> Result<()> {
        let chain = {
            let tree = self.tree.read();
            tree.ancestor_chain(id)?
        };

        // Walk chain from oldest to newest, rebuilding state.
        let mut memory = MemoryMap::new();
        let mut threads: Vec<ThreadState> = Vec::new();
        let mut modules: Vec<ModuleInfo> = Vec::new();

        let tree = self.tree.read();
        for &snap_id in chain.iter().rev() {
            let snap = tree.get(snap_id).ok_or(SnapshotError::NotFound(snap_id))?;
            match &snap.content {
                SnapshotContent::Full(full) => {
                    memory = full.memory.clone();
                    threads = full.threads.clone();
                    modules = full.modules.clone();
                }
                SnapshotContent::Delta(delta) => {
                    for diff in &delta.memory_diffs {
                        memory.write(diff.addr, &diff.after);
                    }
                    for ts in &delta.changed_threads {
                        if let Some(existing) = threads.iter_mut().find(|t| t.tid == ts.tid) {
                            *existing = ts.clone();
                        } else {
                            threads.push(ts.clone());
                        }
                    }
                    for m in &delta.added_modules {
                        modules.push(m.clone());
                    }
                    modules.retain(|m| !delta.removed_modules.contains(&m.base));
                }
            }
        }

        *self.current_memory.write() = memory;
        *self.current_threads.write() = threads;
        *self.current_modules.write() = modules;
        Ok(())
    }

    /// Diff two snapshots by comparing their fully-restored states.
    ///
    /// # Errors
    /// Returns `SnapshotError` if either snapshot cannot be located.
    pub fn diff_snapshots(
        &self,
        id_a: SnapshotId,
        id_b: SnapshotId,
        pos: TracePos,
    ) -> Result<Vec<MemoryDiff>> {
        // Restore both snapshots into temporary maps.
        let mem_a = self.reconstruct_memory(id_a)?;
        let mem_b = self.reconstruct_memory(id_b)?;
        Ok(mem_a.diff(&mem_b, pos, 0))
    }

    /// Reconstruct the memory map for a snapshot without modifying live state.
    fn reconstruct_memory(&self, id: SnapshotId) -> Result<MemoryMap> {
        let chain = {
            let tree = self.tree.read();
            tree.ancestor_chain(id)?
        };
        let mut memory = MemoryMap::new();
        let tree = self.tree.read();
        for &snap_id in chain.iter().rev() {
            let snap = tree.get(snap_id).ok_or(SnapshotError::NotFound(snap_id))?;
            match &snap.content {
                SnapshotContent::Full(full) => {
                    memory = full.memory.clone();
                }
                SnapshotContent::Delta(delta) => {
                    for diff in &delta.memory_diffs {
                        memory.write(diff.addr, &diff.after);
                    }
                }
            }
        }
        Ok(memory)
    }

    /// Prune oldest full snapshots that exceed `max_full_snapshots`.
    fn enforce_full_snapshot_limit(&self) {
        let mut tree = self.tree.write();
        let mut full_ids: Vec<(u64, SnapshotId)> = tree
            .all_ids()
            .into_iter()
            .filter_map(|id| tree.get(id).map(|s| (s.meta.created_at, id)))
            .filter(|(_, id)| tree.get(*id).is_some_and(|s| s.meta.is_full))
            .collect();
        full_ids.sort_by_key(|(ts, _)| *ts);
        while full_ids.len() > self.max_full_snapshots {
            let (_, oldest) = full_ids.remove(0);
            tree.prune(oldest);
        }
    }

    /// Return metadata for all snapshots in the tree.
    #[must_use]
    pub fn list_snapshots(&self) -> Vec<SnapshotMeta> {
        let tree = self.tree.read();
        tree.all_ids()
            .into_iter()
            .filter_map(|id| tree.get(id).map(|s| s.meta.clone()))
            .collect()
    }

    /// Total number of snapshots.
    #[must_use]
    pub fn snapshot_count(&self) -> usize {
        self.tree.read().len()
    }

    /// Clone current memory map (for inspection).
    #[must_use]
    pub fn current_memory_map(&self) -> MemoryMap {
        self.current_memory.read().clone()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager() -> SnapshotManager {
        let mut mem = MemoryMap::new();
        mem.add_region(MemoryRegion::zeroed(0x1000, 0x1000, MemPerm::RW, "heap")).unwrap();
        SnapshotManager::new(mem)
    }

    #[test]
    fn test_take_full_snapshot() {
        let mgr = make_manager();
        let id = mgr.take_full_snapshot(TracePos::start(), "init").unwrap();
        assert_eq!(mgr.snapshot_count(), 1);
        let list = mgr.list_snapshots();
        assert_eq!(list[0].id, id);
        assert!(list[0].is_full);
    }

    #[test]
    fn test_take_delta_snapshot() {
        let mgr = make_manager();
        let full_id = mgr.take_full_snapshot(TracePos::start(), "full").unwrap();
        let diff = MemoryDiff {
            addr: 0x1000,
            before: vec![0u8; 4],
            after: vec![0xde, 0xad, 0xbe, 0xef],
            position: TracePos::new(1, 0),
            tid: 1,
        };
        let delta_id = mgr.take_delta_snapshot(
            full_id,
            TracePos::new(1, 0),
            "delta1",
            vec![diff],
            vec![],
        ).unwrap();
        assert_eq!(mgr.snapshot_count(), 2);
        let list = mgr.list_snapshots();
        assert!(list.iter().any(|m| m.id == delta_id && !m.is_full));
    }

    #[test]
    fn test_restore_full_snapshot() {
        let mgr = make_manager();
        // Write some data into memory.
        mgr.current_memory.write().write(0x1000, &[1, 2, 3, 4]);
        let id = mgr.take_full_snapshot(TracePos::start(), "after_write").unwrap();
        // Corrupt memory.
        mgr.current_memory.write().write(0x1000, &[0xff, 0xff, 0xff, 0xff]);
        // Restore.
        mgr.restore(id).unwrap();
        let data = mgr.current_memory.read().read(0x1000, 4).unwrap().to_vec();
        assert_eq!(data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_restore_delta_chain() {
        let mgr = make_manager();
        let full_id = mgr.take_full_snapshot(TracePos::start(), "base").unwrap();
        let diff = MemoryDiff {
            addr: 0x1008,
            before: vec![0u8; 2],
            after: vec![0xab, 0xcd],
            position: TracePos::new(5, 0),
            tid: 1,
        };
        let delta_id = mgr.take_delta_snapshot(
            full_id, TracePos::new(5, 0), "delta", vec![diff], vec![],
        ).unwrap();
        mgr.restore(delta_id).unwrap();
        let data = mgr.current_memory.read().read(0x1008, 2).unwrap().to_vec();
        assert_eq!(data, vec![0xab, 0xcd]);
    }

    #[test]
    fn test_diff_snapshots() {
        let mgr = make_manager();
        let id_a = mgr.take_full_snapshot(TracePos::start(), "a").unwrap();
        // Modify memory.
        mgr.current_memory.write().write(0x1000, &[0x11, 0x22]);
        let id_b = mgr.take_full_snapshot(TracePos::new(10, 0), "b").unwrap();
        let diffs = mgr.diff_snapshots(id_a, id_b, TracePos::new(10, 0)).unwrap();
        assert!(!diffs.is_empty());
        assert_eq!(diffs[0].addr, 0x1000);
    }

    #[test]
    fn test_memory_region_read_write() {
        let mut r = MemoryRegion::zeroed(0x2000, 0x100, MemPerm::RW, "test");
        assert!(r.write(0x2010, &[0xAA, 0xBB, 0xCC]));
        let data = r.read(0x2010, 3).unwrap();
        assert_eq!(data, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_memory_map_overlap_error() {
        let mut map = MemoryMap::new();
        map.add_region(MemoryRegion::zeroed(0x1000, 0x1000, MemPerm::RW, "a")).unwrap();
        let result = map.add_region(MemoryRegion::zeroed(0x1500, 0x200, MemPerm::RW, "b"));
        assert!(result.is_err());
    }

    #[test]
    fn test_mem_perm_display() {
        assert_eq!(MemPerm::RW.to_string(), "rw-");
        assert_eq!(MemPerm::RX.to_string(), "r-x");
        assert_eq!(MemPerm::NONE.to_string(), "---");
    }

    #[test]
    fn test_snapshot_tree_pruning() {
        let mut tree = SnapshotTree::new();
        let id = next_id();
        tree.insert(Snapshot {
            meta: SnapshotMeta {
                id,
                parent_id: None,
                label: "root".into(),
                position: TracePos::start(),
                created_at: 0,
                size_bytes: 0,
                is_full: true,
            },
            content: SnapshotContent::Full(FullSnapshot {
                memory: MemoryMap::new(),
                threads: vec![],
                modules: vec![],
            }),
        }).unwrap();
        assert_eq!(tree.len(), 1);
        tree.prune(id);
        assert!(tree.is_empty());
    }
}
