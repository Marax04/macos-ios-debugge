//! [`EmulatedMemoryProvider`] — a fully in-process byte-buffer memory provider
//! designed to back emulator or sandbox state.
//!
//! # Design
//!
//! The provider manages a list of *regions*, each defined by a base address, a
//! byte payload, a permission bitmask (`u8`, where bit 0 = read, bit 1 = write,
//! bit 2 = execute), and an optional human-readable name.  Reads and writes are
//! validated against both the registered region map and the permission bitmask.
//!
//! ## Snapshot / restore
//!
//! Every call to [`EmulatedMemoryProvider::snapshot`] captures a deep clone of
//! all regions into an internal store keyed by a monotonically-increasing
//! [`SnapshotId`].  [`EmulatedMemoryProvider::restore`] replays the captured
//! state back.  Both operations run in O(total mapped bytes).
//!
//! ## Thread safety
//!
//! This provider is intentionally **single-threaded**.  If you need concurrent
//! access wrap it in a `Mutex`/`RwLock` at the call site.

use async_trait::async_trait;
use rustre_core::address::{Address, AddressRange};
use rustre_core::permissions::Permissions;
use std::collections::HashMap;

use crate::memory_provider::{MemError, MemoryProvider, MemoryRegion, RegionSource, SnapshotId};

// ─────────────────────────────────────────────────────────────────────────────
// Permission helpers (u8 bit flags)
// ─────────────────────────────────────────────────────────────────────────────

/// Permission bit: region is readable.
pub const PERM_READ: u8 = 0b001;
/// Permission bit: region is writable.
pub const PERM_WRITE: u8 = 0b010;
/// Permission bit: region is executable.
pub const PERM_EXEC: u8 = 0b100;

const fn perm_readable(p: u8) -> bool {
    p & PERM_READ != 0
}

const fn perm_writable(p: u8) -> bool {
    p & PERM_WRITE != 0
}

fn perm_to_permissions(p: u8) -> Permissions {
    let mut perms = Permissions::empty();
    if perm_readable(p) {
        perms |= Permissions::READ;
    }
    if perm_writable(p) {
        perms |= Permissions::WRITE;
    }
    if p & PERM_EXEC != 0 {
        perms |= Permissions::EXECUTE;
    }
    perms
}

// ─────────────────────────────────────────────────────────────────────────────
// Region
// ─────────────────────────────────────────────────────────────────────────────

/// A single memory region owned by [`EmulatedMemoryProvider`].
///
/// The `data` field is a flat `Vec<u8>` that represents the bytes starting at
/// `base`.  `perms` is a `u8` bitmask using the `PERM_*` constants.
#[derive(Debug, Clone)]
pub struct EmulatedRegion {
    /// Start address of this region.
    pub base: u64,
    /// Byte content of this region.
    pub data: Vec<u8>,
    /// Permission bitmask (`PERM_READ | PERM_WRITE | PERM_EXEC`).
    pub perms: u8,
    /// Optional human-readable label (e.g. `.text`, `heap`, `stack`).
    pub name: Option<String>,
}

impl EmulatedRegion {
    /// Create a new region.
    #[must_use] 
    pub const fn new(base: u64, data: Vec<u8>, perms: u8, name: Option<String>) -> Self {
        Self {
            base,
            data,
            perms,
            name,
        }
    }

    /// Exclusive end address of this region.
    #[inline]
    #[must_use] 
    pub const fn end(&self) -> u64 {
        self.base + self.data.len() as u64
    }

    /// Return `true` if `addr` falls within `[base, end)`.
    #[inline]
    #[must_use] 
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }

    /// Return `true` if the byte range `[addr, addr+len)` is fully contained.
    #[inline]
    #[must_use] 
    pub const fn contains_range(&self, addr: u64, len: usize) -> bool {
        addr >= self.base && (addr + len as u64) <= self.end()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Snapshot storage
// ─────────────────────────────────────────────────────────────────────────────

/// A saved snapshot of all regions at a particular point in time.
#[derive(Debug, Clone)]
pub struct EmulatedSnapshot {
    pub id: SnapshotId,
    pub label: Option<String>,
    /// Deep-cloned regions at the time of the snapshot.
    pub regions: Vec<EmulatedRegion>,
}

// ─────────────────────────────────────────────────────────────────────────────
// EmulatedMemoryProvider
// ─────────────────────────────────────────────────────────────────────────────

/// A mutable, in-process memory provider that emulates RAM for a virtual
/// machine, sandbox, or unit test.
///
/// # Example
/// ```rust,ignore
/// use rustre_mem::emulated_memory::{EmulatedMemoryProvider, PERM_READ, PERM_WRITE};
/// use rustre_mem::MemoryProvider;
/// use rustre_core::address::Address;
///
/// let mut mem = EmulatedMemoryProvider::new();
/// mem.map(0x1000, vec![0u8; 0x1000], PERM_READ | PERM_WRITE, Some("stack".into()));
/// mem.write(Address::new(0x1000), &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
/// let bytes = mem.read(Address::new(0x1000), 4).unwrap();
/// assert_eq!(bytes, [0xDE, 0xAD, 0xBE, 0xEF]);
/// ```
pub struct EmulatedMemoryProvider {
    /// All currently mapped regions.
    ///
    /// Tuple layout: `(base_address: u64, data: Vec<u8>, perms: u8)`
    /// This matches the layout prescribed by spec §2.3 verbatim.
    regions: Vec<(u64, Vec<u8>, u8)>,

    /// Optional names, indexed parallel to `regions`.
    names: Vec<Option<String>>,

    /// Monotonically increasing counter used to generate [`SnapshotId`]s.
    snapshot_counter: u64,

    /// Saved snapshots keyed by their [`SnapshotId`].
    snapshots: HashMap<u64, EmulatedSnapshot>,
}

impl EmulatedMemoryProvider {
    /// Create an empty provider with no mapped regions.
    #[must_use]
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
            names: Vec::new(),
            snapshot_counter: 0,
            snapshots: HashMap::new(),
        }
    }

    /// Map a new region starting at `base` with `data` bytes and `perms`
    /// permission flags.  Any existing region whose base address matches is
    /// replaced.
    pub fn map(&mut self, base: u64, data: Vec<u8>, perms: u8, name: Option<String>) {
        // Remove any existing region with the same base.
        if let Some(idx) = self.regions.iter().position(|(b, _, _)| *b == base) {
            self.regions.remove(idx);
            self.names.remove(idx);
        }
        self.regions.push((base, data, perms));
        self.names.push(name);
    }

    /// Unmap the region at `base`.  Returns `true` if it existed.
    pub fn unmap(&mut self, base: u64) -> bool {
        if let Some(idx) = self.regions.iter().position(|(b, _, _)| *b == base) {
            self.regions.remove(idx);
            self.names.remove(idx);
            true
        } else {
            false
        }
    }

    /// Return the number of currently mapped regions.
    #[must_use]
    pub const fn region_count(&self) -> usize {
        self.regions.len()
    }

    /// Update the permission flags on an existing region.  Returns `false` if
    /// no region starts at `base`.
    pub fn set_perms(&mut self, base: u64, perms: u8) -> bool {
        if let Some((_, _, p)) = self.regions.iter_mut().find(|(b, _, _)| *b == base) {
            *p = perms;
            true
        } else {
            false
        }
    }

    /// Return a shared reference to the raw region tuple at index `i`.
    #[must_use] 
    pub fn get_region(&self, idx: usize) -> Option<(&u64, &Vec<u8>, &u8)> {
        self.regions.get(idx).map(|(b, d, p)| (b, d, p))
    }

    // ── Snapshot / restore ───────────────────────────────────────────────────

    /// Take a snapshot of the current memory state and return its
    /// [`SnapshotId`].
    ///
    /// The snapshot deep-clones all regions, so subsequent writes do not
    /// affect the saved state.
    pub fn take_snapshot_labeled(&mut self, label: Option<String>) -> SnapshotId {
        self.snapshot_counter += 1;
        let id = SnapshotId(self.snapshot_counter);

        // Rebuild as EmulatedRegion for the snapshot.
        let snapshot_regions: Vec<EmulatedRegion> = self
            .regions
            .iter()
            .zip(self.names.iter())
            .map(|((base, data, perms), name)| EmulatedRegion {
                base: *base,
                data: data.clone(),
                perms: *perms,
                name: name.clone(),
            })
            .collect();

        self.snapshots.insert(
            id.0,
            EmulatedSnapshot {
                id,
                label,
                regions: snapshot_regions,
            },
        );
        id
    }

    /// Restore the memory state to the snapshot identified by `id`.
    ///
    /// All currently mapped regions are replaced by the saved state.
    /// Returns [`MemError::Other`] if the snapshot does not exist.
    pub fn restore_from_snapshot(&mut self, id: SnapshotId) -> Result<(), MemError> {
        let snap = self
            .snapshots
            .get(&id.0)
            .ok_or_else(|| MemError::Other(format!("snapshot {} not found", id.0)))?
            .clone();

        self.regions.clear();
        self.names.clear();
        for r in snap.regions {
            self.regions.push((r.base, r.data, r.perms));
            self.names.push(r.name);
        }
        Ok(())
    }

    /// Discard a previously saved snapshot.  Returns `true` if it existed.
    pub fn drop_snapshot(&mut self, id: SnapshotId) -> bool {
        self.snapshots.remove(&id.0).is_some()
    }

    /// Return the number of stored snapshots.
    #[must_use]
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    /// Find the region that fully contains `[addr, addr+len)`.
    fn find_region_for_range(&self, addr: u64, len: usize) -> Option<usize> {
        let end = addr + len as u64;
        self.regions.iter().position(|(base, data, _)| {
            let region_end = base + data.len() as u64;
            addr >= *base && end <= region_end
        })
    }

    /// Find the region index that contains `addr`.
    #[must_use] 
    pub fn find_region_at(&self, addr: u64) -> Option<usize> {
        self.regions
            .iter()
            .position(|(base, data, _)| addr >= *base && addr < base + data.len() as u64)
    }
}

impl Default for EmulatedMemoryProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MemoryProvider for EmulatedMemoryProvider {
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let raw = addr.as_u64();
        let idx = self
            .find_region_for_range(raw, len)
            .ok_or(MemError::NotMapped(addr))?;

        let (base, data, perms) = &self.regions[idx];
        if !perm_readable(*perms) {
            return Err(MemError::PermissionDenied(addr));
        }
        let offset = (raw - base) as usize;
        Ok(data[offset..offset + len].to_vec())
    }

    fn write(&mut self, addr: Address, data: &[u8]) -> Result<(), MemError> {
        if data.is_empty() {
            return Ok(());
        }
        let raw = addr.as_u64();
        let idx = self
            .find_region_for_range(raw, data.len())
            .ok_or(MemError::NotMapped(addr))?;

        let (base, region_data, perms) = &mut self.regions[idx];
        if !perm_writable(*perms) {
            return Err(MemError::PermissionDenied(addr));
        }
        let offset = (raw - *base) as usize;
        region_data[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }

    fn regions(&self) -> Vec<MemoryRegion> {
        self.regions
            .iter()
            .zip(self.names.iter())
            .map(|((base, data, perms), name)| {
                let start = Address::new(*base);
                let end = Address::new(base + data.len() as u64);
                MemoryRegion {
                    range: AddressRange::new(start, end),
                    perms: perm_to_permissions(*perms),
                    name: name.clone(),
                    source: RegionSource::Emulated,
                }
            })
            .collect()
    }

    fn is_live(&self) -> bool {
        false
    }

    async fn snapshot(&mut self) -> Result<SnapshotId, MemError> {
        Ok(self.take_snapshot_labeled(None))
    }

    async fn restore(&mut self, id: SnapshotId) -> Result<(), MemError> {
        self.restore_from_snapshot(id)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_provider() -> EmulatedMemoryProvider {
        let mut p = EmulatedMemoryProvider::new();
        // Map a read-only code region at 0x1000.
        p.map(
            0x1000,
            vec![0x90u8; 0x100],
            PERM_READ | PERM_EXEC,
            Some(".text".into()),
        );
        // Map a read-write data region at 0x2000.
        p.map(
            0x2000,
            vec![0x00u8; 0x100],
            PERM_READ | PERM_WRITE,
            Some(".data".into()),
        );
        p
    }

    #[test]
    fn read_within_mapped_region() {
        let p = make_provider();
        let bytes = p.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(bytes, [0x90, 0x90, 0x90, 0x90]);
    }

    #[test]
    fn write_and_read_back() {
        let mut p = make_provider();
        p.write(Address::new(0x2000), &[0xDE, 0xAD, 0xBE, 0xEF])
            .unwrap();
        let back = p.read(Address::new(0x2000), 4).unwrap();
        assert_eq!(back, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn write_to_readonly_region_returns_error() {
        let mut p = make_provider();
        let result = p.write(Address::new(0x1000), &[0x00]);
        assert!(matches!(result, Err(MemError::PermissionDenied(_))));
    }

    #[test]
    fn read_unmapped_address_returns_error() {
        let p = make_provider();
        assert!(matches!(
            p.read(Address::new(0xDEAD), 1),
            Err(MemError::NotMapped(_))
        ));
    }

    #[test]
    fn snapshot_and_restore_preserves_state() {
        let mut p = make_provider();
        // Write a distinctive pattern.
        p.write(Address::new(0x2000), &[0x11, 0x22, 0x33, 0x44])
            .unwrap();
        let id = p.take_snapshot_labeled(Some("v1".into()));

        // Clobber the region.
        p.write(Address::new(0x2000), &[0xFF, 0xFF, 0xFF, 0xFF])
            .unwrap();

        // Restore and verify.
        p.restore_from_snapshot(id).unwrap();
        let back = p.read(Address::new(0x2000), 4).unwrap();
        assert_eq!(back, [0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn snapshot_counter_increments() {
        let mut p = make_provider();
        let id1 = p.take_snapshot_labeled(None);
        let id2 = p.take_snapshot_labeled(None);
        assert_ne!(id1.0, id2.0);
        assert_eq!(p.snapshot_count(), 2);
    }

    #[test]
    fn drop_snapshot_removes_entry() {
        let mut p = make_provider();
        let id = p.take_snapshot_labeled(None);
        assert!(p.drop_snapshot(id));
        assert_eq!(p.snapshot_count(), 0);
        // Restoring a dropped snapshot should error.
        assert!(p.restore_from_snapshot(id).is_err());
    }

    #[test]
    fn unmap_removes_region() {
        let mut p = make_provider();
        assert!(p.unmap(0x1000));
        assert_eq!(p.region_count(), 1);
        assert!(!p.unmap(0x1000)); // already gone
    }

    #[test]
    fn regions_returns_correct_metadata() {
        let p = make_provider();
        let rs = p.regions();
        assert_eq!(rs.len(), 2);
        let names: Vec<_> = rs.iter().filter_map(|r| r.name.as_deref()).collect();
        assert!(names.contains(&".text"));
        assert!(names.contains(&".data"));
    }

    #[test]
    fn zero_length_read_returns_empty() {
        let p = make_provider();
        let result = p.read(Address::new(0x1000), 0).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn zero_length_write_is_noop() {
        let mut p = make_provider();
        // Writing zero bytes into an unmapped address should succeed (noop).
        assert!(p.write(Address::new(0xDEAD), &[]).is_ok());
    }

    #[test]
    fn set_perms_works() {
        let mut p = make_provider();
        // Make .text writable.
        assert!(p.set_perms(0x1000, PERM_READ | PERM_WRITE | PERM_EXEC));
        p.write(Address::new(0x1000), &[0xCC]).unwrap();
        assert_eq!(p.read(Address::new(0x1000), 1).unwrap(), [0xCC]);
    }

    #[test]
    fn multiple_snapshots_are_independent() {
        let mut p = make_provider();
        p.write(Address::new(0x2000), &[0xAA]).unwrap();
        let id1 = p.take_snapshot_labeled(Some("snap1".into()));
        p.write(Address::new(0x2000), &[0xBB]).unwrap();
        let id2 = p.take_snapshot_labeled(Some("snap2".into()));

        p.restore_from_snapshot(id1).unwrap();
        assert_eq!(p.read(Address::new(0x2000), 1).unwrap(), [0xAA]);

        p.restore_from_snapshot(id2).unwrap();
        assert_eq!(p.read(Address::new(0x2000), 1).unwrap(), [0xBB]);
    }
}
