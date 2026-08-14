//! In-memory (virtual) memory provider for synthetic or reconstructed binary views.
//!
//! [`VirtualMemoryProvider`] holds a collection of named, permission-tagged
//! byte slices.  It is the foundation for unit tests, emulator snapshots,
//! and synthetic RE views where no backing file or live process exists.

use crate::memory_provider::{MemError, MemoryProvider, MemoryRegion, RegionSource, SnapshotId};
use async_trait::async_trait;
use rustre_core::address::{Address, AddressRange};
use rustre_core::permissions::Permissions;
use std::collections::BTreeMap;

// ─────────────────────────────────────────────────────────────────────────────
// VirtualRegion — an individual mapped region
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct VirtualRegion {
    data: Vec<u8>,
    perms: Permissions,
    name: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// VirtualMemoryProvider
// ─────────────────────────────────────────────────────────────────────────────

/// A fully in-memory [`MemoryProvider`] backed by a `BTreeMap<u64, VirtualRegion>`.
///
/// Regions are keyed by their start address.  Overlapping regions are not
/// automatically merged; the last-mapped region wins at any given address if
/// the caller maps overlapping ranges (which is allowed but discouraged).
///
/// # Thread safety
///
/// `VirtualMemoryProvider` is `Send + Sync` and can safely be shared across
/// threads if wrapped in a `Arc<parking_lot::RwLock<_>>`.
#[derive(Debug, Default)]
pub struct VirtualMemoryProvider {
    /// `start_addr → VirtualRegion`.  Kept sorted for binary-search lookups.
    regions: BTreeMap<u64, VirtualRegion>,
    /// Monotonically increasing snapshot counter.
    next_snapshot_id: u64,
    /// Stored snapshots: id → cloned `regions` map.
    snapshots: BTreeMap<u64, BTreeMap<u64, VirtualRegion>>,
}

impl VirtualMemoryProvider {
    /// Create an empty provider.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Map `data` at `start` with the given permissions.
    ///
    /// If a region already exists at `start`, it is replaced.
    pub fn map(&mut self, start: Address, data: Vec<u8>, perms: Permissions) {
        self.regions.insert(
            start.as_u64(),
            VirtualRegion {
                data,
                perms,
                name: None,
            },
        );
    }

    /// Map a named region at `start`.
    pub fn map_named(
        &mut self,
        start: Address,
        data: Vec<u8>,
        perms: Permissions,
        name: impl Into<String>,
    ) {
        self.regions.insert(
            start.as_u64(),
            VirtualRegion {
                data,
                perms,
                name: Some(name.into()),
            },
        );
    }

    /// Unmap the region that starts at `start`.  Returns `true` if a region
    /// was removed.
    pub fn unmap(&mut self, start: Address) -> bool {
        self.regions.remove(&start.as_u64()).is_some()
    }

    /// Return `true` if `addr` is covered by any mapped region.
    #[must_use]
    pub fn is_mapped(&self, addr: Address) -> bool {
        self.region_for(addr).is_some()
    }

    /// Return the region covering `addr`, along with its base address and
    /// relative offset within the region.
    fn region_for(&self, addr: Address) -> Option<(&VirtualRegion, u64, usize)> {
        // Find the last region with start_key ≤ addr.
        let (&base, region) = self.regions.range(..=addr.as_u64()).next_back()?;
        let offset = addr.as_u64().checked_sub(base)?;
        let offset_usize = offset as usize;
        if offset_usize < region.data.len() {
            Some((region, base, offset_usize))
        } else {
            None
        }
    }

    /// Return the mutable region covering `addr`.
    fn region_for_mut(&mut self, addr: Address) -> Option<(&mut VirtualRegion, u64, usize)> {
        // Two-phase: first find the key.
        let base = *self
            .regions
            .range(..=addr.as_u64())
            .next_back()
            .map(|(k, _)| k)?;
        let offset = addr.as_u64().checked_sub(base)? as usize;
        let region = self.regions.get_mut(&base)?;
        if offset < region.data.len() {
            Some((region, base, offset))
        } else {
            None
        }
    }

    /// Fill `buf` with zeros (helper for reads crossing unmapped pages).
    fn read_bytes_into(&self, addr: Address, buf: &mut [u8]) -> Result<(), MemError> {
        let mut cursor = addr;
        let mut written = 0;
        while written < buf.len() {
            let (region, base, offset) = self
                .region_for(cursor)
                .ok_or(MemError::NotMapped(cursor))?;
            let available = region.data.len() - offset;
            let to_copy = (buf.len() - written).min(available);
            buf[written..written + to_copy].copy_from_slice(&region.data[offset..offset + to_copy]);
            written += to_copy;
            cursor = Address::new(base + (offset + to_copy) as u64);
        }
        Ok(())
    }

    /// Return all snapshot IDs currently stored.
    #[must_use]
    pub fn snapshot_ids(&self) -> Vec<SnapshotId> {
        self.snapshots.keys().map(|&id| SnapshotId(id)).collect()
    }

    /// Total bytes mapped across all regions.
    #[must_use]
    pub fn total_mapped_bytes(&self) -> u64 {
        self.regions.values().map(|r| r.data.len() as u64).sum()
    }

    /// Return a reference to the raw data for a region starting at `start`,
    /// or `None` if no region starts there.
    #[must_use]
    pub fn raw_data(&self, start: Address) -> Option<&[u8]> {
        self.regions.get(&start.as_u64()).map(|r| r.data.as_slice())
    }
}

#[async_trait]
impl MemoryProvider for VirtualMemoryProvider {
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        if len == 0 {
            return Ok(vec![]);
        }
        let mut buf = vec![0u8; len];
        self.read_bytes_into(addr, &mut buf)?;
        Ok(buf)
    }

    fn write(&mut self, addr: Address, data: &[u8]) -> Result<(), MemError> {
        if data.is_empty() {
            return Ok(());
        }
        // Check that the entire range is writable before writing anything.
        let end_addr = Address::new(addr.as_u64().wrapping_add(data.len() as u64));
        let mut cursor = addr;
        while cursor.as_u64() < end_addr.as_u64() {
            let (region, base, offset) = self
                .region_for(cursor)
                .ok_or(MemError::OutOfBounds(cursor, data.len()))?;
            if !region.perms.is_writable() {
                return Err(MemError::PermissionDenied(cursor));
            }
            let available = region.data.len() - offset;
            let remaining = (end_addr.as_u64() - cursor.as_u64()) as usize;
            let step = available.min(remaining);
            cursor = Address::new(base + (offset + step) as u64);
        }

        // Now perform the actual write.
        let mut src_offset = 0usize;
        let mut cursor = addr;
        while src_offset < data.len() {
            let (region, base, offset) = self
                .region_for_mut(cursor)
                .ok_or(MemError::OutOfBounds(cursor, data.len()))?;
            let available = region.data.len() - offset;
            let to_write = (data.len() - src_offset).min(available);
            region.data[offset..offset + to_write]
                .copy_from_slice(&data[src_offset..src_offset + to_write]);
            src_offset += to_write;
            cursor = Address::new(base + (offset + to_write) as u64);
        }
        Ok(())
    }

    fn regions(&self) -> Vec<MemoryRegion> {
        self.regions
            .iter()
            .map(|(&base, region)| {
                let start = Address::new(base);
                let end = Address::new(base + region.data.len() as u64);
                MemoryRegion {
                    range: AddressRange::new(start, end),
                    perms: region.perms,
                    name: region.name.clone(),
                    source: RegionSource::Reconstructed,
                }
            })
            .collect()
    }

    fn is_live(&self) -> bool {
        false
    }

    async fn snapshot(&mut self) -> Result<SnapshotId, MemError> {
        let id = self.next_snapshot_id;
        self.next_snapshot_id += 1;
        self.snapshots.insert(id, self.regions.clone());
        Ok(SnapshotId(id))
    }

    async fn restore(&mut self, id: SnapshotId) -> Result<(), MemError> {
        let snap = self
            .snapshots
            .get(&id.0)
            .ok_or_else(|| MemError::Other(format!("snapshot {} not found", id.0)))?;
        self.regions = snap.clone();
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn rw_provider(start: u64, len: usize) -> VirtualMemoryProvider {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(start),
            vec![0u8; len],
            Permissions::READ | Permissions::WRITE,
        );
        p
    }

    #[test]
    fn basic_read_write() {
        let mut p = rw_provider(0x1000, 16);
        p.write(Address::new(0x1000), &[1, 2, 3, 4]).unwrap();
        assert_eq!(p.read(Address::new(0x1000), 4).unwrap(), [1, 2, 3, 4]);
    }

    #[test]
    fn read_unmapped_fails() {
        let p = VirtualMemoryProvider::new();
        assert!(p.read(Address::new(0xDEAD0000), 1).is_err());
    }

    #[test]
    fn write_beyond_region_fails() {
        let mut p = rw_provider(0x1000, 4);
        assert!(p.write(Address::new(0x1000), &[0u8; 8]).is_err());
    }

    #[test]
    fn readonly_region_rejects_write() {
        let mut p = VirtualMemoryProvider::new();
        p.map(Address::new(0x1000), vec![0u8; 4], Permissions::READ);
        assert!(p.write(Address::new(0x1000), &[0xFF]).is_err());
    }

    #[test]
    fn unmap_removes_region() {
        let mut p = rw_provider(0x1000, 4);
        assert!(p.unmap(Address::new(0x1000)));
        assert!(!p.unmap(Address::new(0x1000)));
        assert!(p.regions().is_empty());
    }

    #[test]
    fn is_mapped_true() {
        let p = rw_provider(0x1000, 16);
        assert!(p.is_mapped(Address::new(0x1008)));
    }

    #[test]
    fn is_mapped_false() {
        let p = rw_provider(0x1000, 16);
        assert!(!p.is_mapped(Address::new(0x2000)));
    }

    #[test]
    fn total_mapped_bytes() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x1000),
            vec![0u8; 0x100],
            Permissions::READ | Permissions::WRITE,
        );
        p.map(
            Address::new(0x2000),
            vec![0u8; 0x200],
            Permissions::READ | Permissions::WRITE,
        );
        assert_eq!(p.total_mapped_bytes(), 0x300);
    }

    #[test]
    fn raw_data_accessor() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x1000),
            vec![0xABu8; 8],
            Permissions::READ | Permissions::WRITE,
        );
        let raw = p.raw_data(Address::new(0x1000)).unwrap();
        assert_eq!(raw, [0xABu8; 8]);
        assert!(p.raw_data(Address::new(0x2000)).is_none());
    }

    #[test]
    fn regions_list() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x1000),
            vec![0u8; 0x100],
            Permissions::READ | Permissions::EXECUTE,
        );
        p.map(
            Address::new(0x2000),
            vec![0u8; 0x100],
            Permissions::READ | Permissions::WRITE,
        );
        let regs = p.regions();
        assert_eq!(regs.len(), 2);
    }

    #[test]
    fn named_region() {
        let mut p = VirtualMemoryProvider::new();
        p.map_named(
            Address::new(0x1000),
            vec![0u8; 0x100],
            Permissions::READ,
            ".text",
        );
        let regs = p.regions();
        assert_eq!(regs[0].name.as_deref(), Some(".text"));
    }

    #[tokio::test]
    async fn snapshot_and_restore() {
        let mut p = rw_provider(0x1000, 16);
        p.write(Address::new(0x1000), &[0xAAu8; 4]).unwrap();
        let snap_id = p.snapshot().await.unwrap();
        p.write(Address::new(0x1000), &[0xBBu8; 4]).unwrap();
        assert_eq!(p.read(Address::new(0x1000), 4).unwrap(), [0xBBu8; 4]);
        p.restore(snap_id).await.unwrap();
        assert_eq!(p.read(Address::new(0x1000), 4).unwrap(), [0xAAu8; 4]);
    }

    #[tokio::test]
    async fn restore_invalid_snapshot() {
        let mut p = VirtualMemoryProvider::new();
        assert!(p.restore(SnapshotId(999)).await.is_err());
    }

    #[test]
    fn read_zero_len_ok() {
        let p = VirtualMemoryProvider::new();
        assert_eq!(p.read(Address::new(0x1000), 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn write_zero_len_ok() {
        let mut p = VirtualMemoryProvider::new();
        assert!(p.write(Address::new(0x1000), &[]).is_ok());
    }

    #[test]
    fn cross_region_read() {
        let mut p = VirtualMemoryProvider::new();
        p.map(
            Address::new(0x1000),
            vec![0xAAu8; 4],
            Permissions::READ | Permissions::WRITE,
        );
        p.map(
            Address::new(0x1004),
            vec![0xBBu8; 4],
            Permissions::READ | Permissions::WRITE,
        );
        let data = p.read(Address::new(0x1002), 4).unwrap();
        assert_eq!(data, [0xAA, 0xAA, 0xBB, 0xBB]);
    }

    #[test]
    fn multiple_snapshots() {
        let mut p = rw_provider(0x1000, 4);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            p.write(Address::new(0x1000), &[1]).unwrap();
            let s1 = p.snapshot().await.unwrap();
            p.write(Address::new(0x1000), &[2]).unwrap();
            let s2 = p.snapshot().await.unwrap();
            p.write(Address::new(0x1000), &[3]).unwrap();
            // Restore to s1.
            p.restore(s1).await.unwrap();
            assert_eq!(p.read(Address::new(0x1000), 1).unwrap()[0], 1);
            // Restore to s2.
            p.restore(s2).await.unwrap();
            assert_eq!(p.read(Address::new(0x1000), 1).unwrap()[0], 2);
        });
    }
}
