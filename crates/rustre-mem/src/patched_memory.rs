use crate::memory_provider::{MemError, MemoryProvider, MemoryRegion, SnapshotId};
use async_trait::async_trait;
use rustre_core::address::Address;

// ---------------------------------------------------------------------------
// Patch record
// ---------------------------------------------------------------------------

/// A single patch that overrides bytes at a specific virtual address.
#[derive(Debug, Clone)]
pub struct Patch {
    /// Start address of the patch.
    pub addr: Address,
    /// Replacement bytes.
    pub data: Vec<u8>,
    /// Human-readable description of what this patch does.
    pub description: Option<String>,
}

impl Patch {
    /// Compute the exclusive end address of this patch.
    #[must_use] 
    pub fn end_addr(&self) -> Address {
        self.addr + self.data.len() as u64
    }

    /// Return true when `addr` falls within this patch's byte range.
    #[must_use] 
    pub const fn covers(&self, addr: Address) -> bool {
        addr.as_u64() >= self.addr.as_u64()
            && addr.as_u64() < self.addr.as_u64() + self.data.len() as u64
    }
}

// ---------------------------------------------------------------------------
// PatchedMemoryProvider
// ---------------------------------------------------------------------------

/// Wraps an inner `MemoryProvider` and overlays one or more byte-level patches.
///
/// On reads the patch bytes are spliced transparently into whatever the inner
/// provider returned. On writes the data is forwarded to the inner provider
/// first, then any overlapping patches are updated in-place so they stay
/// consistent with what was written.
pub struct PatchedMemoryProvider<P: MemoryProvider> {
    inner: P,
    patches: Vec<Patch>,
}

impl<P: MemoryProvider> PatchedMemoryProvider<P> {
    /// Wrap `inner` without any initial patches.
    pub const fn new(inner: P) -> Self {
        Self {
            inner,
            patches: Vec::new(),
        }
    }

    /// Add a new patch. If an existing patch starts at exactly `addr` it will
    /// be replaced.
    pub fn add_patch(&mut self, addr: Address, data: Vec<u8>, description: Option<String>) {
        // Remove any existing patch at the exact same start address.
        self.patches.retain(|p| p.addr != addr);
        self.patches.push(Patch {
            addr,
            data,
            description,
        });
        // Keep patches sorted by start address for predictable iteration order.
        self.patches.sort_by_key(|p| p.addr);
    }

    /// Remove the patch whose start address is `addr`. Returns `true` if a
    /// patch was found and removed.
    pub fn remove_patch_at(&mut self, addr: Address) -> bool {
        let before = self.patches.len();
        self.patches.retain(|p| p.addr != addr);
        self.patches.len() < before
    }

    /// Immutable view of all registered patches.
    pub fn patches(&self) -> &[Patch] {
        &self.patches
    }

    /// Remove all patches.
    pub fn clear_patches(&mut self) {
        self.patches.clear();
    }

    /// Return the number of active patches.
    pub const fn patch_count(&self) -> usize {
        self.patches.len()
    }

    /// Read the original (pre-patch) bytes from the inner provider.
    pub fn read_original(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        self.inner.read(addr, len)
    }

    /// Return a reference to the inner provider.
    pub const fn inner(&self) -> &P {
        &self.inner
    }

    /// Return a mutable reference to the inner provider.
    pub const fn inner_mut(&mut self) -> &mut P {
        &mut self.inner
    }

    /// Apply all overlapping patches onto `buf`, which was read starting at
    /// `base`.
    fn apply_patches_to_buf(&self, base: Address, buf: &mut [u8]) {
        let buf_start = base.as_u64();
        let buf_end = buf_start + buf.len() as u64;

        for patch in &self.patches {
            let patch_start = patch.addr.as_u64();
            let patch_end = patch_start + patch.data.len() as u64;

            // Check for overlap.
            if patch_end <= buf_start || patch_start >= buf_end {
                continue;
            }

            let copy_from = if patch_start < buf_start {
                (buf_start - patch_start) as usize
            } else {
                0
            };
            let copy_to = if patch_start > buf_start {
                (patch_start - buf_start) as usize
            } else {
                0
            };
            let copy_len = (patch.data.len() - copy_from).min(buf.len() - copy_to);

            buf[copy_to..copy_to + copy_len]
                .copy_from_slice(&patch.data[copy_from..copy_from + copy_len]);
        }
    }
}

#[async_trait]
impl<P: MemoryProvider + Send + Sync> MemoryProvider for PatchedMemoryProvider<P> {
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        let mut buf = self.inner.read(addr, len)?;
        self.apply_patches_to_buf(addr, &mut buf);
        Ok(buf)
    }

    fn write(&mut self, addr: Address, data: &[u8]) -> Result<(), MemError> {
        // Write through to the underlying provider.
        self.inner.write(addr, data)?;
        // Update any patches that overlap with the write range so reading
        // back won't show stale patch data where the caller wrote fresh bytes.
        let write_start = addr.as_u64();
        let write_end = write_start + data.len() as u64;

        for patch in &mut self.patches {
            let patch_start = patch.addr.as_u64();
            let patch_end = patch_start + patch.data.len() as u64;

            if patch_end <= write_start || patch_start >= write_end {
                continue;
            }

            // Determine the overlapping sub-range relative to each buffer.
            let overlap_start = patch_start.max(write_start);
            let overlap_end = patch_end.min(write_end);

            let patch_off = (overlap_start - patch_start) as usize;
            let write_off = (overlap_start - write_start) as usize;
            let copy_len = (overlap_end - overlap_start) as usize;

            patch.data[patch_off..patch_off + copy_len]
                .copy_from_slice(&data[write_off..write_off + copy_len]);
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_memory::FileMemoryProvider;
    use rustre_core::permissions::Permissions;

    fn base_provider() -> FileMemoryProvider {
        // 16 bytes of 0xAA at address 0x1000.
        FileMemoryProvider::from_bytes(
            vec![0xAAu8; 16],
            Address::new(0x1000),
            Permissions::READ | Permissions::WRITE,
        )
    }

    #[test]
    fn read_without_patches_passthrough() {
        let p = PatchedMemoryProvider::new(base_provider());
        let data = p.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(data, [0xAA; 4]);
    }

    #[test]
    fn read_with_patch_applied() {
        let mut p = PatchedMemoryProvider::new(base_provider());
        p.add_patch(Address::new(0x1002), vec![0xBB, 0xCC], Some("test".into()));
        let data = p.read(Address::new(0x1000), 6).unwrap();
        assert_eq!(data, [0xAA, 0xAA, 0xBB, 0xCC, 0xAA, 0xAA]);
    }

    #[test]
    fn remove_patch_reverts_read() {
        let mut p = PatchedMemoryProvider::new(base_provider());
        p.add_patch(Address::new(0x1000), vec![0xFF; 4], None);
        assert!(p.remove_patch_at(Address::new(0x1000)));
        let data = p.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(data, [0xAA; 4]);
    }

    #[test]
    fn remove_nonexistent_patch_returns_false() {
        let mut p = PatchedMemoryProvider::new(base_provider());
        assert!(!p.remove_patch_at(Address::new(0xDEAD)));
    }

    #[test]
    fn clear_patches() {
        let mut p = PatchedMemoryProvider::new(base_provider());
        p.add_patch(Address::new(0x1000), vec![0x01], None);
        p.add_patch(Address::new(0x1001), vec![0x02], None);
        p.clear_patches();
        assert!(p.patches().is_empty());
    }

    #[test]
    fn write_through_updates_inner() {
        let mut p = PatchedMemoryProvider::new(base_provider());
        p.write(Address::new(0x1000), &[0x11, 0x22]).unwrap();
        // Reading original (bypassing patches) should show new bytes.
        let orig = p.read_original(Address::new(0x1000), 2).unwrap();
        assert_eq!(orig, [0x11, 0x22]);
    }

    #[test]
    fn write_updates_overlapping_patch() {
        let mut p = PatchedMemoryProvider::new(base_provider());
        p.add_patch(Address::new(0x1000), vec![0xFF; 4], None);
        // Write two bytes overlapping the start of the patch.
        p.write(Address::new(0x1000), &[0x11, 0x22]).unwrap();
        // The patch should now reflect the write in its first two bytes.
        let data = p.read(Address::new(0x1000), 4).unwrap();
        // Patch bytes 0,1 were updated, bytes 2,3 still 0xFF from patch.
        assert_eq!(data, [0x11, 0x22, 0xFF, 0xFF]);
    }

    #[test]
    fn partial_overlap_at_end_of_read_range() {
        let mut p = PatchedMemoryProvider::new(base_provider());
        // Patch starts inside the read window and extends beyond it.
        p.add_patch(Address::new(0x100E), vec![0x01, 0x02, 0x03, 0x04], None);
        let data = p.read(Address::new(0x1000), 16).unwrap();
        assert_eq!(data[14], 0x01);
        assert_eq!(data[15], 0x02);
    }

    #[test]
    fn multiple_patches_sorted_and_applied() {
        let mut p = PatchedMemoryProvider::new(base_provider());
        p.add_patch(Address::new(0x1004), vec![0x04], None);
        p.add_patch(Address::new(0x1000), vec![0x00], None);
        p.add_patch(Address::new(0x1002), vec![0x02], None);
        // Patches should be sorted; all three applied.
        let data = p.read(Address::new(0x1000), 5).unwrap();
        assert_eq!(data[0], 0x00);
        assert_eq!(data[1], 0xAA);
        assert_eq!(data[2], 0x02);
        assert_eq!(data[3], 0xAA);
        assert_eq!(data[4], 0x04);
    }
}
