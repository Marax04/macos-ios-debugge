//! Physical memory primitives: addresses, page flags, memory maps, and a
//! flat-array physical memory implementation.

// ─────────────────────────────────────────────────────────────────────────────
// PhysAddr / VirtAddr
// ─────────────────────────────────────────────────────────────────────────────

/// A physical (bus) address.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct PhysAddr(pub u64);

impl std::fmt::Display for PhysAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:016x}", self.0)
    }
}

impl PhysAddr {
    /// Construct from a raw `u64`.
    #[must_use]
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    /// Return the raw `u64` value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Checked addition; returns `None` on overflow.
    #[must_use]
    pub fn checked_add(self, rhs: u64) -> Option<Self> {
        self.0.checked_add(rhs).map(Self)
    }
}

/// A virtual (CPU) address.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct VirtAddr(pub u64);

impl std::fmt::Display for VirtAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:016x}", self.0)
    }
}

impl VirtAddr {
    /// Construct from a raw `u64`.
    #[must_use]
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    /// Return the raw `u64` value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Checked addition; returns `None` on overflow.
    #[must_use]
    pub fn checked_add(self, rhs: u64) -> Option<Self> {
        self.0.checked_add(rhs).map(Self)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PageFlags
// ─────────────────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// x86-style page-table permission / attribute flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash,
             serde::Serialize, serde::Deserialize)]
    pub struct PageFlags: u32 {
        /// No flags set.
        const NONE         =   0;
        /// Page is present in memory.
        const PRESENT      =   1;
        /// Page allows writes.
        const WRITABLE     =   2;
        /// Page is accessible from user-mode.
        const USER         =   4;
        /// Write-through caching policy.
        const WRITE_THROUGH =  8;
        /// Caching disabled.
        const NO_CACHE     =  16;
        /// Page has been accessed by the CPU.
        const ACCESSED     =  32;
        /// Page has been written since last flush.
        const DIRTY        =  64;
        /// Huge / large page.
        const HUGE         = 128;
        /// Global page (not flushed on CR3 switches).
        const GLOBAL       = 256;
        /// No-execute bit (NX / XD).
        const NX           = 512;
    }
}

impl std::fmt::Display for PageFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PageFlags(0x{:04x})", self.bits())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PageInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Information about a single mapped page.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PageInfo {
    /// Virtual address of the page.
    pub virt: VirtAddr,
    /// Physical address the page is mapped to.
    pub phys: PhysAddr,
    /// Page-table flags.
    pub flags: PageFlags,
    /// Paging level this entry lives in (1 = 4 KiB, 2 = 2 MiB, 3 = 1 GiB on x86-64).
    pub level: u8,
}

impl PageInfo {
    /// Construct a `PageInfo`.
    #[must_use]
    pub const fn new(virt: VirtAddr, phys: PhysAddr, flags: PageFlags, level: u8) -> Self {
        Self {
            virt,
            phys,
            flags,
            level,
        }
    }

    /// Return `true` if the page is present and executable (NX not set).
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.flags.contains(PageFlags::PRESENT) && !self.flags.contains(PageFlags::NX)
    }

    /// Return `true` if the page is present and writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.flags.contains(PageFlags::PRESENT) && self.flags.contains(PageFlags::WRITABLE)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryRegionPhys  (renamed to avoid clash with mem::MemoryRegion)
// ─────────────────────────────────────────────────────────────────────────────

/// A contiguous mapped virtual-memory region with optional physical backing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemRegion {
    /// Starting virtual address (inclusive).
    pub base: VirtAddr,
    /// Length in bytes.
    pub size: u64,
    /// Page-table flags for the region.
    pub flags: PageFlags,
    /// Human-readable name (e.g. `".text"`, `"[stack]"`).
    pub name: String,
    /// Physical base address if known.
    pub phys_base: Option<PhysAddr>,
}

impl MemRegion {
    /// Construct a new region.
    #[must_use]
    pub fn new(base: VirtAddr, size: u64, flags: PageFlags, name: impl Into<String>) -> Self {
        Self {
            base,
            size,
            flags,
            name: name.into(),
            phys_base: None,
        }
    }

    /// Attach a physical base address.
    #[must_use]
    pub const fn with_phys(mut self, phys: PhysAddr) -> Self {
        self.phys_base = Some(phys);
        self
    }

    /// The first virtual address *past* the end of the region (exclusive).
    #[must_use]
    pub const fn end(&self) -> VirtAddr {
        VirtAddr(self.base.0.saturating_add(self.size))
    }

    /// Return `true` if `addr` falls within `[base, end)`.
    #[must_use]
    pub const fn contains(&self, addr: VirtAddr) -> bool {
        addr.0 >= self.base.0 && addr.0 < self.base.0.saturating_add(self.size)
    }

    /// Return `true` if the region is present and executable (NX not set).
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.flags.contains(PageFlags::PRESENT) && !self.flags.contains(PageFlags::NX)
    }

    /// Return `true` if the region is present and writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.flags.contains(PageFlags::PRESENT) && self.flags.contains(PageFlags::WRITABLE)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemMap
// ─────────────────────────────────────────────────────────────────────────────

/// A virtual-memory map composed of [`MemRegion`] entries.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct MemMap {
    /// All regions in the map (unsorted; insertion order is preserved).
    pub regions: Vec<MemRegion>,
}

impl MemMap {
    /// Create an empty memory map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a region.
    pub fn add_region(&mut self, region: MemRegion) {
        self.regions.push(region);
    }

    /// Find the first region that contains `addr`.
    #[must_use]
    pub fn find_region(&self, addr: VirtAddr) -> Option<&MemRegion> {
        self.regions.iter().find(|r| r.contains(addr))
    }

    /// Return all executable regions.
    #[must_use]
    pub fn executable_regions(&self) -> Vec<&MemRegion> {
        self.regions.iter().filter(|r| r.is_executable()).collect()
    }

    /// Return all writable regions.
    #[must_use]
    pub fn writable_regions(&self) -> Vec<&MemRegion> {
        self.regions.iter().filter(|r| r.is_writable()).collect()
    }

    /// Sum of all region sizes in bytes.
    #[must_use]
    pub fn total_mapped_size(&self) -> u64 {
        self.regions.iter().map(|r| r.size).sum()
    }

    /// Number of regions in the map.
    #[must_use]
    pub const fn region_count(&self) -> usize {
        self.regions.len()
    }

    /// Remove all regions whose name equals `name`.
    pub fn remove_by_name(&mut self, name: &str) {
        self.regions.retain(|r| r.name != name);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemMapError (new, standalone error type for phys memory)
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from physical-memory operations.
#[derive(thiserror::Error, Debug)]
pub enum MemMapError {
    /// The access extends beyond the physical memory boundary.
    #[error("Out of bounds: phys 0x{0:x}")]
    OutOfBounds(u64),
    /// The address is not properly aligned for the operation.
    #[error("Alignment error at 0x{0:x}")]
    Alignment(u64),
    /// A read operation failed.
    #[error("Read error: {0}")]
    Read(String),
    /// A write operation failed.
    #[error("Write error: {0}")]
    Write(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// PhysicalMemory trait
// ─────────────────────────────────────────────────────────────────────────────

/// Abstraction over a physical memory bus / RAM image.
pub trait PhysicalMemory: Send + Sync {
    /// Read bytes from a physical address into `buf`.  Returns the number of
    /// bytes read on success.
    ///
    /// # Errors
    /// Returns [`MemMapError`] on failure.
    fn read_phys(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<usize, MemMapError>;

    /// Write `data` bytes to a physical address.  Returns the number of bytes
    /// written on success.
    ///
    /// # Errors
    /// Returns [`MemMapError`] on failure.
    fn write_phys(&self, addr: PhysAddr, data: &[u8]) -> Result<usize, MemMapError>;

    /// Total size of the physical address space in bytes.
    fn phys_size(&self) -> u64;
}

// ─────────────────────────────────────────────────────────────────────────────
// FlatPhysMemory
// ─────────────────────────────────────────────────────────────────────────────

/// A simple flat byte-array backed physical memory.
pub struct FlatPhysMemory {
    data: Vec<u8>,
}

impl std::fmt::Debug for FlatPhysMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlatPhysMemory")
            .field("size", &self.data.len())
            .finish_non_exhaustive()
    }
}

impl FlatPhysMemory {
    /// Allocate a zero-filled physical memory of `size` bytes.
    #[must_use]
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
        }
    }

    /// Wrap an existing byte vector.
    #[must_use]
    pub const fn from_bytes(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// View the backing data as a byte slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// View the backing data as a mutable byte slice.
    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Return the length of the backing store.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Return `true` if the backing store is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl PhysicalMemory for FlatPhysMemory {
    fn read_phys(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<usize, MemMapError> {
        let start = addr.0 as usize;
        let end = start
            .checked_add(buf.len())
            .ok_or(MemMapError::OutOfBounds(addr.0))?;
        if end > self.data.len() {
            return Err(MemMapError::OutOfBounds(addr.0));
        }
        buf.copy_from_slice(&self.data[start..end]);
        Ok(buf.len())
    }

    fn write_phys(&self, _addr: PhysAddr, _data: &[u8]) -> Result<usize, MemMapError> {
        // Immutable view — writes are not supported via shared reference.
        // Use a mutable wrapper pattern for write-capable scenarios.
        Err(MemMapError::Write(
            "FlatPhysMemory requires interior mutability for writes; use write_phys_mut".into(),
        ))
    }

    fn phys_size(&self) -> u64 {
        self.data.len() as u64
    }
}

impl FlatPhysMemory {
    /// Write `data` to the physical memory at `addr`, bypassing the
    /// [`PhysicalMemory`] trait limitation.
    ///
    /// # Errors
    /// Returns [`MemMapError`] if the write extends beyond the allocation.
    pub fn write_phys_mut(&mut self, addr: PhysAddr, data: &[u8]) -> Result<usize, MemMapError> {
        let start = addr.0 as usize;
        let end = start
            .checked_add(data.len())
            .ok_or(MemMapError::OutOfBounds(addr.0))?;
        if end > self.data.len() {
            return Err(MemMapError::OutOfBounds(addr.0));
        }
        self.data[start..end].copy_from_slice(data);
        Ok(data.len())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PhysAddr ──────────────────────────────────────────────────────────────

    #[test]
    fn test_phys_addr_display() {
        let a = PhysAddr(0x1234_5678_9ABC_DEF0);
        assert_eq!(a.to_string(), "0x123456789abcdef0");
    }

    #[test]
    fn test_phys_addr_eq_ord() {
        let a = PhysAddr(10);
        let b = PhysAddr(20);
        assert!(a < b);
        assert_eq!(a, PhysAddr(10));
    }

    #[test]
    fn test_phys_addr_checked_add() {
        assert_eq!(PhysAddr(10).checked_add(5), Some(PhysAddr(15)));
        assert!(PhysAddr(u64::MAX).checked_add(1).is_none());
    }

    // ── VirtAddr ──────────────────────────────────────────────────────────────

    #[test]
    fn test_virt_addr_display() {
        let v = VirtAddr(0xFFFF_FFFF_FFFF_FFFF);
        assert_eq!(v.to_string(), "0xffffffffffffffff");
    }

    #[test]
    fn test_virt_addr_eq_ord() {
        let a = VirtAddr(100);
        let b = VirtAddr(200);
        assert!(a < b);
        assert_eq!(a, VirtAddr(100));
    }

    #[test]
    fn test_virt_addr_checked_add() {
        assert_eq!(VirtAddr(0x1000).checked_add(0x100), Some(VirtAddr(0x1100)));
        assert!(VirtAddr(u64::MAX).checked_add(1).is_none());
    }

    // ── PageFlags ─────────────────────────────────────────────────────────────

    #[test]
    fn test_page_flags_combine() {
        let flags = PageFlags::PRESENT | PageFlags::WRITABLE;
        assert!(flags.contains(PageFlags::PRESENT));
        assert!(flags.contains(PageFlags::WRITABLE));
        assert!(!flags.contains(PageFlags::NX));
    }

    #[test]
    fn test_page_flags_display() {
        let s = (PageFlags::PRESENT | PageFlags::NX).to_string();
        assert!(s.contains("PageFlags"));
    }

    #[test]
    fn test_page_flags_serde_roundtrip() {
        let flags = PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::HUGE;
        let json = serde_json::to_string(&flags).unwrap();
        let back: PageFlags = serde_json::from_str(&json).unwrap();
        assert_eq!(flags, back);
    }

    // ── PageInfo ──────────────────────────────────────────────────────────────

    #[test]
    fn test_page_info_executable() {
        let pi = PageInfo::new(VirtAddr(0x1000), PhysAddr(0x2000), PageFlags::PRESENT, 1);
        assert!(pi.is_executable());
        assert!(!pi.is_writable());
    }

    #[test]
    fn test_page_info_nx() {
        let pi = PageInfo::new(
            VirtAddr(0x1000),
            PhysAddr(0x2000),
            PageFlags::PRESENT | PageFlags::NX,
            1,
        );
        assert!(!pi.is_executable());
    }

    // ── MemRegion ─────────────────────────────────────────────────────────────

    #[test]
    fn test_mem_region_contains() {
        let r = MemRegion::new(VirtAddr(0x1000), 0x1000, PageFlags::PRESENT, ".text");
        assert!(r.contains(VirtAddr(0x1000)));
        assert!(r.contains(VirtAddr(0x1FFF)));
        assert!(!r.contains(VirtAddr(0x2000)));
    }

    #[test]
    fn test_mem_region_end() {
        let r = MemRegion::new(VirtAddr(0x4000), 0x2000, PageFlags::PRESENT, ".data");
        assert_eq!(r.end(), VirtAddr(0x6000));
    }

    #[test]
    fn test_mem_region_is_executable_writable() {
        let exec = MemRegion::new(VirtAddr(0), 0x100, PageFlags::PRESENT, "code");
        assert!(exec.is_executable());
        assert!(!exec.is_writable());

        let writable = MemRegion::new(
            VirtAddr(0),
            0x100,
            PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::NX,
            "data",
        );
        assert!(!writable.is_executable());
        assert!(writable.is_writable());
    }

    #[test]
    fn test_mem_region_with_phys() {
        let r = MemRegion::new(VirtAddr(0x8000), 0x1000, PageFlags::PRESENT, "heap")
            .with_phys(PhysAddr(0xA000));
        assert_eq!(r.phys_base, Some(PhysAddr(0xA000)));
    }

    // ── MemMap ────────────────────────────────────────────────────────────────

    #[test]
    fn test_mem_map_add_and_find() {
        let mut map = MemMap::new();
        map.add_region(MemRegion::new(
            VirtAddr(0x1000),
            0x1000,
            PageFlags::PRESENT,
            ".text",
        ));
        assert_eq!(map.region_count(), 1);
        let found = map.find_region(VirtAddr(0x1500));
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, ".text");
    }

    #[test]
    fn test_mem_map_find_missing() {
        let map = MemMap::new();
        assert!(map.find_region(VirtAddr(0xDEAD)).is_none());
    }

    #[test]
    fn test_mem_map_executable_writable() {
        let mut map = MemMap::new();
        map.add_region(MemRegion::new(
            VirtAddr(0),
            0x100,
            PageFlags::PRESENT,
            "code",
        ));
        map.add_region(MemRegion::new(
            VirtAddr(0x1000),
            0x100,
            PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::NX,
            "data",
        ));
        assert_eq!(map.executable_regions().len(), 1);
        assert_eq!(map.writable_regions().len(), 1);
    }

    #[test]
    fn test_mem_map_total_size() {
        let mut map = MemMap::new();
        map.add_region(MemRegion::new(VirtAddr(0), 0x1000, PageFlags::PRESENT, "a"));
        map.add_region(MemRegion::new(
            VirtAddr(0x2000),
            0x2000,
            PageFlags::PRESENT,
            "b",
        ));
        assert_eq!(map.total_mapped_size(), 0x3000);
    }

    #[test]
    fn test_mem_map_remove_by_name() {
        let mut map = MemMap::new();
        map.add_region(MemRegion::new(
            VirtAddr(0),
            0x100,
            PageFlags::PRESENT,
            "old",
        ));
        map.add_region(MemRegion::new(
            VirtAddr(0x200),
            0x100,
            PageFlags::PRESENT,
            "keep",
        ));
        map.remove_by_name("old");
        assert_eq!(map.region_count(), 1);
        assert_eq!(map.regions[0].name, "keep");
    }

    #[test]
    fn test_mem_map_default() {
        let map = MemMap::default();
        assert_eq!(map.region_count(), 0);
        assert_eq!(map.total_mapped_size(), 0);
    }

    // ── MemMapError ───────────────────────────────────────────────────────────

    #[test]
    fn test_mem_map_error_display() {
        assert!(
            MemMapError::OutOfBounds(0x1000)
                .to_string()
                .contains("Out of bounds")
        );
        assert!(
            MemMapError::Alignment(0x13)
                .to_string()
                .contains("Alignment")
        );
        assert!(
            MemMapError::Read("io".into())
                .to_string()
                .contains("Read error")
        );
        assert!(
            MemMapError::Write("perm".into())
                .to_string()
                .contains("Write error")
        );
    }

    // ── FlatPhysMemory ────────────────────────────────────────────────────────

    #[test]
    fn test_flat_phys_new_zeroed() {
        let mem = FlatPhysMemory::new(256);
        assert_eq!(mem.phys_size(), 256);
        assert_eq!(mem.len(), 256);
        assert!(!mem.is_empty());
    }

    #[test]
    fn test_flat_phys_read() {
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let mem = FlatPhysMemory::from_bytes(data);
        let mut buf = [0u8; 2];
        assert_eq!(mem.read_phys(PhysAddr(1), &mut buf).unwrap(), 2);
        assert_eq!(buf, [0xBB, 0xCC]);
    }

    #[test]
    fn test_flat_phys_read_out_of_bounds() {
        let mem = FlatPhysMemory::new(4);
        let mut buf = [0u8; 8];
        assert!(mem.read_phys(PhysAddr(2), &mut buf).is_err());
    }

    #[test]
    fn test_flat_phys_write_mut() {
        let mut mem = FlatPhysMemory::new(16);
        mem.write_phys_mut(PhysAddr(4), &[1, 2, 3, 4]).unwrap();
        let mut buf = [0u8; 4];
        mem.read_phys(PhysAddr(4), &mut buf).unwrap();
        assert_eq!(buf, [1, 2, 3, 4]);
    }

    #[test]
    fn test_flat_phys_write_mut_out_of_bounds() {
        let mut mem = FlatPhysMemory::new(4);
        assert!(mem.write_phys_mut(PhysAddr(3), &[1, 2]).is_err());
    }

    #[test]
    fn test_flat_phys_write_via_trait_returns_error() {
        let mem = FlatPhysMemory::new(4);
        let buf = [0u8; 4];
        // The trait write_phys on immutable self is intentionally unsupported.
        assert!(mem.write_phys(PhysAddr(0), &buf).is_err());
    }

    #[test]
    fn test_flat_phys_from_bytes() {
        let mem = FlatPhysMemory::from_bytes(vec![0xFF; 8]);
        let mut buf = [0u8; 8];
        mem.read_phys(PhysAddr(0), &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn test_flat_phys_as_slice() {
        let data = vec![1u8, 2, 3];
        let mem = FlatPhysMemory::from_bytes(data.clone());
        assert_eq!(mem.as_slice(), &data);
    }

    #[test]
    fn test_flat_phys_empty() {
        let mem = FlatPhysMemory::new(0);
        assert!(mem.is_empty());
        assert_eq!(mem.phys_size(), 0);
    }

    #[test]
    fn test_page_info_serde_roundtrip() {
        let pi = PageInfo::new(
            VirtAddr(0xABCD),
            PhysAddr(0x1234),
            PageFlags::PRESENT | PageFlags::WRITABLE,
            2,
        );
        let json = serde_json::to_string(&pi).unwrap();
        let back: PageInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.virt, VirtAddr(0xABCD));
        assert_eq!(back.phys, PhysAddr(0x1234));
        assert_eq!(back.level, 2);
    }

    #[test]
    fn test_mem_map_serde_roundtrip() {
        let mut map = MemMap::new();
        map.add_region(MemRegion::new(
            VirtAddr(0),
            0x1000,
            PageFlags::PRESENT,
            "seg",
        ));
        let json = serde_json::to_string(&map).unwrap();
        let back: MemMap = serde_json::from_str(&json).unwrap();
        assert_eq!(back.region_count(), 1);
    }
}
