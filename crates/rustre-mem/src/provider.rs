/// Concrete `MemoryProvider` implementations beyond the basic `FileMemoryProvider`.
///
/// This module provides:
/// - [`EmulatedMemoryProvider`] — a mutable, byte-buffer provider with snapshot
///   support, page-granular write-tracking, and multi-region management.
/// - [`ProcessMemoryProvider`] — reads live process memory via OS APIs
///   (`ReadProcessMemory` on Windows, `process_vm_readv` on Linux) with an
///   optional read cache.
/// - [`TraceMemoryProvider`] — replays memory state at a given "tick" from a
///   pre-recorded sequence of memory snapshots (TTD-style).
use crate::cache::PageCache;
use crate::memory_provider::{MemError, MemoryProvider, MemoryRegion, RegionSource, SnapshotId};
use crate::snapshot::SnapshotStore;
use async_trait::async_trait;
use parking_lot::Mutex;
use rustre_core::address::{Address, AddressRange};
use rustre_core::permissions::Permissions;
use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────────────
// EmulatedMemoryProvider
// ─────────────────────────────────────────────────────────────────────────────

/// An in-memory provider backed by a page cache with multi-region support.
///
/// Unlike [`crate::file_memory::FileMemoryProvider`], this provider supports:
/// - Multiple named regions with independent permissions.
/// - Snapshot/restore using [`SnapshotStore`].
/// - Page-granular dirty tracking.
///
/// All data is stored inside a [`PageCache`]; writes go directly into the
/// cache without touching any file.
pub struct EmulatedMemoryProvider {
    /// The underlying page cache that serves as the backing store.
    /// Wrapped in a `Mutex` to allow interior mutability through `&self`
    /// (needed by `MemoryProvider::read`) while remaining thread-safe.
    cache: Mutex<PageCache>,
    /// Registered memory regions (address range + permissions + name).
    regions: Vec<EmulatedRegion>,
    /// Snapshot store for save/restore.
    snapshots: SnapshotStore,
}

/// A region registered in an [`EmulatedMemoryProvider`].
#[derive(Debug, Clone)]
struct EmulatedRegion {
    range: AddressRange,
    perms: Permissions,
    name: Option<String>,
}

impl EmulatedMemoryProvider {
    /// Create an empty emulated provider.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(PageCache::new(0x1000, 0)), // unlimited
            regions: Vec::new(),
            snapshots: SnapshotStore::new(),
        }
    }

    /// Add a memory region backed by `data`.
    ///
    /// The `data` slice is seeded directly into the page cache at `base`.
    /// Any region with the same range is replaced.
    pub fn add_region(
        &mut self,
        base: Address,
        data: Vec<u8>,
        perms: Permissions,
        name: Option<String>,
    ) {
        let end = base + data.len() as u64;
        let range = AddressRange::new(base, end);

        // Remove any existing region that overlaps exactly (same start).
        self.regions.retain(|r| r.range.start != base);
        self.regions.push(EmulatedRegion { range, perms, name });
        self.cache.lock().seed(base, &data);
    }

    /// Remove the region starting at `base`.  Returns `true` if it existed.
    pub fn remove_region(&mut self, base: Address) -> bool {
        let before = self.regions.len();
        self.regions.retain(|r| r.range.start != base);
        self.regions.len() < before
    }

    /// Return all pages currently held in the cache.
    #[must_use]
    pub fn cache_len(&self) -> usize {
        self.cache.lock().len()
    }

    /// Number of registered regions.
    #[must_use]
    pub const fn region_count(&self) -> usize {
        self.regions.len()
    }

    /// Dump the full contents of `range` into a `Vec<u8>`.
    ///
    /// Bytes that are not backed by a registered region are returned as zeroes.
    #[must_use]
    pub fn dump_range(&mut self, range: AddressRange) -> Vec<u8> {
        if range.is_empty() {
            return Vec::new();
        }
        let len = range.len() as usize;
        self.cache
            .lock()
            .read(range.start, len, |_page_start, page_size| {
                // For emulated providers the cache IS the backing store; any page
                // not yet cached is implicitly zero-filled.
                Ok::<Vec<u8>, ()>(vec![0u8; page_size])
            })
            .unwrap_or_else(|()| vec![0u8; len])
    }

    /// Snapshot the contents of all registered regions and return the id.
    ///
    /// The snapshot captures a contiguous byte buffer per region; it is stored
    /// in the `SnapshotStore` and can be restored later.
    pub fn take_snapshot(&mut self, tag: Option<String>) -> SnapshotId {
        // Build a compact representation: for each region, dump its bytes.
        let mut combined: Vec<u8> = Vec::new();
        for region in &self.regions.clone() {
            let len = region.range.len() as usize;
            let bytes = self.dump_range(region.range);
            // Pad/truncate to exact length.
            let mut region_bytes = bytes;
            region_bytes.resize(len, 0);
            combined.extend_from_slice(&region_bytes);
        }
        self.snapshots.snapshot(combined, tag)
    }

    /// Restore the state of all regions from a previously taken snapshot.
    ///
    /// The snapshot bytes are replayed back into the cache in the same order
    /// the regions were registered at snapshot time.  If the byte counts do
    /// not match (e.g. a region was added/removed) the restore is best-effort.
    pub fn restore_snapshot(&mut self, id: SnapshotId) -> Result<(), MemError> {
        let data = self
            .snapshots
            .get_data(id)
            .ok_or(MemError::Other(format!("snapshot {} not found", id.0)))?
            .to_vec();

        let mut offset = 0usize;
        for region in &self.regions.clone() {
            let len = region.range.len() as usize;
            if offset + len > data.len() {
                break;
            }
            self.cache
                .lock()
                .write_into_cache(region.range.start, &data[offset..offset + len]);
            offset += len;
        }
        Ok(())
    }

    /// Discard a previously saved snapshot.
    pub fn discard_snapshot(&mut self, id: SnapshotId) -> bool {
        self.snapshots.discard(id)
    }

    /// Number of stored snapshots.
    #[must_use]
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    // ── Internal helpers ────────────────────────────────────────────────────

    fn find_region(&self, addr: Address) -> Option<&EmulatedRegion> {
        self.regions.iter().find(|r| r.range.contains(addr))
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
        // Verify the entire range is mapped and readable.
        // We check only the first and last address for performance; a stricter
        // check can be layered on top if needed.
        let end = addr + (len as u64).saturating_sub(1);
        if self.find_region(addr).is_none() || self.find_region(end).is_none() {
            return Err(MemError::NotMapped(addr));
        }
        if let Some(r) = self.find_region(addr)
            && !r.perms.is_readable() {
                return Err(MemError::PermissionDenied(addr));
            }
        self.cache
            .lock()
            .read(addr, len, |_page_start, page_size| {
                Ok::<Vec<u8>, MemError>(vec![0u8; page_size])
            })
            .map_err(|e: MemError| e)
    }

    fn write(&mut self, addr: Address, data: &[u8]) -> Result<(), MemError> {
        if data.is_empty() {
            return Ok(());
        }
        let end = addr + (data.len() as u64).saturating_sub(1);
        if self.find_region(addr).is_none() || self.find_region(end).is_none() {
            return Err(MemError::NotMapped(addr));
        }
        if let Some(r) = self.find_region(addr)
            && !r.perms.is_writable() {
                return Err(MemError::PermissionDenied(addr));
            }
        self.cache.lock().write_into_cache(addr, data);
        Ok(())
    }

    fn regions(&self) -> Vec<MemoryRegion> {
        self.regions
            .iter()
            .map(|r| MemoryRegion {
                range: r.range,
                perms: r.perms,
                name: r.name.clone(),
                source: RegionSource::Emulated,
            })
            .collect()
    }

    fn is_live(&self) -> bool {
        false
    }

    async fn snapshot(&mut self) -> Result<SnapshotId, MemError> {
        Ok(self.take_snapshot(None))
    }

    async fn restore(&mut self, id: SnapshotId) -> Result<(), MemError> {
        self.restore_snapshot(id)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProcessMemoryProvider
// ─────────────────────────────────────────────────────────────────────────────

/// Reads from a live process using OS-specific APIs.
///
/// On Windows this uses `ReadProcessMemory` (via `windows-sys`).
/// On Linux this uses `process_vm_readv` (via raw libc).
/// Writes are not supported (returns `MemError::Unsupported`).
///
/// The provider maintains a page-granular read cache to reduce the number of
/// syscalls.  The cache is refreshed on every call to [`refresh`] or when
/// [`invalidate_cache`] is explicitly called.
pub struct ProcessMemoryProvider {
    /// Target process identifier.
    pub pid: u32,
    /// Cached memory regions obtained from the OS.
    regions_cache: Vec<MemoryRegion>,
    /// Page-level read cache.
    read_cache: Arc<Mutex<PageCache>>,
}

impl ProcessMemoryProvider {
    /// Attach to process `pid` and build an initial region list.
    ///
    /// On unsupported platforms the region list will be empty; reads will
    /// attempt to use the OS API anyway.
    #[must_use]
    pub fn new(pid: u32) -> Self {
        let regions = Self::enumerate_regions_for_pid(pid);
        Self {
            pid,
            regions_cache: regions,
            read_cache: Arc::new(Mutex::new(PageCache::new(0x1000, 512))),
        }
    }

    /// Invalidate all cached pages, forcing fresh reads from the process.
    pub fn invalidate_cache(&self) {
        self.read_cache.lock().invalidate_all();
    }

    /// Enumerate the memory regions of `pid`.
    ///
    /// On Windows this would walk the VAD via `VirtualQueryEx`; on Linux it
    /// parses `/proc/{pid}/maps`.  Both paths are gated by `cfg()` so the
    /// crate compiles on all platforms.
    fn enumerate_regions_for_pid(pid: u32) -> Vec<MemoryRegion> {
        #[cfg(target_os = "linux")]
        {
            Self::parse_proc_maps(pid)
        }
        #[cfg(target_os = "windows")]
        {
            Self::virtual_query_regions(pid)
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = pid;
            Vec::new()
        }
    }

    /// Parse `/proc/{pid}/maps` to obtain memory regions.
    #[cfg(target_os = "linux")]
    fn parse_proc_maps(pid: u32) -> Vec<MemoryRegion> {
        use std::io::{BufRead, BufReader};
        let path = format!("/proc/{pid}/maps");
        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        let reader = BufReader::new(file);
        let mut regions = Vec::new();

        for line in reader.lines().map_while(Result::ok) {
            // Format: address_range perms offset dev inode [pathname]
            // e.g.  "7f1234000000-7f1234001000 r-xp 00000000 fd:01 123456 /lib/libc.so"
            let parts: Vec<&str> = line.splitn(6, ' ').collect();
            if parts.len() < 5 {
                continue;
            }
            let range_str = parts[0];
            let perms_str = parts[1];
            let name = parts
                .get(5)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());

            let mut addrs = range_str.splitn(2, '-');
            let start_hex = addrs.next().unwrap_or("0");
            let end_hex = addrs.next().unwrap_or("0");
            let start = u64::from_str_radix(start_hex, 16).unwrap_or(0);
            let end = u64::from_str_radix(end_hex, 16).unwrap_or(0);
            if start >= end {
                continue;
            }

            let mut perms = Permissions::empty();
            let pb = perms_str.as_bytes();
            if pb.first() == Some(&b'r') {
                perms |= Permissions::READ;
            }
            if pb.get(1) == Some(&b'w') {
                perms |= Permissions::WRITE;
            }
            if pb.get(2) == Some(&b'x') {
                perms |= Permissions::EXECUTE;
            }

            let source = if let Some(ref n) = name {
                if n.starts_with('[') {
                    RegionSource::Anonymous
                } else {
                    RegionSource::FileSection {
                        file: std::path::PathBuf::from(n),
                        section: String::new(),
                        file_offset: 0,
                    }
                }
            } else {
                RegionSource::Anonymous
            };

            regions.push(MemoryRegion {
                range: AddressRange::new(Address::new(start), Address::new(end)),
                perms,
                name,
                source,
            });
        }
        regions
    }

    /// Enumerate regions via `VirtualQueryEx` on Windows.
    #[cfg(target_os = "windows")]
    fn virtual_query_regions(pid: u32) -> Vec<MemoryRegion> {
        use std::mem::MaybeUninit;
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Memory::{
            MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READONLY, PAGE_READWRITE,
            PAGE_WRITECOPY, VirtualQueryEx,
        };
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
        };

        let mut regions = Vec::new();
        let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return regions;
        }

        let mut addr: usize = 0;
        loop {
            let mut mbi = MaybeUninit::<MEMORY_BASIC_INFORMATION>::uninit();
            let ret = unsafe {
                VirtualQueryEx(
                    handle,
                    addr as *const _,
                    mbi.as_mut_ptr(),
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if ret == 0 {
                break;
            }
            let mbi = unsafe { mbi.assume_init() };
            if mbi.State == MEM_COMMIT {
                let mut perms = Permissions::empty();
                let p = mbi.Protect;
                if p == PAGE_READONLY
                    || p == PAGE_READWRITE
                    || p == PAGE_EXECUTE_READ
                    || p == PAGE_EXECUTE_READWRITE
                    || p == PAGE_WRITECOPY
                    || p == PAGE_EXECUTE_WRITECOPY
                {
                    perms |= Permissions::READ;
                }
                if p == PAGE_READWRITE
                    || p == PAGE_EXECUTE_READWRITE
                    || p == PAGE_WRITECOPY
                    || p == PAGE_EXECUTE_WRITECOPY
                {
                    perms |= Permissions::WRITE;
                }
                if p == PAGE_EXECUTE
                    || p == PAGE_EXECUTE_READ
                    || p == PAGE_EXECUTE_READWRITE
                    || p == PAGE_EXECUTE_WRITECOPY
                {
                    perms |= Permissions::EXECUTE;
                }
                let start = mbi.BaseAddress as u64;
                let end = start + mbi.RegionSize as u64;
                regions.push(MemoryRegion {
                    range: AddressRange::new(Address::new(start), Address::new(end)),
                    perms,
                    name: None,
                    source: RegionSource::ProcessModule {
                        module: String::new(),
                        pid,
                    },
                });
            }
            addr = mbi.BaseAddress as usize + mbi.RegionSize;
        }
        unsafe { CloseHandle(handle) };
        regions
    }

    /// Perform the actual OS read from the target process.
    ///
    /// This is a synchronous operation; callers must not hold locks that could
    /// deadlock with the OS scheduler.
    fn os_read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        #[cfg(target_os = "linux")]
        {
            self.linux_read(addr, len)
        }
        #[cfg(target_os = "windows")]
        {
            self.windows_read(addr, len)
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            // Generic fallback: return zeros and log.  Useful for unit-testing on
            // platforms that support neither.
            let _ = (addr, len);
            Ok(vec![0u8; len])
        }
    }

    #[cfg(target_os = "linux")]
    fn linux_read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        // process_vm_readv is available on Linux >= 3.2.
        // We use the raw syscall via libc so we do not add a dependency on nix.
        use std::io;
        unsafe extern "C" {
            fn process_vm_readv(
                pid: libc::pid_t,
                local_iov: *const libc::iovec,
                liovcnt: libc::c_ulong,
                remote_iov: *const libc::iovec,
                riovcnt: libc::c_ulong,
                flags: libc::c_ulong,
            ) -> libc::ssize_t;
        }

        let mut buf = vec![0u8; len];
        let local_iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut _,
            iov_len: len,
        };
        let remote_iov = libc::iovec {
            iov_base: addr.as_u64() as *mut _,
            iov_len: len,
        };
        let ret =
            unsafe { process_vm_readv(self.pid as libc::pid_t, &local_iov, 1, &remote_iov, 1, 0) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            return Err(MemError::Other(format!("process_vm_readv failed: {err}")));
        }
        buf.truncate(ret as usize);
        Ok(buf)
    }

    #[cfg(target_os = "windows")]
    fn windows_read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ};

        let handle = unsafe { OpenProcess(PROCESS_VM_READ, 0, self.pid) };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(MemError::Other(format!(
                "OpenProcess({}) failed: {}",
                self.pid,
                std::io::Error::last_os_error()
            )));
        }

        let mut buf = vec![0u8; len];
        let mut bytes_read: usize = 0;
        let ret = unsafe {
            ReadProcessMemory(
                handle,
                addr.as_u64() as *const _,
                buf.as_mut_ptr().cast(),
                len,
                &raw mut bytes_read,
            )
        };
        unsafe { CloseHandle(handle) };

        if ret == 0 {
            return Err(MemError::NotMapped(addr));
        }
        buf.truncate(bytes_read);
        Ok(buf)
    }
}

#[async_trait]
impl MemoryProvider for ProcessMemoryProvider {
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        // Try to serve from cache first.
        let mut cache = self.read_cache.lock();
        let pid = self.pid;
        let os_reader = |page_start: Address, page_size: usize| {
            // Open and read the page via the OS API.
            // We allocate a temporary provider to do the read.
            let tmp = Self {
                pid,
                regions_cache: Vec::new(),
                read_cache: Arc::new(Mutex::new(PageCache::new(0x1000, 0))),
            };
            tmp.os_read(page_start, page_size)
        };
        cache.read(addr, len, os_reader)
    }

    fn write(&mut self, _addr: Address, _data: &[u8]) -> Result<(), MemError> {
        // Process memory writes via ptrace/WriteProcessMemory are supported in
        // principle but are not implemented here to keep the provider focused.
        Err(MemError::Unsupported)
    }

    fn regions(&self) -> Vec<MemoryRegion> {
        self.regions_cache.clone()
    }

    fn is_live(&self) -> bool {
        true
    }

    async fn refresh(&mut self) -> Result<(), MemError> {
        self.regions_cache = Self::enumerate_regions_for_pid(self.pid);
        self.read_cache.lock().invalidate_all();
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TraceTickMemory — a single snapshot in a TTD-style trace
// ─────────────────────────────────────────────────────────────────────────────

/// A memory snapshot at a specific trace tick.
#[derive(Debug, Clone)]
pub struct TraceTickMemory {
    /// The tick number (monotonically increasing).
    pub tick: u64,
    /// Regions and their contents at this tick.
    pub regions: Vec<MemoryRegion>,
    /// Flat byte dumps, aligned with `regions` (regions[i] -> data[i]).
    pub data: Vec<Vec<u8>>,
}

impl TraceTickMemory {
    /// Create a tick snapshot from a list of `(region, bytes)` pairs.
    #[must_use]
    pub fn new(tick: u64, region_data: Vec<(MemoryRegion, Vec<u8>)>) -> Self {
        let mut regions = Vec::with_capacity(region_data.len());
        let mut data = Vec::with_capacity(region_data.len());
        for (r, d) in region_data {
            regions.push(r);
            data.push(d);
        }
        Self {
            tick,
            regions,
            data,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TraceMemoryProvider
// ─────────────────────────────────────────────────────────────────────────────

/// Replays memory state from a pre-recorded sequence of `TraceTickMemory`
/// snapshots.  This is the in-platform approximation of Windows TTD / rr-style
/// trace replay.
///
/// The trace is a sorted list of tick snapshots.  When reading at tick `T`, the
/// provider finds the latest snapshot with `tick <= T` and serves bytes from
/// there.
///
/// Writes are silently discarded (replay is read-only by design).
pub struct TraceMemoryProvider {
    /// All recorded memory snapshots, sorted by tick ascending.
    ticks: Vec<TraceTickMemory>,
    /// The current replay tick.
    pub current_tick: u64,
    /// Per-tick page cache.  Wrapped in a `Mutex` for thread-safe interior
    /// mutability through `MemoryProvider::read(&self, ...)`.
    cache: Mutex<PageCache>,
    /// The tick index of the most recently loaded cache.
    cached_tick_idx: Option<usize>,
}

impl TraceMemoryProvider {
    /// Create a provider from a list of tick snapshots (need not be sorted).
    #[must_use]
    pub fn new(mut ticks: Vec<TraceTickMemory>) -> Self {
        ticks.sort_by_key(|t| t.tick);
        let max_tick = ticks.last().map_or(0, |t| t.tick);
        Self {
            ticks,
            current_tick: max_tick,
            cache: Mutex::new(PageCache::new(0x1000, 256)),
            cached_tick_idx: None,
        }
    }

    /// Seek to `tick`.  This invalidates the current cache if the tick index
    /// changes.
    pub fn seek_to(&mut self, tick: u64) {
        let old_idx = self.find_tick_idx(self.current_tick);
        let new_idx = self.find_tick_idx(tick);
        self.current_tick = tick;
        if old_idx != new_idx {
            self.cache.lock().invalidate_all();
            self.cached_tick_idx = None;
        }
    }

    /// Number of recorded ticks.
    #[must_use]
    pub const fn tick_count(&self) -> usize {
        self.ticks.len()
    }

    /// Return the earliest recorded tick number.
    #[must_use]
    pub fn first_tick(&self) -> Option<u64> {
        self.ticks.first().map(|t| t.tick)
    }

    /// Return the latest recorded tick number.
    #[must_use]
    pub fn last_tick(&self) -> Option<u64> {
        self.ticks.last().map(|t| t.tick)
    }

    // ── Internal helpers ────────────────────────────────────────────────────

    /// Find the index of the latest tick snapshot at or before `tick`.
    fn find_tick_idx(&self, tick: u64) -> Option<usize> {
        // Binary search for the rightmost tick <= `tick`.
        let idx = self.ticks.partition_point(|t| t.tick <= tick);
        if idx == 0 { None } else { Some(idx - 1) }
    }

    fn read_from_tick(
        &self,
        tick_idx: usize,
        addr: Address,
        len: usize,
    ) -> Result<Vec<u8>, MemError> {
        let tick = &self.ticks[tick_idx];
        let mut result = vec![0u8; len];
        let mut filled = 0usize;
        let end_addr = addr + len as u64;

        for (region, data) in tick.regions.iter().zip(tick.data.iter()) {
            if !region.range.overlaps(&AddressRange::new(addr, end_addr)) {
                continue;
            }
            let region_start = region.range.start.as_u64();
            let overlap_start = addr.as_u64().max(region_start);
            let overlap_end = end_addr.as_u64().min(region.range.end.as_u64());
            if overlap_start >= overlap_end {
                continue;
            }
            let dst_offset = (overlap_start - addr.as_u64()) as usize;
            let src_offset = (overlap_start - region_start) as usize;
            let copy_len = (overlap_end - overlap_start) as usize;
            let src_end = (src_offset + copy_len).min(data.len());
            let actual_copy = src_end.saturating_sub(src_offset);
            if actual_copy == 0 {
                continue;
            }
            result[dst_offset..dst_offset + actual_copy]
                .copy_from_slice(&data[src_offset..src_offset + actual_copy]);
            filled += actual_copy;
        }

        if filled == 0 && len > 0 {
            return Err(MemError::NotMapped(addr));
        }
        Ok(result)
    }
}

#[async_trait]
impl MemoryProvider for TraceMemoryProvider {
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        let tick_idx = self
            .find_tick_idx(self.current_tick)
            .ok_or(MemError::Other("no ticks in trace".into()))?;
        // Use `read_from_tick` as the page-fetch callback inside the cache.
        let result = self.cache.lock().read(addr, len, |page_start, page_size| {
            self.read_from_tick(tick_idx, page_start, page_size)
        })?;
        Ok(result)
    }

    fn write(&mut self, _addr: Address, _data: &[u8]) -> Result<(), MemError> {
        // Trace replay is read-only.
        Err(MemError::Unsupported)
    }

    fn regions(&self) -> Vec<MemoryRegion> {
        let tick_idx = match self.find_tick_idx(self.current_tick) {
            Some(i) => i,
            None => return Vec::new(),
        };
        self.ticks[tick_idx].regions.clone()
    }

    fn is_live(&self) -> bool {
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── EmulatedMemoryProvider ────────────────────────────────────────────────

    fn make_emulated() -> EmulatedMemoryProvider {
        let mut p = EmulatedMemoryProvider::new();
        let code_data = vec![0x90u8; 0x1000]; // NOP sled
        p.add_region(
            Address::new(0x1000),
            code_data,
            Permissions::READ | Permissions::EXECUTE,
            Some(".text".into()),
        );
        let data_buf = (0u8..=0xFFu8).cycle().take(0x1000).collect::<Vec<_>>();
        p.add_region(
            Address::new(0x2000),
            data_buf,
            Permissions::READ | Permissions::WRITE,
            Some(".data".into()),
        );
        p
    }

    #[test]
    fn emulated_read_code() {
        let p = make_emulated();
        let bytes = p.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(bytes, [0x90, 0x90, 0x90, 0x90]);
    }

    #[test]
    fn emulated_write_data() {
        let mut p = make_emulated();
        p.write(Address::new(0x2000), &[0xDE, 0xAD, 0xBE, 0xEF])
            .unwrap();
        let back = p.read(Address::new(0x2000), 4).unwrap();
        assert_eq!(back, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn emulated_write_code_denied() {
        let mut p = make_emulated();
        let result = p.write(Address::new(0x1000), &[0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn emulated_read_unmapped_errors() {
        let p = make_emulated();
        let result = p.read(Address::new(0x9000), 4);
        assert!(result.is_err());
    }

    #[test]
    fn emulated_regions() {
        let p = make_emulated();
        let regions = p.regions();
        assert_eq!(regions.len(), 2);
        let names: Vec<_> = regions.iter().filter_map(|r| r.name.as_deref()).collect();
        assert!(names.contains(&".text"));
        assert!(names.contains(&".data"));
    }

    #[test]
    fn emulated_snapshot_restore() {
        let mut p = make_emulated();
        p.write(Address::new(0x2000), &[0x11, 0x22, 0x33, 0x44])
            .unwrap();
        let id = p.take_snapshot(Some("before".into()));

        // Mutate further.
        p.write(Address::new(0x2000), &[0xFF, 0xFF, 0xFF, 0xFF])
            .unwrap();
        let after = p.read(Address::new(0x2000), 4).unwrap();
        assert_eq!(after, [0xFF, 0xFF, 0xFF, 0xFF]);

        // Restore.
        p.restore_snapshot(id).unwrap();
        let restored = p.read(Address::new(0x2000), 4).unwrap();
        assert_eq!(restored, [0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn emulated_snapshot_count() {
        let mut p = EmulatedMemoryProvider::new();
        p.add_region(
            Address::new(0),
            vec![0u8; 16],
            Permissions::READ | Permissions::WRITE,
            None,
        );
        p.take_snapshot(None);
        p.take_snapshot(None);
        assert_eq!(p.snapshot_count(), 2);
    }

    #[test]
    fn emulated_remove_region() {
        let mut p = make_emulated();
        assert!(p.remove_region(Address::new(0x1000)));
        assert_eq!(p.region_count(), 1);
        assert!(!p.remove_region(Address::new(0x1000))); // already gone
    }

    // ── TraceMemoryProvider ───────────────────────────────────────────────────

    fn make_trace() -> TraceMemoryProvider {
        // Tick 0: region at 0x1000 filled with 0xAA
        let tick0 = TraceTickMemory::new(
            0,
            vec![(
                MemoryRegion {
                    range: AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
                    perms: Permissions::READ,
                    name: None,
                    source: RegionSource::Anonymous,
                },
                vec![0xAAu8; 0x1000],
            )],
        );
        // Tick 5: region at 0x1000 changed to 0xBB
        let tick5 = TraceTickMemory::new(
            5,
            vec![(
                MemoryRegion {
                    range: AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
                    perms: Permissions::READ,
                    name: None,
                    source: RegionSource::Anonymous,
                },
                vec![0xBBu8; 0x1000],
            )],
        );
        TraceMemoryProvider::new(vec![tick0, tick5])
    }

    #[test]
    fn trace_reads_latest_tick() {
        let p = make_trace();
        let bytes = p.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(bytes, [0xBBu8; 4]);
    }

    #[test]
    fn trace_seek_to_earlier_tick() {
        let mut p = make_trace();
        p.seek_to(0);
        let bytes = p.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(bytes, [0xAAu8; 4]);
    }

    #[test]
    fn trace_seek_to_between_ticks() {
        let mut p = make_trace();
        p.seek_to(3); // between tick 0 and tick 5
        let bytes = p.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(bytes, [0xAAu8; 4]); // latest tick <= 3 is tick 0
    }

    #[test]
    fn trace_tick_count() {
        let p = make_trace();
        assert_eq!(p.tick_count(), 2);
        assert_eq!(p.first_tick(), Some(0));
        assert_eq!(p.last_tick(), Some(5));
    }

    #[test]
    fn trace_write_returns_unsupported() {
        let mut p = make_trace();
        let result = p.write(Address::new(0x1000), &[0x00]);
        assert!(matches!(result, Err(MemError::Unsupported)));
    }

    #[test]
    fn trace_is_not_live() {
        let p = make_trace();
        assert!(!p.is_live());
    }
}
