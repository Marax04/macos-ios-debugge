//! [`ProcessMemoryProvider`] — live process memory via OS APIs.
//!
//! # Overview
//!
//! This provider attaches to a running process and exposes its virtual address
//! space through the [`MemoryProvider`] interface.  The implementation is a
//! *stub* in the sense that the OS-specific calls are gated behind `#[cfg]`
//! guards; on unsupported platforms all reads return
//! [`MemError::Unsupported`].
//!
//! ## Platform support
//!
//! | Platform | Region enumeration | Byte reads |
//! |---|---|---|
//! | Windows | `VirtualQueryEx` | `ReadProcessMemory` |
//! | Linux | `/proc/{pid}/maps` | `process_vm_readv` |
//! | Other | empty list (stub) | `Unsupported` |
//!
//! ## Attaching
//!
//! ```rust,ignore
//! let mut provider = ProcessMemoryProvider::attach(1234)?;
//! let bytes = provider.read(Address::new(0x7fff_0000), 16)?;
//! ```
//!
//! ## Region refresh
//!
//! Call [`ProcessMemoryProvider::refresh_regions`] to re-enumerate the memory
//! map of the live process (e.g. after a `dlopen` or `VirtualAlloc`).
//!
//! ## Writes
//!
//! Writing to process memory via `ptrace` / `WriteProcessMemory` is supported
//! in principle but not yet implemented; `write` returns
//! [`MemError::Unsupported`].

use async_trait::async_trait;
use rustre_core::address::{Address, AddressRange};
use rustre_core::permissions::Permissions;

use crate::memory_provider::{MemError, MemoryProvider, MemoryRegion, RegionSource, SnapshotId};

// ─────────────────────────────────────────────────────────────────────────────
// MemRegion — a lightweight representation used internally
// ─────────────────────────────────────────────────────────────────────────────

/// A lightweight description of a mapped region in a live process.
///
/// This mirrors the information available from `/proc/{pid}/maps` on Linux and
/// `MEMORY_BASIC_INFORMATION` on Windows.
#[derive(Debug, Clone)]
pub struct MemRegion {
    /// Start of the region (inclusive).
    pub base: u64,
    /// Size in bytes.
    pub size: u64,
    /// Permission flags.
    pub perms: Permissions,
    /// Name / path of the backing file or label (`[heap]`, `[stack]`, …).
    pub name: Option<String>,
}

impl MemRegion {
    /// Construct a region descriptor.
    #[must_use] 
    pub const fn new(base: u64, size: u64, perms: Permissions, name: Option<String>) -> Self {
        Self {
            base,
            size,
            perms,
            name,
        }
    }

    /// Exclusive end address.
    #[inline]
    #[must_use] 
    pub const fn end(&self) -> u64 {
        self.base + self.size
    }

    /// Convert to the public [`MemoryRegion`] type.
    #[must_use] 
    pub fn to_memory_region(&self, pid: u32) -> MemoryRegion {
        let start = Address::new(self.base);
        let end = Address::new(self.end());
        let source = if let Some(ref n) = self.name {
            if n.starts_with('[') {
                RegionSource::Anonymous
            } else {
                RegionSource::ProcessModule {
                    module: n.clone(),
                    pid,
                }
            }
        } else {
            RegionSource::Anonymous
        };
        MemoryRegion {
            range: AddressRange::new(start, end),
            perms: self.perms,
            name: self.name.clone(),
            source,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProcessMemoryProvider
// ─────────────────────────────────────────────────────────────────────────────

/// Reads live process memory using platform-specific OS APIs.
///
/// # Fields (spec §2.3)
///
/// - `pid: u32` — target process identifier
/// - `regions: Vec<MemRegion>` — currently known memory map
pub struct ProcessMemoryProvider {
    /// Target process identifier.
    pub pid: u32,
    /// Cached memory region list obtained from the OS.
    pub regions: Vec<MemRegion>,
}

impl ProcessMemoryProvider {
    /// Attach to process `pid`, enumerate its regions, and return a ready
    /// provider.
    ///
    /// On platforms where region enumeration is not supported the region list
    /// will be empty; reads will still be attempted via the OS API.
    pub fn attach(pid: u32) -> Result<Self, MemError> {
        let regions = Self::enumerate_regions(pid)?;
        Ok(Self { pid, regions })
    }

    /// Re-enumerate the memory map of the live process.
    ///
    /// Call this after `dlopen`, `mmap`, `VirtualAlloc`, or any other event
    /// that may change the process layout.
    pub fn refresh_regions(&mut self) -> Result<(), MemError> {
        self.regions = Self::enumerate_regions(self.pid)?;
        Ok(())
    }

    /// Return the number of currently cached regions.
    #[must_use]
    pub const fn region_count(&self) -> usize {
        self.regions.len()
    }

    /// Return the region that contains `addr`, if any.
    #[must_use]
    pub fn region_at(&self, addr: u64) -> Option<&MemRegion> {
        self.regions
            .iter()
            .find(|r| addr >= r.base && addr < r.end())
    }

    // ── OS-specific region enumeration ───────────────────────────────────────

    fn enumerate_regions(pid: u32) -> Result<Vec<MemRegion>, MemError> {
        #[cfg(target_os = "linux")]
        return Self::enumerate_linux(pid);

        #[cfg(target_os = "windows")]
        return Self::enumerate_windows(pid);

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = pid;
            Ok(Vec::new())
        }
    }

    // ── Linux ─────────────────────────────────────────────────────────────────

    #[cfg(target_os = "linux")]
    fn enumerate_linux(pid: u32) -> Result<Vec<MemRegion>, MemError> {
        use std::io::{BufRead, BufReader};
        let path = format!("/proc/{pid}/maps");
        let file = std::fs::File::open(&path).map_err(MemError::from)?;
        let reader = BufReader::new(file);
        let mut regions = Vec::new();

        for line in reader.lines() {
            let line = line.map_err(MemError::from)?;
            // Format: addr_start-addr_end perms offset dev inode [pathname]
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

            let mut range_parts = range_str.splitn(2, '-');
            let start = u64::from_str_radix(range_parts.next().unwrap_or("0"), 16).unwrap_or(0);
            let end = u64::from_str_radix(range_parts.next().unwrap_or("0"), 16).unwrap_or(0);
            if start >= end {
                continue;
            }

            let pb = perms_str.as_bytes();
            let mut perms = Permissions::empty();
            if pb.first() == Some(&b'r') {
                perms |= Permissions::READ;
            }
            if pb.get(1) == Some(&b'w') {
                perms |= Permissions::WRITE;
            }
            if pb.get(2) == Some(&b'x') {
                perms |= Permissions::EXECUTE;
            }

            regions.push(MemRegion::new(start, end - start, perms, name));
        }
        Ok(regions)
    }

    // ── Windows ───────────────────────────────────────────────────────────────

    #[cfg(target_os = "windows")]
    fn enumerate_windows(pid: u32) -> Result<Vec<MemRegion>, MemError> {
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

        let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(MemError::Other(format!(
                "OpenProcess({pid}) failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let mut regions = Vec::new();
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
                let p = mbi.Protect;
                let mut perms = Permissions::empty();
                if matches!(
                    p,
                    PAGE_READONLY
                        | PAGE_READWRITE
                        | PAGE_EXECUTE_READ
                        | PAGE_EXECUTE_READWRITE
                        | PAGE_WRITECOPY
                        | PAGE_EXECUTE_WRITECOPY
                ) {
                    perms |= Permissions::READ;
                }
                if matches!(
                    p,
                    PAGE_READWRITE
                        | PAGE_EXECUTE_READWRITE
                        | PAGE_WRITECOPY
                        | PAGE_EXECUTE_WRITECOPY
                ) {
                    perms |= Permissions::WRITE;
                }
                if matches!(
                    p,
                    PAGE_EXECUTE
                        | PAGE_EXECUTE_READ
                        | PAGE_EXECUTE_READWRITE
                        | PAGE_EXECUTE_WRITECOPY
                ) {
                    perms |= Permissions::EXECUTE;
                }
                regions.push(MemRegion::new(
                    mbi.BaseAddress as u64,
                    mbi.RegionSize as u64,
                    perms,
                    None,
                ));
            }
            addr = mbi.BaseAddress as usize + mbi.RegionSize;
        }
        unsafe { CloseHandle(handle) };
        Ok(regions)
    }

    // ── OS-specific byte reads ────────────────────────────────────────────────

    fn os_read_bytes(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        if len == 0 {
            return Ok(Vec::new());
        }

        #[cfg(target_os = "linux")]
        return self.linux_read(addr, len);

        #[cfg(target_os = "windows")]
        return self.windows_read(addr, len);

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = (addr, len);
            Err(MemError::Unsupported)
        }
    }

    #[cfg(target_os = "linux")]
    fn linux_read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
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
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut _,
            iov_len: len,
        };
        let remote = libc::iovec {
            iov_base: addr.as_u64() as *mut _,
            iov_len: len,
        };
        let ret = unsafe { process_vm_readv(self.pid as libc::pid_t, &local, 1, &remote, 1, 0) };
        if ret < 0 {
            return Err(MemError::Other(format!(
                "process_vm_readv failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        buf.truncate(ret as usize);
        Ok(buf)
    }

    #[cfg(target_os = "windows")]
    fn windows_read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ};

        /// RAII guard that closes a Windows HANDLE on drop.
        struct HandleGuard(HANDLE);
        impl Drop for HandleGuard {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    unsafe { CloseHandle(self.0) };
                }
            }
        }

        let raw_handle = unsafe { OpenProcess(PROCESS_VM_READ, 0, self.pid) };
        if raw_handle == INVALID_HANDLE_VALUE || raw_handle.is_null() {
            return Err(MemError::Other(format!(
                "OpenProcess({}) failed: {}",
                self.pid,
                std::io::Error::last_os_error()
            )));
        }
        // Guard ensures CloseHandle is called even if we return early or panic.
        let _guard = HandleGuard(raw_handle);

        let mut buf = vec![0u8; len];
        let mut bytes_read: usize = 0;
        let ret = unsafe {
            ReadProcessMemory(
                raw_handle,
                addr.as_u64() as *const _,
                buf.as_mut_ptr().cast(),
                len,
                &raw mut bytes_read,
            )
        };

        if ret == 0 {
            return Err(MemError::NotMapped(addr));
        }
        buf.truncate(bytes_read);
        Ok(buf)
    }
}

// SAFETY: ProcessMemoryProvider holds no raw pointers in Rust memory — all OS
// handles are opened and closed within individual method calls.
unsafe impl Send for ProcessMemoryProvider {}
unsafe impl Sync for ProcessMemoryProvider {}

#[async_trait]
impl MemoryProvider for ProcessMemoryProvider {
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        self.os_read_bytes(addr, len)
    }

    fn write(&mut self, _addr: Address, _data: &[u8]) -> Result<(), MemError> {
        // Writing to process memory via WriteProcessMemory / ptrace POKEDATA is
        // possible but not yet implemented in this stub.
        Err(MemError::Unsupported)
    }

    fn regions(&self) -> Vec<MemoryRegion> {
        let pid = self.pid;
        self.regions
            .iter()
            .map(|r| r.to_memory_region(pid))
            .collect()
    }

    fn is_live(&self) -> bool {
        true
    }

    async fn refresh(&mut self) -> Result<(), MemError> {
        self.refresh_regions()
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

    /// Build a provider whose region list is pre-populated without going to
    /// the OS, so tests work on every platform.
    fn fake_provider(pid: u32, regions: Vec<MemRegion>) -> ProcessMemoryProvider {
        ProcessMemoryProvider { pid, regions }
    }

    #[test]
    fn attach_returns_provider() {
        // On the current platform (wherever tests run) we at least get a
        // provider back without panicking.  The region list may be empty on
        // unsupported platforms, and that is fine.
        let _p = ProcessMemoryProvider::attach(std::process::id());
        // If we get here without a panic, the test passes.
    }

    #[test]
    fn regions_converts_correctly() {
        let p = fake_provider(
            42,
            vec![
                MemRegion::new(0x1000, 0x1000, Permissions::READ, Some("[stack]".into())),
                MemRegion::new(0x3000, 0x2000, Permissions::READ | Permissions::WRITE, None),
            ],
        );
        let rs = p.regions();
        assert_eq!(rs.len(), 2);
        assert_eq!(rs[0].range.start, Address::new(0x1000));
        assert_eq!(rs[1].perms, Permissions::READ | Permissions::WRITE);
    }

    #[test]
    fn write_returns_unsupported() {
        let mut p = fake_provider(1, vec![]);
        assert!(matches!(
            p.write(Address::new(0x1000), &[0xAA]),
            Err(MemError::Unsupported)
        ));
    }

    #[test]
    fn is_live_is_true() {
        let p = fake_provider(1, vec![]);
        assert!(p.is_live());
    }

    #[test]
    fn region_at_finds_correct_region() {
        let p = fake_provider(
            1,
            vec![MemRegion::new(0x1000, 0x1000, Permissions::READ, None)],
        );
        assert!(p.region_at(0x1500).is_some());
        assert!(p.region_at(0x3000).is_none());
    }

    #[test]
    fn region_count_is_correct() {
        let p = fake_provider(
            9,
            vec![
                MemRegion::new(0, 0x1000, Permissions::READ, None),
                MemRegion::new(
                    0x2000,
                    0x1000,
                    Permissions::READ | Permissions::EXECUTE,
                    None,
                ),
                MemRegion::new(0x4000, 0x2000, Permissions::READ | Permissions::WRITE, None),
            ],
        );
        assert_eq!(p.region_count(), 3);
    }

    #[test]
    fn mem_region_end_is_correct() {
        let r = MemRegion::new(0x1000, 0x500, Permissions::READ, None);
        assert_eq!(r.end(), 0x1500);
    }

    #[test]
    fn mem_region_to_memory_region_name_forwarded() {
        let r = MemRegion::new(
            0x7fff_0000,
            0x1000,
            Permissions::READ,
            Some("libfoo.so".into()),
        );
        let mr = r.to_memory_region(100);
        assert_eq!(mr.name.as_deref(), Some("libfoo.so"));
    }

    #[test]
    fn zero_length_read_returns_empty() {
        let p = fake_provider(1, vec![]);
        // Even on unsupported platforms a zero-length read returns an empty vec.
        // The os_read_bytes fast-path returns Ok(vec![]) for len == 0.
        let result = p.read(Address::new(0x1000), 0).unwrap();
        assert!(result.is_empty());
    }
}
