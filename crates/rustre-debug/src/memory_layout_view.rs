//! `memory_layout_view` — runtime memory layout visualisation.
//!
//! Provides:
//! - Heap layout analysis: glibc ptmalloc2, jemalloc, tcmalloc, Windows HeapWalk
//! - Live stack-frame unwinding from a register set + memory reader
//! - Mapped memory regions with permissions and file backing
//! - ASLR base offset calculation per module
//! - Guard page detection

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the memory layout subsystem.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MemoryLayoutError {
    #[error("memory read error at {0:#x}: {1}")]
    ReadError(u64, String),
    #[error("invalid heap header at {0:#x}")]
    InvalidHeapHeader(u64),
    #[error("stack unwind failed at frame {0}: {1}")]
    UnwindError(usize, String),
    #[error("region not found for address {0:#x}")]
    RegionNotFound(u64),
    #[error("unsupported allocator: {0}")]
    UnsupportedAllocator(String),
    #[error("parse error: {0}")]
    ParseError(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryRegion — a mapped region with full metadata
// ─────────────────────────────────────────────────────────────────────────────

/// Additional mapping flags beyond the basic rwx permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MappingFlags {
    /// Page is copy-on-write (shared mapping with lazy copy).
    pub copy_on_write: bool,
}

/// Protection flags for a memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Protection {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub mapping: MappingFlags,
}

impl Protection {
    #[must_use]
    pub const fn rwx() -> Self {
        Self { readable: true, writable: true, executable: true, mapping: MappingFlags { copy_on_write: false } }
    }

    #[must_use]
    pub const fn rx() -> Self {
        Self { readable: true, writable: false, executable: true, mapping: MappingFlags { copy_on_write: false } }
    }

    #[must_use]
    pub const fn rw() -> Self {
        Self { readable: true, writable: true, executable: false, mapping: MappingFlags { copy_on_write: false } }
    }

    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }
}

impl fmt::Display for Protection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}{}",
            if self.readable { 'r' } else { '-' },
            if self.writable { 'w' } else { '-' },
            if self.executable { 'x' } else { '-' },
            if self.mapping.copy_on_write { 'c' } else { 'p' },
        )
    }
}

/// The type / role of a mapped region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionKind {
    /// Anonymous private mapping (stack, heap, anonymous mmap).
    Anonymous,
    /// Backed by a file (shared library, executable, mmap'd file).
    FileBacked { path: String, offset: u64 },
    /// The main thread's stack.
    MainStack,
    /// A thread stack (identified by heuristic).
    ThreadStack { tid: u32 },
    /// A heap arena.
    Heap { allocator: String },
    /// A guard page (`PROT_NONE` or no-access sentinel).
    Guard,
    /// vDSO / vsyscall / vvar special regions.
    Vdso,
    /// Kernel-mapped region (e.g. `[vsyscall]`).
    Kernel,
}

impl fmt::Display for RegionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anonymous => write!(f, "[anon]"),
            Self::FileBacked { path, offset } => write!(f, "{path}+{offset:#x}"),
            Self::MainStack => write!(f, "[stack]"),
            Self::ThreadStack { tid } => write!(f, "[stack:tid={tid}]"),
            Self::Heap { allocator } => write!(f, "[heap:{allocator}]"),
            Self::Guard => write!(f, "[guard]"),
            Self::Vdso => write!(f, "[vdso]"),
            Self::Kernel => write!(f, "[kernel]"),
        }
    }
}

/// A single mapped memory region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// Start address (inclusive).
    pub start: u64,
    /// End address (exclusive).
    pub end: u64,
    /// Memory protection flags.
    pub prot: Protection,
    /// Semantic kind of the region.
    pub kind: RegionKind,
    /// ASLR offset relative to the module's preferred base (0 for anonymous).
    pub aslr_offset: i64,
    /// Whether this region is a guard page.
    pub is_guard: bool,
    /// RSS (resident set size) in bytes, if known.
    pub rss: Option<u64>,
}

impl MemoryRegion {
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}

impl fmt::Display for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#018x}-{:#018x} {} {:>8} {}{}",
            self.start,
            self.end,
            self.prot,
            humanize_size(self.size()),
            self.kind,
            if self.is_guard { " [GUARD]" } else { "" },
        )
    }
}

fn humanize_size(bytes: u64) -> String {
    const G: u64 = 1 << 30;
    const M: u64 = 1 << 20;
    const K: u64 = 1 << 10;
    if bytes >= G {
        format!("{}.{}G", bytes / G, (bytes % G) * 10 / G)
    } else if bytes >= M {
        format!("{}.{}M", bytes / M, (bytes % M) * 10 / M)
    } else if bytes >= K {
        format!("{}.{}K", bytes / K, (bytes % K) * 10 / K)
    } else {
        format!("{bytes}B")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MappedRegionView — the full virtual address space view
// ─────────────────────────────────────────────────────────────────────────────

/// The complete runtime virtual address space of a process.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MappedRegionView {
    /// All mapped regions, sorted by start address.
    pub regions: Vec<MemoryRegion>,
}

impl MappedRegionView {
    /// Build a view from what [`crate::Debugger::memory_maps`] already returns.
    ///
    /// This type was `pub`, documented and reachable, and NOTHING in the crate
    /// could produce one from a live process: every `MemoryRegion` ever built
    /// was built by a test. So the whole view — guard-page scan, ASLR offsets,
    /// RSS totals — was unreachable from a real target, which is also why the
    /// RSS was never measured (iteration 418).
    ///
    /// Sorted by start address on the way in, because `find` binary-searches on
    /// that ordering and a caller handing over the OS's own order would
    /// otherwise get `None` for an address that IS mapped.
    #[must_use]
    pub fn from_memory_maps(maps: &[crate::MemoryMap]) -> Self {
        let mut regions: Vec<MemoryRegion> = maps
            .iter()
            .map(|m| MemoryRegion {
                start: m.base.as_u64(),
                end: m.base.as_u64().saturating_add(m.size),
                prot: Protection {
                    readable: m.readable,
                    writable: m.writable,
                    executable: m.executable,
                    mapping: MappingFlags { copy_on_write: false },
                },
                kind: Self::classify(m),
                aslr_offset: 0,
                // Unknown until somebody measures it. Left `None` rather than
                // zeroed, which is the distinction iteration 418 exists for.
                rss: None,
                is_guard: false,
            })
            .collect();
        regions.sort_by_key(|r| r.start);
        Self { regions }
    }

    /// The whole thing, from a live target: mappings AND resident bytes.
    ///
    /// The missing consumer. Three per-OS fillers existed and nothing called any
    /// of them, so a caller holding a `Debugger` still had no way to obtain a
    /// measured view — the capability was present and unreachable, which is the
    /// same shape as the builder gap iteration 419 closed one level down.
    ///
    /// RSS is best-effort and deliberately so: the mappings are the answer the
    /// caller asked for, and a residency query that fails (the target exited
    /// between the two calls, or this user may not inspect it) must not throw the
    /// address space away. Unmeasured regions keep `rss: None`, which
    /// [`Self::measured_rss`] reports as "unknown" rather than as zero.
    ///
    /// On macOS the residency comes from a Mach task port, which only
    /// `MacosDebugger` holds: that caller should follow this with
    /// `resident_bytes()` and [`Self::fill_rss_from_pairs`]. Saying so here beats
    /// silently returning an unmeasured view on one OS out of three.
    ///
    /// # Errors
    /// Whatever `memory_maps()` reports. A view with no mappings is useless, so
    /// that failure IS an error, unlike the residency one.
    pub async fn of_target(dbg: &dyn crate::Debugger) -> Result<Self, crate::DebugError> {
        let maps = dbg.memory_maps().await?;
        let mut view = Self::from_memory_maps(&maps);
        if let Some(pid) = dbg.target_pid() {
            view.measure_rss(pid.0);
        }
        Ok(view)
    }

    /// Measure resident bytes with whichever mechanism this OS provides.
    ///
    /// Best-effort by contract: every failure leaves the regions unmeasured
    /// rather than zeroed, and the caller can tell the difference through
    /// [`Self::measured_rss`].
    pub fn measure_rss(&mut self, pid: u32) {
        #[cfg(target_os = "linux")]
        {
            let _ = self.fill_rss_from_smaps(pid);
        }
        #[cfg(target_os = "windows")]
        {
            // A page-counting query costs one entry per page, so regions past
            // this stay unmeasured rather than estimated — see
            // `fill_rss_from_working_set`. 64 Ki pages is 256 MiB of a 4 KiB-page
            // region, which covers everything but the giant reservations a
            // runtime makes and never touches.
            const MAX_PAGES: usize = 64 * 1024;
            let _ = self.fill_rss_from_working_set(pid, MAX_PAGES);
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            // macOS needs the task port; see `of_target`.
            let _ = pid;
        }
    }

    /// Fill in RSS from `(region start, resident bytes)` pairs measured elsewhere.
    ///
    /// The platform-neutral door, and the one macOS needs: resident bytes there
    /// come from `vm_region_submap_info_64::pages_resident`, which the backend
    /// already retrieves while walking the address space — but the walk needs a
    /// Mach task port, which this view has no business holding. So the party
    /// that owns the port measures, and this one records.
    ///
    /// A pair for an address that is not a region START is IGNORED rather than
    /// invented into existence: the view describes the address space the caller
    /// built it from, and a figure that matches nothing in it is a mismatch
    /// between two snapshots, not a new mapping.
    pub fn fill_rss_from_pairs(&mut self, pairs: &[(u64, u64)]) {
        for &(start, resident) in pairs {
            if let Some(region) = self.regions.iter_mut().find(|r| r.start == start) {
                region.rss = Some(resident);
            }
        }
    }

    /// Fill in each region's RSS from `/proc/<pid>/smaps`.
    ///
    /// The kernel reports resident bytes PER MAPPING there, which is exactly the
    /// granularity this view wants — `/proc/<pid>/status`'s `VmRSS` is a single
    /// process-wide number and could not answer "which of these regions is
    /// actually resident".
    ///
    /// Best-effort per region: a mapping that appears in the view but not in
    /// `smaps` (the map list was taken a moment earlier, and mappings come and
    /// go) keeps `rss: None` rather than being recorded as zero — the difference
    /// between "not resident" and "not measured" is the whole point of the
    /// `Option`.
    ///
    /// # Errors
    /// Whatever reading `/proc/<pid>/smaps` reports. A process that has exited,
    /// or one this user may not inspect, is an error rather than a view full of
    /// zeroes.
    #[cfg(target_os = "linux")]
    pub fn fill_rss_from_smaps(&mut self, pid: u32) -> std::io::Result<()> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/smaps"))?;
        let mut current: Option<u64> = None;
        for line in text.lines() {
            // A header line starts a mapping: `<start>-<end> perms ...`.
            if let Some((range, _)) = line.split_once(' ')
                && let Some((start, _end)) = range.split_once('-')
                && let Ok(start) = u64::from_str_radix(start, 16)
            {
                current = Some(start);
                continue;
            }
            if let Some(rest) = line.strip_prefix("Rss:")
                && let Some(start) = current
            {
                // `Rss:  <n> kB` — kibibytes, per the proc(5) format.
                let kb: u64 = rest
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                if let Some(region) = self.regions.iter_mut().find(|r| r.start == start) {
                    region.rss = Some(kb * 1024);
                }
            }
        }
        Ok(())
    }

    /// Fill in each region's RSS from the process's working set.
    ///
    /// Windows has no per-mapping resident counter the way `smaps` does; the
    /// nearest truth is `QueryWorkingSetEx`, which answers PER PAGE whether that
    /// page is currently valid (resident). Resident bytes for a region are
    /// therefore counted, page by page, not read off a field.
    ///
    /// Regions above `max_pages` are left UNMEASURED rather than sampled and
    /// extrapolated. Extrapolation would produce a plausible number nobody
    /// measured, which is exactly what iteration 418 removed from this file; a
    /// bound on the work is worth an honest `None`.
    ///
    /// # Errors
    /// Whatever `OpenProcess` reports. A process that has exited, or one this
    /// user may not inspect, is an error rather than a view full of zeroes.
    #[cfg(target_os = "windows")]
    pub fn fill_rss_from_working_set(&mut self, pid: u32, max_pages: usize) -> std::io::Result<()> {
        use winapi::shared::minwindef::FALSE;
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::processthreadsapi::OpenProcess;
        use winapi::um::psapi::{PSAPI_WORKING_SET_EX_INFORMATION, QueryWorkingSetEx};
        use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

        const PAGE: u64 = 4096;

        let handle =
            unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        for region in &mut self.regions {
            let pages = usize::try_from(region.size() / PAGE).unwrap_or(usize::MAX);
            if pages == 0 || pages > max_pages {
                continue;
            }
            let mut info: Vec<PSAPI_WORKING_SET_EX_INFORMATION> =
                Vec::with_capacity(pages);
            for n in 0..pages {
                // SAFETY: the struct is plain data; every field is filled in
                // below or by the call itself.
                let mut entry: PSAPI_WORKING_SET_EX_INFORMATION =
                    unsafe { std::mem::zeroed() };
                entry.VirtualAddress = (region.start + n as u64 * PAGE) as *mut _;
                info.push(entry);
            }
            let bytes = std::mem::size_of::<PSAPI_WORKING_SET_EX_INFORMATION>() * pages;
            let ok = unsafe {
                QueryWorkingSetEx(
                    handle,
                    info.as_mut_ptr().cast(),
                    u32::try_from(bytes).unwrap_or(u32::MAX),
                )
            };
            if ok == FALSE {
                // Best-effort per region, exactly as the Linux filler is: a
                // mapping that went away between the map walk and this call
                // stays unmeasured instead of being recorded as zero.
                continue;
            }
            let resident = info.iter().filter(|e| e.VirtualAttributes.Valid() != 0).count();
            region.rss = Some(resident as u64 * PAGE);
        }
        unsafe {
            CloseHandle(handle);
        }
        Ok(())
    }

    /// Which kind of region a map describes.
    ///
    /// The `[heap]`/`[stack]` names are what the unixes report; a file-backed
    /// mapping is recognised by having a path, which is what every OS agrees on.
    fn classify(m: &crate::MemoryMap) -> RegionKind {
        match m.name.as_deref() {
            Some("[heap]") => RegionKind::Heap { allocator: "system".to_string() },
            Some("[stack]") => RegionKind::MainStack,
            Some("[vdso]" | "[vvar]") => RegionKind::Vdso,
            Some("[vsyscall]") => RegionKind::Kernel,
            _ => match m.file_path.as_deref() {
                Some(path) => {
                    RegionKind::FileBacked { path: path.to_string(), offset: m.file_offset }
                }
                None => RegionKind::Anonymous,
            },
        }
    }

    /// Find the region that contains `addr`.
    ///
    /// The fast path is a binary search, which is only valid while `regions` is
    /// sorted by start address. That ordering is documented on the field and
    /// enforced by nothing: `regions` is `pub`, so any caller may push in the
    /// order the OS handed the mappings over. When the ordering does not hold,
    /// the binary search lands on the wrong slot and `find` answers `None` for
    /// an address that IS mapped — a wrong answer about the target's memory,
    /// returned with no indication that anything was off.
    ///
    /// So a miss is confirmed by a linear scan before it is reported. Cost: the
    /// common case (hit) stays `O(log n)`, and only a genuine miss pays `O(n)`.
    #[must_use]
    pub fn find(&self, addr: u64) -> Option<&MemoryRegion> {
        let idx = self.regions.partition_point(|r| r.end <= addr);
        if let Some(r) = self.regions.get(idx).filter(|r| r.contains(addr)) {
            return Some(r);
        }
        self.regions.iter().find(|r| r.contains(addr))
    }

    /// Return all regions whose kind matches a heap.
    #[must_use]
    pub fn heap_regions(&self) -> Vec<&MemoryRegion> {
        self.regions.iter().filter(|r| matches!(r.kind, RegionKind::Heap { .. })).collect()
    }

    /// Return all guard pages.
    #[must_use]
    pub fn guard_pages(&self) -> Vec<&MemoryRegion> {
        self.regions.iter().filter(|r| r.is_guard).collect()
    }

    /// Return all executable regions.
    #[must_use]
    pub fn executable_regions(&self) -> Vec<&MemoryRegion> {
        self.regions.iter().filter(|r| r.prot.executable).collect()
    }

    /// Detect guard pages: regions with no permissions (`PROT_NONE`) adjacent to
    /// another region.
    pub fn mark_guard_pages(&mut self) {
        for region in &mut self.regions {
            if !region.prot.readable && !region.prot.writable && !region.prot.executable {
                region.is_guard = true;
                region.kind = RegionKind::Guard;
            }
        }
    }

    /// Calculate ASLR offset for a module at `load_address` with preferred base
    /// `preferred_base`.
    #[must_use]
    pub const fn aslr_offset(load_address: u64, preferred_base: u64) -> i64 {
        load_address.cast_signed() - preferred_base.cast_signed()
    }

    /// Annotate regions with ASLR offsets given a map of `module_path →
    /// preferred_base`.
    pub fn annotate_aslr(&mut self, preferred_bases: &HashMap<String, u64>) {
        for region in &mut self.regions {
            if let RegionKind::FileBacked { path, .. } = &region.kind && let Some(&preferred) = preferred_bases.get(path.as_str()) {
                region.aslr_offset = Self::aslr_offset(region.start, preferred);
            }
        }
    }

    /// Total mapped virtual memory in bytes.
    #[must_use]
    pub fn total_virtual(&self) -> u64 {
        self.regions.iter().map(MemoryRegion::size).sum()
    }

    /// Total RSS in bytes (only from regions where RSS is known).
    ///
    /// Zero means BOTH "nothing is resident" and "nobody measured", which is why
    /// [`Self::measured_rss`] exists and is what the display uses.
    #[must_use]
    pub fn total_rss(&self) -> u64 {
        self.regions.iter().filter_map(|r| r.rss).sum()
    }

    /// Total RSS, or `None` when no region carries a measurement.
    ///
    /// `MemoryRegion::rss` is an `Option` precisely because the figure is not
    /// always available, and no caller in this crate fills it today — so
    /// [`Self::total_rss`] answered `0` for every view ever built, and the
    /// display printed "0 B RSS" as if the process were entirely non-resident.
    /// A fabricated measurement is worse than an absent one: a reader acts on
    /// the number, and this one said the process occupies no physical memory at
    /// all.
    ///
    /// PARTIAL data is still data: if some regions carry a figure and others do
    /// not, the sum of the known ones is returned. That is the honest reading of
    /// `filter_map`, and it is why the emptiness test is "did anyone measure"
    /// rather than "is the sum zero" — a genuinely non-resident region measured
    /// as zero must not read as no data.
    #[must_use]
    pub fn measured_rss(&self) -> Option<u64> {
        self.regions
            .iter()
            .any(|r| r.rss.is_some())
            .then(|| self.total_rss())
    }
}

impl fmt::Display for MappedRegionView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for region in &self.regions {
            writeln!(f, "{region}")?;
        }
        match self.measured_rss() {
            Some(rss) => write!(
                f,
                "Total: {} virtual, {} RSS",
                humanize_size(self.total_virtual()),
                humanize_size(rss),
            ),
            // Say so, rather than print a zero nobody measured.
            None => write!(
                f,
                "Total: {} virtual, RSS unknown",
                humanize_size(self.total_virtual()),
            ),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HeapAllocator — which allocator produced a chunk
// ─────────────────────────────────────────────────────────────────────────────

/// Supported heap allocators for chunk-level introspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HeapAllocator {
    /// glibc ptmalloc2 (Linux default).
    GlibcPtmalloc2,
    /// jemalloc (used by Firefox, Rust's default on some platforms).
    Jemalloc,
    /// tcmalloc (Google's Thread-Caching Malloc).
    Tcmalloc,
    /// Windows process heap (`RtlHeap` / NT Heap).
    WindowsNtHeap,
    /// Windows segment heap (Windows 10+).
    WindowsSegmentHeap,
}

impl fmt::Display for HeapAllocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GlibcPtmalloc2 => write!(f, "ptmalloc2"),
            Self::Jemalloc => write!(f, "jemalloc"),
            Self::Tcmalloc => write!(f, "tcmalloc"),
            Self::WindowsNtHeap => write!(f, "nt-heap"),
            Self::WindowsSegmentHeap => write!(f, "segment-heap"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HeapChunk — a single allocation chunk
// ─────────────────────────────────────────────────────────────────────────────

/// The state of a heap chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChunkState {
    Allocated,
    Free,
    /// Partially freed or in a free-list but not yet returned to OS.
    Pending,
    /// Chunk whose header appears corrupted.
    Corrupted,
}

impl fmt::Display for ChunkState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allocated => write!(f, "alloc"),
            Self::Free => write!(f, "free"),
            Self::Pending => write!(f, "pending"),
            Self::Corrupted => write!(f, "CORRUPTED"),
        }
    }
}

/// A single heap chunk as seen by the allocator layout parser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeapChunk {
    /// Address of the chunk header (not the user data pointer).
    pub header_addr: u64,
    /// Address of the user data portion (`header_addr` + `header_size`).
    pub user_addr: u64,
    /// Total chunk size including header and padding, in bytes.
    pub chunk_size: u64,
    /// Requested user size (may be less than `chunk_size - header_size`).
    pub user_size: u64,
    /// Allocation state.
    pub state: ChunkState,
    /// Allocator-specific flags (e.g. ptmalloc2 `prev_inuse` / `IS_MMAPPED`).
    pub flags: u32,
    /// Which allocator this chunk belongs to.
    pub allocator: HeapAllocator,
    /// For free chunks: address of the next chunk in the free list.
    pub next_free: Option<u64>,
    /// For free chunks: address of the previous chunk in the free list.
    pub prev_free: Option<u64>,
}

impl HeapChunk {
    /// Padding bytes between user allocation and next chunk header.
    #[must_use]
    pub const fn padding(&self) -> u64 {
        let header_size = self.user_addr - self.header_addr;
        self.chunk_size.saturating_sub(header_size + self.user_size)
    }

    /// Whether this chunk appears to have a corrupted header.
    #[must_use]
    pub fn is_corrupted(&self) -> bool {
        self.state == ChunkState::Corrupted
    }
}

impl fmt::Display for HeapChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} chunk@{:#x} user={:#x} size={} user_size={} flags={:#x}",
            self.state,
            self.header_addr,
            self.user_addr,
            self.chunk_size,
            self.user_size,
            self.flags,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Ptmalloc2Parser — glibc malloc_chunk header parser
// ─────────────────────────────────────────────────────────────────────────────

/// Parses glibc ptmalloc2 `malloc_chunk` structures.
///
/// ```c
/// struct malloc_chunk {
///   size_t prev_size;   // size of previous chunk if free
///   size_t size;        // size of this chunk + status flags in low bits
///   struct malloc_chunk *fd;   // next chunk in free list (if free)
///   struct malloc_chunk *bk;   // prev chunk in free list (if free)
/// };
/// ```
/// Flags in `size` low bits:
/// - bit 0 : `PREV_INUSE`
/// - bit 1 : `IS_MMAPPED`
/// - bit 2 : `NON_MAIN_ARENA`
pub struct Ptmalloc2Parser {
    /// Whether the target is 64-bit (word size 8) or 32-bit (word size 4).
    pub word_size: u8,
}

impl Ptmalloc2Parser {
    pub const PREV_INUSE: u64 = 1;
    pub const IS_MMAPPED: u64 = 2;
    pub const NON_MAIN_ARENA: u64 = 4;

    #[must_use]
    pub const fn new(word_size: u8) -> Self {
        Self { word_size }
    }

    /// Header size: 2 × `word_size` (`prev_size` + size fields).
    #[must_use]
    pub const fn header_size(&self) -> u64 {
        2 * u64::from_le_bytes([self.word_size, 0, 0, 0, 0, 0, 0, 0])
    }

    /// Parse a chunk from a raw byte buffer starting at the chunk header.
    ///
    /// `chunk_addr` is the address of the first byte of the buffer in the
    /// target's address space.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the buffer is too small or the header is invalid.
    pub fn parse_chunk(
        &self,
        chunk_addr: u64,
        data: &[u8],
    ) -> Result<HeapChunk, MemoryLayoutError> {
        let ws = self.word_size as usize;
        if data.len() < ws * 4 {
            return Err(MemoryLayoutError::InvalidHeapHeader(chunk_addr));
        }
        let _prev_size = self.read_word(data, 0);
        let size_with_flags = self.read_word(data, ws);
        let flags = (size_with_flags & 0x7) as u32;
        let chunk_size = size_with_flags & !0x7;

        if chunk_size == 0 || chunk_size > (1u64 << 40) {
            return Err(MemoryLayoutError::InvalidHeapHeader(chunk_addr));
        }

        let prev_inuse = (size_with_flags & Self::PREV_INUSE) != 0;
        let user_addr = chunk_addr + self.header_size();

        // fd / bk only meaningful for free chunks.
        let fd = self.read_word(data, ws * 2);
        let bk = self.read_word(data, ws * 3);

        let state = if prev_inuse {
            ChunkState::Allocated
        } else {
            ChunkState::Free
        };

        let (next_free, prev_free) = if state == ChunkState::Free {
            (Some(fd), Some(bk))
        } else {
            (None, None)
        };

        Ok(HeapChunk {
            header_addr: chunk_addr,
            user_addr,
            chunk_size,
            user_size: chunk_size.saturating_sub(self.header_size()),
            state,
            flags,
            allocator: HeapAllocator::GlibcPtmalloc2,
            next_free,
            prev_free,
        })
    }

    fn read_word(&self, data: &[u8], offset: usize) -> u64 {
        match self.word_size {
            8 => {
                let b: [u8; 8] = data[offset..offset + 8].try_into().unwrap_or([0; 8]);
                u64::from_le_bytes(b)
            }
            4 => {
                let b: [u8; 4] = data[offset..offset + 4].try_into().unwrap_or([0; 4]);
                u64::from(u32::from_le_bytes(b))
            }
            _ => 0,
        }
    }

    /// Walk a heap arena starting at `arena_start`, reading chunks from the
    /// `reader` closure until the top chunk is reached or an error occurs.
    ///
    /// `reader(addr, size) -> Result<Vec<u8>>` must return `size` bytes from
    /// `addr` in the target's memory.
    ///
    /// # Errors
    ///
    /// Returns `Err` if reading memory fails or a chunk header is invalid.
    pub fn walk_arena<R>(
        &self,
        arena_start: u64,
        mut reader: R,
    ) -> Result<Vec<HeapChunk>, MemoryLayoutError>
    where
        R: FnMut(u64, usize) -> Result<Vec<u8>, MemoryLayoutError>,
    {
        let mut chunks = Vec::new();
        let mut addr = arena_start;
        let max_iterations = 100_000usize;

        for _ in 0..max_iterations {
            let data = reader(addr, self.word_size as usize * 4)?;
            let chunk = self.parse_chunk(addr, &data)?;
            let size = chunk.chunk_size;

            // Stop at the "top" chunk (conventionally: size of 0 or very large).
            if size == 0 {
                break;
            }

            let next_addr = addr.wrapping_add(size);
            let is_last = chunk.flags & 0x2 != 0; // IS_MMAPPED heuristic
            chunks.push(chunk);

            if is_last || next_addr <= addr {
                break;
            }
            addr = next_addr;
        }

        Ok(chunks)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HeapLayout — the result of a heap analysis pass
// ─────────────────────────────────────────────────────────────────────────────

/// Complete heap layout snapshot for a process.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct HeapLayout {
    /// All chunks found, sorted by header address.
    pub chunks: Vec<HeapChunk>,
    /// Detected allocator.
    pub allocator: Option<HeapAllocator>,
    /// Number of allocated chunks.
    pub allocated_count: usize,
    /// Number of free chunks.
    pub free_count: usize,
    /// Total bytes in allocated chunks (`user_size` sum).
    pub total_allocated_bytes: u64,
    /// Total bytes in free chunks.
    pub total_free_bytes: u64,
    /// Any detected corrupted chunks.
    pub corrupted_chunks: Vec<u64>,
}

impl HeapLayout {
    /// Build a `HeapLayout` summary from a flat list of chunks.
    #[must_use]
    pub fn from_chunks(chunks: Vec<HeapChunk>) -> Self {
        let mut layout = Self::default();
        if let Some(first) = chunks.first() {
            layout.allocator = Some(first.allocator);
        }
        for chunk in &chunks {
            match chunk.state {
                ChunkState::Allocated => {
                    layout.allocated_count += 1;
                    layout.total_allocated_bytes += chunk.user_size;
                }
                ChunkState::Free | ChunkState::Pending => {
                    layout.free_count += 1;
                    layout.total_free_bytes += chunk.user_size;
                }
                ChunkState::Corrupted => {
                    layout.corrupted_chunks.push(chunk.header_addr);
                }
            }
        }
        layout.chunks = chunks;
        layout
    }

    /// Detect heap-level corruption patterns.
    #[must_use]
    pub fn detect_corruption(&self) -> Vec<String> {
        let mut issues = Vec::new();
        for chunk in &self.chunks {
            if chunk.is_corrupted() {
                issues.push(format!("Corrupted chunk header at {:#x}", chunk.header_addr));
            }
            // Double-free heuristic: free chunk with both fd and bk pointing to itself.
            if let (Some(fd), Some(bk)) = (chunk.next_free, chunk.prev_free) && (fd == chunk.header_addr || bk == chunk.header_addr) {
                issues.push(format!("Possible double-free at {:#x}", chunk.header_addr));
            }
        }
        issues
    }
}

impl fmt::Display for HeapLayout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "HeapLayout: {} alloc ({} bytes) / {} free ({} bytes), {} corrupted",
            self.allocated_count,
            self.total_allocated_bytes,
            self.free_count,
            self.total_free_bytes,
            self.corrupted_chunks.len(),
        )?;
        for chunk in self.chunks.iter().take(50) {
            writeln!(f, "  {chunk}")?;
        }
        if self.chunks.len() > 50 {
            writeln!(f, "  … {} more chunks", self.chunks.len() - 50)?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LiveStackUnwinder — unwind stack frames from a live process
// ─────────────────────────────────────────────────────────────────────────────

/// A single unwound stack frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveStackFrame {
    /// Frame index (0 = innermost / current frame).
    pub index: usize,
    /// Return address (or instruction pointer for frame 0).
    pub pc: u64,
    /// Stack pointer at this frame.
    pub sp: u64,
    /// Frame pointer at this frame (if available).
    pub fp: Option<u64>,
    /// Guessed function start address (heuristic).
    pub func_start: Option<u64>,
    /// Which region the PC falls in.
    pub region: Option<String>,
}

impl fmt::Display for LiveStackFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "#{:<3} pc={:#018x} sp={:#018x}{}{}",
            self.index,
            self.pc,
            self.sp,
            self.fp.map_or(String::new(), |fp| format!(" fp={fp:#018x}")),
            self.region.as_deref().map_or(String::new(), |r| format!(" in {r}")),
        )
    }
}

/// Unwinds a live stack via frame-pointer chain (RBP chain on x86-64).
///
/// For a more accurate result in production use DWARF CFI or .pdata (Windows);
/// this implementation uses the simple frame-pointer heuristic which works for
/// code compiled with `-fno-omit-frame-pointer`.
pub struct FramePointerUnwinder {
    /// Maximum number of frames to unwind.
    pub max_frames: usize,
}

impl FramePointerUnwinder {
    #[must_use]
    pub const fn new(max_frames: usize) -> Self {
        Self { max_frames }
    }

    /// Unwind the stack given a `reader` closure and the initial register values.
    ///
    /// `reader(addr, size) -> Option<Vec<u8>>` reads from the target's memory.
    pub fn unwind<R>(
        &self,
        pc: u64,
        sp: u64,
        fp: Option<u64>,
        regions: &MappedRegionView,
        mut reader: R,
    ) -> Vec<LiveStackFrame>
    where
        R: FnMut(u64, usize) -> Option<Vec<u8>>,
    {
        let mut frames = Vec::new();
        let mut current_pc = pc;
        let mut current_sp = sp;
        let mut active_fp = fp;

        for index in 0..self.max_frames {
            let region_name = regions.find(current_pc).map(|r| r.kind.to_string());

            frames.push(LiveStackFrame {
                index,
                pc: current_pc,
                sp: current_sp,
                fp: active_fp,
                func_start: None,
                region: region_name,
            });

            // Follow the frame pointer chain: [rbp] = saved_rbp, [rbp+8] = return_addr.
            let fp_addr = match active_fp {
                Some(f) if f != 0 => f,
                _ => break,
            };

            let saved_fp = match reader(fp_addr, 8) {
                Some(data) if data.len() >= 8 => {
                    let b: [u8; 8] = data[..8].try_into().unwrap_or([0; 8]);
                    u64::from_le_bytes(b)
                }
                _ => break,
            };
            // `fp_addr` comes out of the debuggee's memory, so it can be any
            // value. `fp_addr + 8` wraps for an address near `u64::MAX`: the
            // read then lands on an unrelated low address and whatever is there
            // is accepted as a return address — a fabricated frame reported as
            // a real caller (and an outright panic in a debug build).
            let Some(ret_slot) = fp_addr.checked_add(8) else { break };
            let return_addr = match reader(ret_slot, 8) {
                Some(data) if data.len() >= 8 => {
                    let b: [u8; 8] = data[..8].try_into().unwrap_or([0; 8]);
                    u64::from_le_bytes(b)
                }
                _ => break,
            };

            if return_addr == 0 || saved_fp == 0 {
                break;
            }
            // A return address must point at CODE.
            //
            // `saved_fp`/`return_addr` come out of the debuggee's stack, so a
            // corrupt frame — or a function that keeps a data pointer in the
            // frame register, which is what `-fomit-frame-pointer` frees it to
            // do — hands back a "caller" somewhere in the heap or in a data
            // segment. The chain then keeps walking and the caller receives a
            // column of frames that look exactly like real ones: a backtrace is
            // read as a statement of fact, and nothing here marked the guess.
            //
            // The region view was already in this function, used only to NAME
            // frames. Same rule `run_to_return` follows in all three backends:
            // refuse a region the map says is not executable, and leave alone
            // one the map simply does not describe — `memory_maps` can miss
            // freshly mapped JIT code, and refusing what we merely cannot see
            // would truncate exactly the stacks that need this most.
            if regions.find(return_addr).is_some_and(|r| !r.prot.executable) {
                break;
            }
            // Sanity check: frame pointer should be above the previous one on
            // a downward-growing stack.
            if let Some(prev_fp) = active_fp && saved_fp <= prev_fp {
                break;
            }

            current_pc = return_addr;
            // Same reasoning as the read above: never let a debuggee-supplied
            // address wrap into a plausible-looking small one.
            let Some(next_sp) = fp_addr.checked_add(16) else { break };
            current_sp = next_sp; // just past saved_rbp + return_addr
            active_fp = Some(saved_fp);
        }

        frames
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryLayoutView — combined view of everything
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level runtime memory layout view combining the mapped regions, heap
/// layout, and live stack frames.
#[derive(Debug, Default)]
pub struct MemoryLayoutView {
    /// All mapped regions.
    pub regions: MappedRegionView,
    /// Heap layout (if analysed).
    pub heap: Option<HeapLayout>,
    /// Live stack frames (if unwound).
    pub stack_frames: Vec<LiveStackFrame>,
    /// ASLR offsets by module name.
    pub aslr_offsets: HashMap<String, i64>,
    /// Detected guard pages.
    pub guard_pages: Vec<u64>,
}

impl MemoryLayoutView {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach heap layout results.
    pub fn set_heap(&mut self, heap: HeapLayout) {
        self.heap = Some(heap);
    }

    /// Attach unwound stack frames.
    pub fn set_stack_frames(&mut self, frames: Vec<LiveStackFrame>) {
        self.stack_frames = frames;
    }

    /// Compute and store ASLR offsets for all file-backed regions.
    pub fn compute_aslr_offsets(&mut self, preferred_bases: &HashMap<String, u64>) {
        self.aslr_offsets.clear();
        for region in &self.regions.regions {
            if let RegionKind::FileBacked { path, .. } = &region.kind && let Some(&preferred) = preferred_bases.get(path.as_str()) {
                let offset = MappedRegionView::aslr_offset(region.start, preferred);
                self.aslr_offsets.insert(path.clone(), offset);
            }
        }
    }

    /// Scan for guard pages and record their start addresses.
    pub fn scan_guard_pages(&mut self) {
        self.regions.mark_guard_pages();
        self.guard_pages = self.regions.guard_pages().into_iter().map(|r| r.start).collect();
    }

    /// Return a summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        let guard_count = self.guard_pages.len();
        let heap_chunks = self.heap.as_ref().map_or(0, |h| h.chunks.len());
        let stack_depth = self.stack_frames.len();
        let region_count = self.regions.regions.len();
        format!("MemoryLayout: {region_count} regions | {heap_chunks} heap chunks | {stack_depth} stack frames | {guard_count} guard pages")
    }
}

impl fmt::Display for MemoryLayoutView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Memory Regions ===")?;
        write!(f, "{}", self.regions)?;
        writeln!(f)?;
        if let Some(heap) = &self.heap {
            writeln!(f, "\n=== Heap Layout ===")?;
            write!(f, "{heap}")?;
        }
        if !self.stack_frames.is_empty() {
            writeln!(f, "\n=== Stack Frames ===")?;
            for frame in &self.stack_frames {
                writeln!(f, "{frame}")?;
            }
        }
        if !self.guard_pages.is_empty() {
            writeln!(f, "\n=== Guard Pages ===")?;
            for &g in &self.guard_pages {
                writeln!(f, "  {g:#018x}")?;
            }
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Heap/memory chunk graph visualizer (Tier 1, item 4 of the enhancement plan)
// ─────────────────────────────────────────────────────────────────────────────
//
// Reuses the heap enumeration already produced by [`HeapLayout`]/[`HeapChunk`]
// (pwndbg/GEF `vis_heap_chunks`-style) to emit a plain, serializable graph:
// one node per chunk (state, size, allocator) and one edge per free-list
// link (`fd`/`bk`). No new memory parsing — this is a pure projection over
// data the ptmalloc2/jemalloc/tcmalloc/NT-heap parsers already produce, so it
// feeds any front-end (TUI/web) as JSON without touching the target process
// again.

/// One node in a [`HeapChunkGraph`]: a single chunk, projected for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeapGraphNode {
    /// Chunk header address — also this node's unique ID.
    pub id: u64,
    pub user_addr: u64,
    pub chunk_size: u64,
    pub user_size: u64,
    pub state: ChunkState,
    pub allocator: HeapAllocator,
    pub corrupted: bool,
}

/// Why two chunk nodes are connected in a [`HeapChunkGraph`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HeapGraphEdgeKind {
    /// `fd` (forward) free-list pointer: `from` is free, points to the next
    /// free chunk in its bin.
    FreeListForward,
    /// `bk` (backward) free-list pointer.
    FreeListBackward,
    /// The two chunks are physically adjacent in memory (`from`'s end ==
    /// `to`'s header address) — useful for spotting a corrupted `size` field
    /// that makes chunks overlap or leaves a gap.
    Adjacent,
}

/// One edge in a [`HeapChunkGraph`], connecting two chunk node IDs
/// (header addresses).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeapGraphEdge {
    pub from: u64,
    pub to: u64,
    pub kind: HeapGraphEdgeKind,
}

/// A graph view of a [`HeapLayout`]: chunk nodes plus free-list and
/// adjacency edges, ready to serialize to JSON for any visualizer front-end.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeapChunkGraph {
    pub nodes: Vec<HeapGraphNode>,
    pub edges: Vec<HeapGraphEdge>,
}

impl HeapChunkGraph {
    /// Build a graph from a [`HeapLayout`]'s chunks (already sorted by header
    /// address, per [`HeapLayout::chunks`]'s doc contract).
    #[must_use]
    pub fn from_layout(layout: &HeapLayout) -> Self {
        let mut nodes = Vec::with_capacity(layout.chunks.len());
        let mut edges = Vec::new();

        for chunk in &layout.chunks {
            nodes.push(HeapGraphNode {
                id: chunk.header_addr,
                user_addr: chunk.user_addr,
                chunk_size: chunk.chunk_size,
                user_size: chunk.user_size,
                state: chunk.state,
                allocator: chunk.allocator,
                corrupted: chunk.is_corrupted(),
            });
            if let Some(fd) = chunk.next_free {
                edges.push(HeapGraphEdge { from: chunk.header_addr, to: fd, kind: HeapGraphEdgeKind::FreeListForward });
            }
            if let Some(bk) = chunk.prev_free {
                edges.push(HeapGraphEdge { from: chunk.header_addr, to: bk, kind: HeapGraphEdgeKind::FreeListBackward });
            }
        }

        // Adjacency edges, over chunks put in address order HERE.
        //
        // `HeapLayout::chunks` documents that it is sorted by header address,
        // and `pub chunks` means nothing enforces it — the same exposure
        // `MappedRegionView::find` above already had to defend against, with
        // the same failure shape. Pairing `windows(2)` over an unsorted vector
        // compares chunks that are not neighbours, so the arithmetic almost
        // never matches and the adjacency edges are simply MISSING: the graph
        // then says two physically adjacent chunks are not adjacent, which is
        // the fact a reader consults this graph to learn (coalescing
        // opportunities, overflow from one chunk into the next).
        //
        // Sorting a local index list costs one `O(n log n)` pass on a builder
        // that already allocates a node and up to two edges per chunk, and it
        // removes the assumption instead of restating it.
        let mut ordered: Vec<&HeapChunk> = layout.chunks.iter().collect();
        ordered.sort_by_key(|c| c.header_addr);
        for pair in ordered.windows(2) {
            let [a, b] = pair else { continue };
            if a.header_addr.saturating_add(a.chunk_size) == b.header_addr {
                edges.push(HeapGraphEdge { from: a.header_addr, to: b.header_addr, kind: HeapGraphEdgeKind::Adjacent });
            }
        }

        Self { nodes, edges }
    }

    /// Serialize to a pretty-printed JSON string for consumption by any
    /// front-end (TUI/web) without further parsing work.
    ///
    /// # Errors
    /// Returns a [`serde_json::Error`] if serialization fails (should not
    /// happen for this plain-data type).
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// All node IDs (chunk header addresses) currently flagged corrupted.
    #[must_use]
    pub fn corrupted_node_ids(&self) -> Vec<u64> {
        self.nodes.iter().filter(|n| n.corrupted).map(|n| n.id).collect()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_region(start: u64, end: u64, r: bool, w: bool, x: bool) -> MemoryRegion {
        MemoryRegion {
            start,
            end,
            prot: Protection { readable: r, writable: w, executable: x, mapping: MappingFlags { copy_on_write: false } },
            kind: RegionKind::Anonymous,
            aslr_offset: 0,
            is_guard: false,
            rss: None,
        }
    }

    fn map(base: u64, size: u64, name: Option<&str>, path: Option<&str>) -> crate::MemoryMap {
        crate::MemoryMap {
            base: rustre_core::address::Address::new(base),
            size,
            readable: true,
            writable: true,
            executable: false,
            name: name.map(ToString::to_string),
            file_path: path.map(ToString::to_string),
            file_offset: 0,
        }
    }

    /// The view must be buildable from what the debugger already reports.
    ///
    /// Until this existed, every `MemoryRegion` in the crate was built by a test:
    /// the guard-page scan, the ASLR offsets and the RSS totals were all
    /// unreachable from a live target, which is also why nobody had ever noticed
    /// the RSS was never measured.
    #[test]
    fn a_view_can_be_built_from_the_debuggers_own_memory_maps() {
        // Deliberately NOT in address order: `find` binary-searches, so the
        // builder must sort or it answers `None` for an address that is mapped.
        let maps = vec![
            map(0x4000, 0x1000, Some("[heap]"), None),
            map(0x1000, 0x1000, Some("libc.so"), Some("/usr/lib/libc.so")),
            map(0x8000, 0x1000, None, None),
        ];
        let view = MappedRegionView::from_memory_maps(&maps);

        assert_eq!(view.regions.len(), 3);
        assert!(
            view.find(0x4500).is_some(),
            "a mapped address was reported unmapped: the builder handed the regions over unsorted"
        );
        assert!(matches!(view.regions[0].kind, RegionKind::FileBacked { .. }));
        assert!(matches!(view.regions[1].kind, RegionKind::Heap { .. }));
        assert!(matches!(view.regions[2].kind, RegionKind::Anonymous));
        assert_eq!(
            view.measured_rss(),
            None,
            "a freshly built view has measured nothing, and must say so rather than report zero"
        );
    }

    /// Pairs measured elsewhere must be recorded — and only where they belong.
    ///
    /// The platform-neutral door, and the one macOS uses: resident bytes there
    /// come from `vm_region_submap_info_64::pages_resident`, which the backend
    /// already reads while walking the address space — but the walk needs a Mach
    /// task port, which this view has no business holding. So the party with the
    /// port measures and this one records.
    ///
    /// A pair whose address is not a region START must be IGNORED, not invented
    /// into a new region: two snapshots taken a moment apart disagree all the
    /// time, and a view that grows mappings from a residency report would be
    /// describing an address space nobody observed.
    #[test]
    fn rss_pairs_are_recorded_only_against_regions_that_exist() {
        let maps = vec![map(0x1000, 0x1000, None, None), map(0x3000, 0x1000, None, None)];
        let mut view = MappedRegionView::from_memory_maps(&maps);

        view.fill_rss_from_pairs(&[
            (0x1000, 4096),
            // Mid-region, not a start: a stale or shifted snapshot.
            (0x3800, 4096),
            // A mapping that is not in this view at all.
            (0x9000, 8192),
        ]);

        assert_eq!(view.regions.len(), 2, "a residency report must not create mappings");
        assert_eq!(view.regions[0].rss, Some(4096));
        assert_eq!(
            view.regions[1].rss, None,
            "a pair that does not name a region start was applied anyway"
        );
        assert_eq!(
            view.measured_rss(),
            Some(4096),
            "the total must count what was measured and nothing else"
        );
    }

    /// And on Windows too — measured against this very process.
    ///
    /// There is no per-mapping resident counter here the way `smaps` provides,
    /// so `QueryWorkingSetEx` is asked page by page whether each page is valid,
    /// and the resident bytes are COUNTED. A running test process necessarily
    /// has resident pages, so a total of zero would mean the query matched
    /// nothing.
    ///
    /// The region walked is one this test allocates and then TOUCHES, so its
    /// residency is not a matter of luck: an untouched reservation is legitimately
    /// non-resident, and a test built on one would be measuring the weather.
    #[cfg(target_os = "windows")]
    #[test]
    fn rss_is_measured_from_the_working_set_on_windows() {
        // Four pages, written to, so they are certainly resident.
        let mut owned = vec![0u8; 4 * 4096];
        for (n, b) in owned.iter_mut().enumerate() {
            *b = (n % 251) as u8;
        }
        let base = owned.as_ptr() as u64;
        // Page-align downwards: the allocation may start mid-page, and a query
        // for a page that is only partly ours is still a query for a resident
        // page of this process.
        let start = base & !0xFFF;

        let maps = vec![map(start, 4 * 4096, None, None)];
        let mut view = MappedRegionView::from_memory_maps(&maps);
        assert_eq!(view.measured_rss(), None, "nothing is measured before the fill");

        view.fill_rss_from_working_set(std::process::id(), 1024)
            .expect("querying our own working set must succeed");

        let rss = view.measured_rss().expect("the working set carries a figure for this region");
        assert!(
            rss > 0,
            "pages this process just wrote to were reported as non-resident: the query matched nothing"
        );
        assert!(
            rss <= view.total_virtual(),
            "resident memory ({rss}) cannot exceed the virtual size ({})",
            view.total_virtual()
        );
        // Keep the buffer alive to here, so the pages cannot be reclaimed
        // between the write and the query.
        assert_eq!(owned.len(), 4 * 4096);
    }

    /// A region too big to measure exactly stays UNMEASURED.
    ///
    /// Counting pages costs one entry per page, so the walk is bounded. The
    /// bound must produce an honest `None`, never a sampled-and-extrapolated
    /// number: a plausible figure nobody measured is the defect iteration 418
    /// removed from this file, and re-introducing it through a performance
    /// shortcut would be the same lie by another door.
    #[cfg(target_os = "windows")]
    #[test]
    fn a_region_beyond_the_page_budget_is_left_unmeasured() {
        let mut owned = vec![0u8; 4 * 4096];
        owned[0] = 1;
        let start = (owned.as_ptr() as u64) & !0xFFF;

        let maps = vec![map(start, 4 * 4096, None, None)];
        let mut view = MappedRegionView::from_memory_maps(&maps);
        // A budget of two pages cannot measure a four-page region.
        view.fill_rss_from_working_set(std::process::id(), 2).expect("query");
        assert_eq!(
            view.measured_rss(),
            None,
            "a region past the budget was given a figure anyway — that number was estimated, not measured"
        );
    }

    /// And on Linux the RSS can actually be measured — against this very process.
    ///
    /// `/proc/self/smaps` reports resident bytes PER MAPPING, which is the
    /// granularity this view wants; `VmRSS` is one process-wide number and could
    /// not answer "which of these regions is resident". A running test process
    /// necessarily has some resident memory, so a total of zero here would mean
    /// the parse found nothing.
    #[cfg(target_os = "linux")]
    #[test]
    fn rss_is_measured_from_smaps_on_linux() {
        // Build the view straight from this process's own mappings.
        let text = std::fs::read_to_string("/proc/self/maps").expect("read own maps");
        let mut maps = Vec::new();
        for line in text.lines() {
            let Some((range, _)) = line.split_once(' ') else { continue };
            let Some((start, end)) = range.split_once('-') else { continue };
            let (Ok(start), Ok(end)) =
                (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
            else {
                continue;
            };
            maps.push(map(start, end - start, None, None));
        }
        assert!(!maps.is_empty(), "this process must have mappings");

        let mut view = MappedRegionView::from_memory_maps(&maps);
        assert_eq!(view.measured_rss(), None, "nothing is measured before the fill");
        view.fill_rss_from_smaps(std::process::id()).expect("read own smaps");

        let rss = view.measured_rss().expect("smaps carries a figure for at least one mapping");
        assert!(
            rss > 0,
            "a running process reported zero resident bytes across every mapping: the parse matched nothing"
        );
        assert!(
            rss <= view.total_virtual(),
            "resident memory ({rss}) cannot exceed the virtual size ({})",
            view.total_virtual()
        );
    }

    /// An RSS nobody measured must READ as unmeasured, not as zero.
    ///
    /// `MemoryRegion::rss` is an `Option` because the figure is often
    /// unavailable, and nothing in this crate fills it today. `total_rss()`
    /// therefore summed an empty set and the display printed "0 B RSS" for every
    /// view ever built — telling the reader the process occupies no physical
    /// memory at all. A fabricated measurement is worse than an absent one
    /// because it is acted upon.
    ///
    /// The distinction that matters, and the reason the test carries three
    /// cases: a region genuinely measured at zero is DATA and must still print a
    /// number.
    #[test]
    fn an_unmeasured_rss_is_reported_as_unknown_not_as_zero() {
        let mut view = MappedRegionView::default();
        view.regions.push(make_region(0x1000, 0x2000, true, true, false));
        assert_eq!(view.measured_rss(), None, "nothing carries a figure, so there is nothing to total");
        let shown = view.to_string();
        assert!(
            shown.contains("RSS unknown"),
            "the view printed a resident-set size nobody measured: {shown}"
        );

        // A measured ZERO is data, and must print as a number.
        let mut measured_zero = MappedRegionView::default();
        let mut region = make_region(0x1000, 0x2000, true, true, false);
        region.rss = Some(0);
        measured_zero.regions.push(region);
        assert_eq!(measured_zero.measured_rss(), Some(0));
        assert!(
            measured_zero.to_string().contains("0B RSS"),
            "a region measured at zero must still report a number: {}",
            measured_zero.to_string()
        );

        // Partial data is data: the known regions are summed.
        let mut partial = MappedRegionView::default();
        let mut known = make_region(0x1000, 0x2000, true, true, false);
        known.rss = Some(4096);
        partial.regions.push(known);
        partial.regions.push(make_region(0x3000, 0x4000, true, false, false));
        assert_eq!(
            partial.measured_rss(),
            Some(4096),
            "a view where only some regions were measured must report what is known"
        );
    }

    /// `find` must answer correctly whatever order the regions were pushed in.
    ///
    /// `regions` is a `pub` field whose ordering is stated in a doc comment and
    /// enforced by nothing, so a caller that pushes the mappings in the order
    /// the OS reported them is doing something the API allows. The binary search
    /// then landed on the wrong slot and reported `None` for an address that is
    /// mapped — a wrong answer about the target's memory, with nothing to
    /// suggest the answer was unreliable.
    #[test]
    fn find_is_correct_even_when_regions_were_pushed_out_of_order() {
        let mut view = MappedRegionView::default();
        // Descending on purpose: allowed by the API, fatal to a bare binary
        // search.
        view.regions.push(make_region(0x3000, 0x4000, true, false, false));
        view.regions.push(make_region(0x1000, 0x2000, true, false, false));

        assert!(
            view.find(0x1500).is_some(),
            "an address inside a mapped region was reported as unmapped"
        );
        assert!(view.find(0x3500).is_some());
        // A genuinely unmapped address must still be reported as such.
        assert!(view.find(0x2500).is_none(), "the gap must stay a gap");
    }

    #[test]
    fn test_find_region() {
        let mut view = MappedRegionView::default();
        view.regions.push(make_region(0x1000, 0x2000, true, false, false));
        view.regions.push(make_region(0x2000, 0x3000, true, true, false));

        assert!(view.find(0x1000).is_some());
        assert!(view.find(0x1fff).is_some());
        assert!(view.find(0x2000).is_some());
        assert!(view.find(0x3000).is_none());
    }

    #[test]
    fn test_guard_page_detection() {
        let mut view = MappedRegionView::default();
        view.regions.push(make_region(0x7fff_0000, 0x7fff_1000, false, false, false));
        view.mark_guard_pages();
        assert!(view.regions[0].is_guard);
        assert_eq!(view.guard_pages().len(), 1);
    }

    #[test]
    fn test_aslr_offset() {
        let offset = MappedRegionView::aslr_offset(0x7f00_0000, 0x0040_0000);
        assert_eq!(offset, 0x7f00_0000_i64 - 0x0040_0000_i64);
    }

    #[test]
    fn test_ptmalloc2_parse_allocated() {
        let parser = Ptmalloc2Parser::new(8);
        // Construct a fake allocated chunk: prev_size=0, size=0x21 (PREV_INUSE set)
        let mut data = vec![0u8; 64];
        let size_with_flags: u64 = 0x21; // chunk_size=0x20, PREV_INUSE bit set
        data[8..16].copy_from_slice(&size_with_flags.to_le_bytes());
        let chunk = parser.parse_chunk(0x1000, &data).unwrap();
        assert_eq!(chunk.state, ChunkState::Allocated);
        assert_eq!(chunk.chunk_size, 0x20);
        assert_eq!(chunk.user_addr, 0x1010);
    }

    #[test]
    fn test_ptmalloc2_parse_free() {
        let parser = Ptmalloc2Parser::new(8);
        let mut data = vec![0u8; 64];
        let size_with_flags: u64 = 0x20; // PREV_INUSE = 0 → free
        data[8..16].copy_from_slice(&size_with_flags.to_le_bytes());
        let fd: u64 = 0x2000;
        let bk: u64 = 0x3000;
        data[16..24].copy_from_slice(&fd.to_le_bytes());
        data[24..32].copy_from_slice(&bk.to_le_bytes());
        let chunk = parser.parse_chunk(0x1000, &data).unwrap();
        assert_eq!(chunk.state, ChunkState::Free);
        assert_eq!(chunk.next_free, Some(0x2000));
        assert_eq!(chunk.prev_free, Some(0x3000));
    }

    #[test]
    fn test_heap_layout_summary() {
        let chunks = vec![
            HeapChunk {
                header_addr: 0x1000, user_addr: 0x1010, chunk_size: 0x20,
                user_size: 0x10, state: ChunkState::Allocated, flags: 1,
                allocator: HeapAllocator::GlibcPtmalloc2, next_free: None, prev_free: None,
            },
            HeapChunk {
                header_addr: 0x1020, user_addr: 0x1030, chunk_size: 0x30,
                user_size: 0x20, state: ChunkState::Free, flags: 0,
                allocator: HeapAllocator::GlibcPtmalloc2, next_free: Some(0), prev_free: Some(0),
            },
        ];
        let layout = HeapLayout::from_chunks(chunks);
        assert_eq!(layout.allocated_count, 1);
        assert_eq!(layout.free_count, 1);
        assert_eq!(layout.total_allocated_bytes, 0x10);
    }

    /// A frame pointer near the top of memory must stop the walk, not wrap.
    ///
    /// This is the unwinder all three OS backends fall back to. It read the
    /// return address at `fp_addr + 8` and set `sp = fp_addr + 16` with plain
    /// additions, on a value taken straight out of the debuggee's memory. For
    /// an `fp` close to `u64::MAX` those wrap: the read lands on a completely
    /// different, low address, and whatever happens to live there is accepted
    /// as a return address. The result is a fabricated frame presented as a
    /// real caller — and in a debug build the addition panics outright.
    ///
    /// The twin in `lib.rs` had the same class of defect (iter 336) and panicked
    /// on a slice instead; this one stays quiet and lies.
    #[test]
    fn a_frame_pointer_near_the_top_of_memory_stops_instead_of_wrapping() {
        let unwinder = FramePointerUnwinder::new(16);
        let regions = MappedRegionView::default();

        // A reader that succeeds for EVERY address: it models a target whose
        // memory happens to be readable wherever a wrapped address lands, so
        // the only thing that can stop the walk is the unwinder's own arithmetic.
        let mut asked: Vec<u64> = Vec::new();
        let frames = unwinder.unwind(
            0x0040_1000,
            0x7fff_0000,
            Some(u64::MAX - 3),
            &regions,
            |addr, len| {
                asked.push(addr);
                Some(vec![0xAA; len])
            },
        );

        assert!(
            asked.iter().all(|&a| a >= u64::MAX - 3),
            "the walk read a wrapped-around address ({:#x?}) instead of stopping",
            asked.iter().find(|&&a| a < u64::MAX - 3)
        );
        assert_eq!(
            frames.len(),
            1,
            "an fp whose frame record cannot be addressed yields only the initial frame"
        );
    }

    /// A return address that the map says is NOT executable ends the walk.
    ///
    /// The values come out of the debuggee stack, so a corrupt frame - or a
    /// function that keeps a data pointer in the frame register, which
    /// -fomit-frame-pointer frees it to do - yields a caller somewhere in the
    /// heap. The chain kept walking and produced frames that look exactly like
    /// real ones. A backtrace is read as a statement of fact, so a fabricated
    /// caller is worse than a short stack: it names a function that is not on
    /// the stack at all.
    ///
    /// The region view was already passed in and used only to NAME frames.
    #[test]
    fn a_return_address_in_non_executable_memory_ends_the_walk() {
        let mut regions = MappedRegionView::default();
        regions.regions.push(MemoryRegion {
            start: 0x0040_0000,
            end: 0x0041_0000,
            prot: Protection::rx(),
            kind: RegionKind::Anonymous,
            aslr_offset: 0,
            is_guard: false,
            rss: None,
        });
        regions.regions.push(MemoryRegion {
            start: 0x0060_0000,
            end: 0x0061_0000,
            prot: Protection::rw(),
            kind: RegionKind::Heap { allocator: "test".to_string() },
            aslr_offset: 0,
            is_guard: false,
            rss: None,
        });

        // Frame record at 0x7000: saved_fp = 0x8000 (higher, so the monotonic
        // check passes), return address = 0x0060_0100, which is in the HEAP.
        let unwinder = FramePointerUnwinder::new(16);
        let frames = unwinder.unwind(0x0040_1000, 0x7fff_0000, Some(0x7000), &regions, |addr, len| {
            let value: u64 = match addr {
                0x7000 => 0x8000,
                0x7008 => 0x0060_0100,
                _ => 0x9000,
            };
            let mut v = value.to_le_bytes().to_vec();
            v.resize(len.max(8), 0);
            Some(v)
        });
        assert_eq!(
            frames.len(),
            1,
            "a return address inside a read/write heap region is not a caller and must not be reported as one"
        );
    }

    /// ...but an address the map does not describe AT ALL is still followed.
    ///
    /// memory_maps can miss freshly mapped JIT code, and refusing what we
    /// merely cannot see would truncate exactly the stacks that need an
    /// unwinder most. Same rule run_to_return follows in all three backends.
    #[test]
    fn a_return_address_in_an_unmapped_region_is_still_followed() {
        let mut regions = MappedRegionView::default();
        regions.regions.push(MemoryRegion {
            start: 0x0040_0000,
            end: 0x0041_0000,
            prot: Protection::rx(),
            kind: RegionKind::Anonymous,
            aslr_offset: 0,
            is_guard: false,
            rss: None,
        });
        let unwinder = FramePointerUnwinder::new(4);
        let frames = unwinder.unwind(0x0040_1000, 0x7fff_0000, Some(0x7000), &regions, |addr, len| {
            let value: u64 = match addr {
                0x7000 => 0x8000,
                0x7008 => 0x00CA_FE00,
                _ => 0,
            };
            let mut v = value.to_le_bytes().to_vec();
            v.resize(len.max(8), 0);
            Some(v)
        });
        assert!(
            frames.len() >= 2,
            "an unmapped return address is unknown, not known-bad, and the walk must continue"
        );
        assert_eq!(frames[1].pc, 0x00CA_FE00);
    }

    #[test]
    fn test_frame_pointer_unwinder_no_frames() {
        let unwinder = FramePointerUnwinder::new(16);
        let regions = MappedRegionView::default();
        let frames = unwinder.unwind(0x0040_1000, 0x7fff_0000, None, &regions, |_, _| None);
        // With fp=None only the initial frame is returned.
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].pc, 0x0040_1000);
    }

    #[test]
    fn test_protection_display() {
        let p = Protection::rx();
        assert_eq!(p.to_string(), "r-xp");
        let q = Protection::rw();
        assert_eq!(q.to_string(), "rw-p");
    }

    // ── HeapChunkGraph ───────────────────────────────────────────────────────

    fn chunk(header: u64, size: u64, state: ChunkState, fd: Option<u64>, bk: Option<u64>) -> HeapChunk {
        HeapChunk {
            header_addr: header,
            user_addr: header + 0x10,
            chunk_size: size,
            user_size: size - 0x10,
            state,
            flags: 0,
            allocator: HeapAllocator::GlibcPtmalloc2,
            next_free: fd,
            prev_free: bk,
        }
    }

        /// Adjacency must not depend on the order the caller happened to supply.
    ///
    /// `HeapLayout::chunks` DOCUMENTS that it is sorted by header address and
    /// `pub chunks` enforces nothing — the same exposure `MappedRegionView::find`
    /// already defends against. Pairing `windows(2)` over an unsorted vector
    /// compares chunks that are not neighbours, so the adjacency edges go
    /// MISSING: the graph then reports two physically adjacent chunks as not
    /// adjacent, which is precisely the fact this graph is consulted for.
    #[test]
    fn heap_graph_adjacency_does_not_depend_on_input_order() {
        let sorted = vec![
            chunk(0x1000, 0x20, ChunkState::Allocated, None, None),
            chunk(0x1020, 0x20, ChunkState::Free, None, None),
            chunk(0x1040, 0x20, ChunkState::Allocated, None, None),
        ];
        // The SAME three chunks, handed over in another order.
        let shuffled = vec![
            chunk(0x1040, 0x20, ChunkState::Allocated, None, None),
            chunk(0x1000, 0x20, ChunkState::Allocated, None, None),
            chunk(0x1020, 0x20, ChunkState::Free, None, None),
        ];

        let adjacency = |chunks: Vec<HeapChunk>| -> Vec<(u64, u64)> {
            let g = HeapChunkGraph::from_layout(&HeapLayout::from_chunks(chunks));
            let mut e: Vec<(u64, u64)> = g
                .edges
                .iter()
                .filter(|e| e.kind == HeapGraphEdgeKind::Adjacent)
                .map(|e| (e.from, e.to))
                .collect();
            e.sort_unstable();
            e
        };

        let expected = vec![(0x1000, 0x1020), (0x1020, 0x1040)];
        assert_eq!(adjacency(sorted), expected, "the sorted case is the baseline");
        assert_eq!(
            adjacency(shuffled),
            expected,
            "the same chunks in another order describe the same heap, so the adjacency edges must be the same"
        );
    }

#[test]
    fn heap_graph_one_node_per_chunk() {
        let chunks = vec![
            chunk(0x1000, 0x20, ChunkState::Allocated, None, None),
            chunk(0x1020, 0x20, ChunkState::Free, None, None),
        ];
        let layout = HeapLayout::from_chunks(chunks);
        let graph = HeapChunkGraph::from_layout(&layout);
        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.nodes[0].id, 0x1000);
        assert_eq!(graph.nodes[0].state, ChunkState::Allocated);
        assert_eq!(graph.nodes[1].state, ChunkState::Free);
    }

    #[test]
    fn heap_graph_free_list_edges() {
        let chunks = vec![
            chunk(0x1000, 0x20, ChunkState::Free, Some(0x2000), Some(0x3000)),
        ];
        let layout = HeapLayout::from_chunks(chunks);
        let graph = HeapChunkGraph::from_layout(&layout);
        assert_eq!(graph.edges.len(), 2);
        assert!(graph.edges.iter().any(|e| e.kind == HeapGraphEdgeKind::FreeListForward && e.to == 0x2000));
        assert!(graph.edges.iter().any(|e| e.kind == HeapGraphEdgeKind::FreeListBackward && e.to == 0x3000));
    }

    #[test]
    fn heap_graph_adjacency_edges() {
        let chunks = vec![
            chunk(0x1000, 0x20, ChunkState::Allocated, None, None),
            chunk(0x1020, 0x20, ChunkState::Allocated, None, None), // adjacent: 0x1000+0x20=0x1020
            chunk(0x1100, 0x20, ChunkState::Allocated, None, None), // gap: not adjacent
        ];
        let layout = HeapLayout::from_chunks(chunks);
        let graph = HeapChunkGraph::from_layout(&layout);
        let adj: Vec<_> = graph.edges.iter().filter(|e| e.kind == HeapGraphEdgeKind::Adjacent).collect();
        assert_eq!(adj.len(), 1);
        assert_eq!(adj[0].from, 0x1000);
        assert_eq!(adj[0].to, 0x1020);
    }

    #[test]
    fn heap_graph_corrupted_node_ids() {
        let chunks = vec![
            chunk(0x1000, 0x20, ChunkState::Allocated, None, None),
            chunk(0x1020, 0x20, ChunkState::Corrupted, None, None),
        ];
        let layout = HeapLayout::from_chunks(chunks);
        let graph = HeapChunkGraph::from_layout(&layout);
        assert_eq!(graph.corrupted_node_ids(), vec![0x1020]);
    }

    #[test]
    fn heap_graph_empty_layout() {
        let layout = HeapLayout::from_chunks(vec![]);
        let graph = HeapChunkGraph::from_layout(&layout);
        assert!(graph.is_empty());
        assert!(graph.edges.is_empty());
    }

    #[test]
    fn heap_graph_to_json_round_trips_node_count() {
        let chunks = vec![chunk(0x1000, 0x20, ChunkState::Allocated, None, None)];
        let layout = HeapLayout::from_chunks(chunks);
        let graph = HeapChunkGraph::from_layout(&layout);
        let json = graph.to_json().unwrap();
        let parsed: HeapChunkGraph = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.nodes.len(), 1);
        assert_eq!(parsed.nodes[0].id, 0x1000);
    }
}
