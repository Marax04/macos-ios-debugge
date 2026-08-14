//! `vmmap_analyzer` — VMMap-equivalent
//!
//! Virtual memory layout of a process, regions by type (heap/stack/mapped/image/private),
//! commit vs reserve, working set analysis, memory protection flags.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::SysinternalsError;

// ─── MemoryRegionType ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryRegionType {
    Image,
    Mapped,
    Private,
    Heap,
    Stack,
    Teb,
    Peb,
    ShareData,
    NtDllData,
    KernelShared,
    Guard,
    Free,
    Reserved,
    Unknown,
}

impl fmt::Display for MemoryRegionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Image => "Image",
            Self::Mapped => "Mapped",
            Self::Private => "Private",
            Self::Heap => "Heap",
            Self::Stack => "Stack",
            Self::Teb => "TEB",
            Self::Peb => "PEB",
            Self::ShareData => "Share Data",
            Self::NtDllData => "NtDll Data",
            Self::KernelShared => "Kernel Shared",
            Self::Guard => "Guard",
            Self::Free => "Free",
            Self::Reserved => "Reserved",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

// ─── PageProtection ───────────────────────────────────────────────────────────

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct PageProtection: u32 {
        const NONE                  = 0x00;
        const NOACCESS              = 0x01;
        const READONLY              = 0x02;
        const READWRITE             = 0x04;
        const WRITECOPY             = 0x08;
        const EXECUTE               = 0x10;
        const EXECUTE_READ          = 0x20;
        const EXECUTE_READWRITE     = 0x40;
        const EXECUTE_WRITECOPY     = 0x80;
        const GUARD                 = 0x100;
        const NOCACHE               = 0x200;
        const WRITECOMBINE          = 0x400;
    }
}

impl PageProtection {
    #[must_use]
    pub fn is_executable(self) -> bool {
        self.intersects(
            Self::EXECUTE
                | Self::EXECUTE_READ
                | Self::EXECUTE_READWRITE
                | Self::EXECUTE_WRITECOPY,
        )
    }

    #[must_use]
    pub fn is_writable(self) -> bool {
        self.intersects(
            Self::READWRITE | Self::WRITECOPY | Self::EXECUTE_READWRITE | Self::EXECUTE_WRITECOPY,
        )
    }

    #[must_use]
    pub fn is_rwx(self) -> bool {
        self.intersects(Self::EXECUTE_READWRITE | Self::EXECUTE_WRITECOPY)
    }

    #[must_use]
    pub fn to_str_abbr(self) -> &'static str {
        if self.is_rwx() {
            "RWX"
        } else if self.contains(Self::EXECUTE_READ) {
            "R-X"
        } else if self.is_executable() {
            "--X"
        } else if self.is_writable() {
            "RW-"
        } else if self.contains(Self::READONLY) {
            "R--"
        } else if self.contains(Self::NOACCESS) {
            "---"
        } else {
            "???"
        }
    }
}

// ─── MemoryState ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryState {
    Commit,
    Reserve,
    Free,
}

impl fmt::Display for MemoryState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Commit => write!(f, "Commit"),
            Self::Reserve => write!(f, "Reserve"),
            Self::Free => write!(f, "Free"),
        }
    }
}

// ─── MemoryRegion ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub base_address: u64,
    pub size: u64,
    pub region_type: MemoryRegionType,
    pub state: MemoryState,
    pub protection: PageProtection,
    pub initial_protection: PageProtection,
    /// Associated file/image path (for Image/Mapped regions).
    pub filename: String,
    /// Heap ID (for Heap regions).
    pub heap_id: Option<u32>,
    /// Thread ID (for Stack/TEB regions).
    pub thread_id: Option<u32>,
    /// Whether this region is in the working set (physically resident).
    pub in_working_set: bool,
    /// Working set page count (pages physically in RAM).
    pub working_set_pages: u64,
    /// Committed bytes within this region.
    pub committed_bytes: u64,
    /// Private bytes (not shared).
    pub private_bytes: u64,
    /// Blocks (sub-regions) if this is a heap region.
    pub blocks: Vec<MemoryBlock>,
}

impl MemoryRegion {
    #[must_use]
    pub const fn new(
        base: u64,
        size: u64,
        region_type: MemoryRegionType,
        state: MemoryState,
        protection: PageProtection,
    ) -> Self {
        Self {
            base_address: base,
            size,
            region_type,
            state,
            protection,
            initial_protection: protection,
            filename: String::new(),
            heap_id: None,
            thread_id: None,
            in_working_set: false,
            working_set_pages: 0,
            committed_bytes: 0,
            private_bytes: 0,
            blocks: Vec::new(),
        }
    }

    #[must_use]
    pub const fn end_address(&self) -> u64 {
        self.base_address.saturating_add(self.size)
    }

    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base_address && addr < self.end_address()
    }

    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        // Executable + writable regions not backed by a file.
        (self.protection.is_rwx() && self.region_type == MemoryRegionType::Private)
            || (self.protection.is_executable()
                && self.region_type == MemoryRegionType::Private
                && self.filename.is_empty())
            || (self.region_type == MemoryRegionType::Image && self.protection.is_writable())
    }

    /// Entropy of the first 4KB of committed data.
    #[must_use]
    pub const fn estimated_entropy(&self) -> f64 {
        // Without actual memory reads, return 0. Platform backends fill this.
        0.0
    }

    #[must_use]
    pub fn protection_str(&self) -> &'static str {
        self.protection.to_str_abbr()
    }

    #[must_use]
    pub fn to_csv_row(&self) -> String {
        format!(
            "{:#018x},{:#018x},{},{},{},{},{},{}",
            self.base_address,
            self.size,
            self.region_type,
            self.state,
            self.protection_str(),
            self.committed_bytes,
            self.private_bytes,
            self.filename,
        )
    }
}

// ─── MemoryBlock ──────────────────────────────────────────────────────────────

/// A sub-allocation within a heap region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryBlock {
    pub offset: u64,
    pub size: u64,
    pub is_free: bool,
    pub overhead: u64,
}

// ─── VmMapSummary ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VmMapSummary {
    pub total_committed: u64,
    pub total_reserved: u64,
    pub total_free: u64,
    pub total_private: u64,
    pub total_image: u64,
    pub total_mapped: u64,
    pub heap_committed: u64,
    pub stack_committed: u64,
    pub executable_committed: u64,
    pub rwx_committed: u64,
    pub working_set_bytes: u64,
    pub region_count: usize,
    pub suspicious_region_count: usize,
    pub by_type: HashMap<String, u64>,
}

// ─── HeapInfo ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeapInfo {
    pub heap_id: u32,
    pub base_address: u64,
    pub committed_bytes: u64,
    pub reserved_bytes: u64,
    pub free_bytes: u64,
    pub block_count: u32,
    pub free_block_count: u32,
    pub is_default: bool,
    pub flags: u32,
}

// ─── StackInfo ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackInfo {
    pub thread_id: u32,
    pub base_address: u64,
    pub committed_bytes: u64,
    pub reserved_bytes: u64,
    pub stack_pointer: u64,
    pub max_usage: u64,
    pub overflow_risk: bool,
}

// ─── VmMapFilter ──────────────────────────────────────────────────────────────

/// Memory protection filter flags (≤ 3 bools to satisfy the lint).
#[derive(Debug, Clone, Default)]
pub struct ProtectionFilter {
    pub executable_only: bool,
    pub writable_only: bool,
    pub rwx_only: bool,
}

#[derive(Debug, Clone, Default)]
pub struct VmMapFilter {
    pub region_types: Vec<MemoryRegionType>,
    pub states: Vec<MemoryState>,
    pub min_size: Option<u64>,
    pub protection: ProtectionFilter,
    pub suspicious_only: bool,
    pub in_working_set: bool,
    pub filename_contains: Option<String>,
    pub address_range: Option<(u64, u64)>,
}

impl VmMapFilter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn matches(&self, r: &MemoryRegion) -> bool {
        if !self.region_types.is_empty() && !self.region_types.contains(&r.region_type) {
            return false;
        }
        if !self.states.is_empty() && !self.states.contains(&r.state) {
            return false;
        }
        if let Some(ms) = self.min_size
            && r.size < ms
        {
            return false;
        }
        if self.protection.executable_only && !r.protection.is_executable() {
            return false;
        }
        if self.protection.writable_only && !r.protection.is_writable() {
            return false;
        }
        if self.protection.rwx_only && !r.protection.is_rwx() {
            return false;
        }
        if self.suspicious_only && !r.is_suspicious() {
            return false;
        }
        if self.in_working_set && !r.in_working_set {
            return false;
        }
        if let Some(ref fc) = self.filename_contains
            && !r.filename.to_lowercase().contains(fc.to_lowercase().as_str())
        {
            return false;
        }
        if let Some((lo, hi)) = self.address_range
            && (r.end_address() <= lo || r.base_address >= hi)
        {
            return false;
        }
        true
    }

    #[must_use]
    pub const fn executable_only(mut self) -> Self {
        self.protection.executable_only = true;
        self
    }

    #[must_use]
    pub const fn rwx_only(mut self) -> Self {
        self.protection.rwx_only = true;
        self
    }

    #[must_use]
    pub const fn suspicious_only(mut self) -> Self {
        self.suspicious_only = true;
        self
    }

    #[must_use]
    pub fn with_type(mut self, t: MemoryRegionType) -> Self {
        self.region_types.push(t);
        self
    }
}

// ─── VmMapAnalyzer ────────────────────────────────────────────────────────────

pub struct VmMapAnalyzer {
    pid: u32,
    regions: Vec<MemoryRegion>,
    heaps: Vec<HeapInfo>,
    stacks: Vec<StackInfo>,
}

impl VmMapAnalyzer {
    #[must_use]
    pub const fn new(pid: u32) -> Self {
        Self {
            pid,
            regions: Vec::new(),
            heaps: Vec::new(),
            stacks: Vec::new(),
        }
    }

    pub fn add_region(&mut self, r: MemoryRegion) {
        self.regions.push(r);
    }

    pub fn bulk_add(&mut self, regions: Vec<MemoryRegion>) {
        self.regions.extend(regions);
    }

    pub fn add_heap(&mut self, h: HeapInfo) {
        self.heaps.push(h);
    }

    pub fn add_stack(&mut self, s: StackInfo) {
        self.stacks.push(s);
    }

    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    #[must_use]
    pub const fn region_count(&self) -> usize {
        self.regions.len()
    }

    #[must_use]
    pub fn all_regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    /// Query regions with a filter.
    #[must_use]
    pub fn query(&self, filter: &VmMapFilter) -> Vec<&MemoryRegion> {
        self.regions.iter().filter(|r| filter.matches(r)).collect()
    }

    /// Find region containing an address.
    #[must_use]
    pub fn region_at(&self, addr: u64) -> Option<&MemoryRegion> {
        self.regions.iter().find(|r| r.contains(addr))
    }

    /// Compute summary statistics.
    #[must_use]
    pub fn summary(&self) -> VmMapSummary {
        let mut s = VmMapSummary {
            region_count: self.regions.len(),
            ..Default::default()
        };
        for r in &self.regions {
            match r.state {
                MemoryState::Commit => s.total_committed += r.size,
                MemoryState::Reserve => s.total_reserved += r.size,
                MemoryState::Free => s.total_free += r.size,
            }
            match r.region_type {
                MemoryRegionType::Private => s.total_private += r.committed_bytes,
                MemoryRegionType::Image => s.total_image += r.committed_bytes,
                MemoryRegionType::Mapped => s.total_mapped += r.committed_bytes,
                MemoryRegionType::Heap => s.heap_committed += r.committed_bytes,
                MemoryRegionType::Stack => s.stack_committed += r.committed_bytes,
                _ => {}
            }
            if r.protection.is_executable() {
                s.executable_committed += r.committed_bytes;
            }
            if r.protection.is_rwx() {
                s.rwx_committed += r.committed_bytes;
            }
            if r.in_working_set {
                s.working_set_bytes += r.working_set_pages * 4096;
            }
            if r.is_suspicious() {
                s.suspicious_region_count += 1;
            }
            *s.by_type.entry(r.region_type.to_string()).or_default() += r.size;
        }
        s
    }

    /// Find all executable private regions (classic shellcode indicator).
    #[must_use]
    pub fn exec_private_regions(&self) -> Vec<&MemoryRegion> {
        let filter = VmMapFilter::new()
            .with_type(MemoryRegionType::Private)
            .executable_only();
        self.query(&filter)
    }

    /// Find all RWX regions.
    #[must_use]
    pub fn rwx_regions(&self) -> Vec<&MemoryRegion> {
        let filter = VmMapFilter::new().rwx_only();
        self.query(&filter)
    }

    /// All heap info.
    #[must_use]
    pub fn heaps(&self) -> &[HeapInfo] {
        &self.heaps
    }

    /// All stack info.
    #[must_use]
    pub fn stacks(&self) -> &[StackInfo] {
        &self.stacks
    }

    /// Detect stacks at risk of overflow.
    #[must_use]
    pub fn overflow_risk_stacks(&self) -> Vec<&StackInfo> {
        self.stacks.iter().filter(|s| s.overflow_risk).collect()
    }

    /// Sort regions by base address ascending.
    pub fn sort_by_address(&mut self) {
        self.regions.sort_by_key(|r| r.base_address);
    }

    /// Find the largest private committed region.
    #[must_use]
    pub fn largest_private_region(&self) -> Option<&MemoryRegion> {
        self.regions
            .iter()
            .filter(|r| r.region_type == MemoryRegionType::Private && r.state == MemoryState::Commit)
            .max_by_key(|r| r.size)
    }

    /// Find all mapped files and their total committed bytes.
    #[must_use]
    pub fn mapped_file_summary(&self) -> HashMap<String, u64> {
        let mut map: HashMap<String, u64> = HashMap::new();
        for r in &self.regions {
            if (r.region_type == MemoryRegionType::Image
                || r.region_type == MemoryRegionType::Mapped)
                && !r.filename.is_empty()
            {
                *map.entry(r.filename.clone()).or_default() += r.committed_bytes;
            }
        }
        map
    }

    /// Total virtual address space consumed.
    #[must_use]
    pub fn total_virtual_bytes(&self) -> u64 {
        self.regions
            .iter()
            .filter(|r| r.state != MemoryState::Free)
            .map(|r| r.size)
            .sum()
    }

    /// Export to CSV.
    #[must_use]
    pub fn to_csv(&self) -> String {
        let mut out =
            String::from("BaseAddress,Size,Type,State,Protection,Committed,Private,Filename\n");
        for r in &self.regions {
            out.push_str(&r.to_csv_row());
            out.push('\n');
        }
        out
    }

    /// # Errors
    /// Returns an error if the underlying operation fails.
    pub fn to_json(&self) -> Result<String, SysinternalsError> {
        serde_json::to_string_pretty(&self.regions)
            .map_err(|e| SysinternalsError::InvalidData(e.to_string()))
    }
}

// ─── Region builder ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct RegionBuilder {
    inner: MemoryRegion,
}

impl RegionBuilder {
    #[must_use]
    pub const fn new(base: u64, size: u64) -> Self {
        Self {
            inner: MemoryRegion::new(base, size, MemoryRegionType::Unknown, MemoryState::Free, PageProtection::NONE),
        }
    }

    #[must_use]
    pub const fn region_type(mut self, t: MemoryRegionType) -> Self {
        self.inner.region_type = t;
        self
    }

    #[must_use]
    pub const fn state(mut self, s: MemoryState) -> Self {
        self.inner.state = s;
        self
    }

    #[must_use]
    pub const fn protection(mut self, p: PageProtection) -> Self {
        self.inner.protection = p;
        self
    }

    #[must_use]
    pub fn filename(mut self, f: impl Into<String>) -> Self {
        self.inner.filename = f.into();
        self
    }

    #[must_use]
    pub const fn committed(mut self, c: u64) -> Self {
        self.inner.committed_bytes = c;
        self
    }

    #[must_use]
    pub const fn private_bytes(mut self, p: u64) -> Self {
        self.inner.private_bytes = p;
        self
    }

    #[must_use]
    pub const fn thread_id(mut self, tid: u32) -> Self {
        self.inner.thread_id = Some(tid);
        self
    }

    #[must_use]
    pub const fn heap_id(mut self, hid: u32) -> Self {
        self.inner.heap_id = Some(hid);
        self
    }

    #[must_use]
    pub const fn in_working_set(mut self, pages: u64) -> Self {
        self.inner.in_working_set = true;
        self.inner.working_set_pages = pages;
        self
    }

    #[must_use]
    pub fn build(self) -> MemoryRegion {
        self.inner
    }
}

// ─── Process memory footprint ─────────────────────────────────────────────────

/// High-level footprint summary used by the MCP layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMemoryFootprint {
    pub pid: u32,
    pub virtual_bytes: u64,
    pub committed_bytes: u64,
    pub private_bytes: u64,
    pub working_set_bytes: u64,
    pub image_bytes: u64,
    pub heap_bytes: u64,
    pub stack_bytes: u64,
    pub mapped_bytes: u64,
    pub exec_private_bytes: u64,
    pub rwx_bytes: u64,
    pub suspicious_region_count: usize,
}

impl ProcessMemoryFootprint {
    #[must_use]
    pub fn from_analyzer(analyzer: &VmMapAnalyzer) -> Self {
        let summary = analyzer.summary();
        Self {
            pid: analyzer.pid(),
            virtual_bytes: analyzer.total_virtual_bytes(),
            committed_bytes: summary.total_committed,
            private_bytes: summary.total_private,
            working_set_bytes: summary.working_set_bytes,
            image_bytes: summary.total_image,
            heap_bytes: summary.heap_committed,
            stack_bytes: summary.stack_committed,
            mapped_bytes: summary.total_mapped,
            exec_private_bytes: analyzer
                .exec_private_regions()
                .iter()
                .map(|r| r.committed_bytes)
                .sum(),
            rwx_bytes: analyzer
                .rwx_regions()
                .iter()
                .map(|r| r.committed_bytes)
                .sum(),
            suspicious_region_count: summary.suspicious_region_count,
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_region(
        base: u64,
        size: u64,
        t: MemoryRegionType,
        state: MemoryState,
        prot: PageProtection,
    ) -> MemoryRegion {
        RegionBuilder::new(base, size)
            .region_type(t)
            .state(state)
            .protection(prot)
            .committed(if state == MemoryState::Commit { size } else { 0 })
            .build()
    }

    #[test]
    fn test_page_protection_rwx() {
        let p = PageProtection::EXECUTE_READWRITE;
        assert!(p.is_rwx());
        assert!(p.is_executable());
        assert!(p.is_writable());
        assert_eq!(p.to_str_abbr(), "RWX");
    }

    #[test]
    fn test_page_protection_readonly() {
        let p = PageProtection::READONLY;
        assert!(!p.is_executable());
        assert!(!p.is_writable());
        assert_eq!(p.to_str_abbr(), "R--");
    }

    #[test]
    fn test_memory_region_contains() {
        let r = make_region(0x1000, 0x1000, MemoryRegionType::Private, MemoryState::Commit, PageProtection::READWRITE);
        assert!(r.contains(0x1000));
        assert!(r.contains(0x1500));
        assert!(!r.contains(0x2000));
        assert_eq!(r.end_address(), 0x2000);
    }

    #[test]
    fn test_memory_region_suspicious_rwx_private() {
        let r = make_region(
            0x1000,
            0x1000,
            MemoryRegionType::Private,
            MemoryState::Commit,
            PageProtection::EXECUTE_READWRITE,
        );
        assert!(r.is_suspicious());
    }

    #[test]
    fn test_memory_region_not_suspicious() {
        let r = make_region(
            0x0040_0000,
            0x10000,
            MemoryRegionType::Image,
            MemoryState::Commit,
            PageProtection::EXECUTE_READ,
        );
        assert!(!r.is_suspicious());
    }

    #[test]
    fn test_vmmap_analyzer_summary() {
        let mut analyzer = VmMapAnalyzer::new(1234);
        // Private committed.
        analyzer.add_region(make_region(0x0010_0000, 0x10000, MemoryRegionType::Private, MemoryState::Commit, PageProtection::READWRITE));
        // Image committed.
        analyzer.add_region(make_region(0x0040_0000, 0x50000, MemoryRegionType::Image, MemoryState::Commit, PageProtection::EXECUTE_READ));
        // Reserved.
        analyzer.add_region(make_region(0x0050_0000, 0x0010_0000, MemoryRegionType::Private, MemoryState::Reserve, PageProtection::NONE));

        let s = analyzer.summary();
        assert_eq!(s.region_count, 3);
        assert!(s.total_committed > 0);
        assert!(s.total_reserved > 0);
        assert!(s.executable_committed > 0);
    }

    #[test]
    fn test_vmmap_analyzer_query_filter() {
        let mut analyzer = VmMapAnalyzer::new(1);
        analyzer.add_region(make_region(0x1000, 0x1000, MemoryRegionType::Private, MemoryState::Commit, PageProtection::EXECUTE_READWRITE));
        analyzer.add_region(make_region(0x2000, 0x1000, MemoryRegionType::Image, MemoryState::Commit, PageProtection::EXECUTE_READ));
        let filter = VmMapFilter::new().rwx_only();
        let results = analyzer.query(&filter);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].base_address, 0x1000);
    }

    #[test]
    fn test_vmmap_analyzer_exec_private() {
        let mut analyzer = VmMapAnalyzer::new(1);
        analyzer.add_region(make_region(0x1000, 0x1000, MemoryRegionType::Private, MemoryState::Commit, PageProtection::EXECUTE));
        analyzer.add_region(make_region(0x2000, 0x1000, MemoryRegionType::Private, MemoryState::Commit, PageProtection::READWRITE));
        analyzer.add_region(make_region(0x3000, 0x1000, MemoryRegionType::Image, MemoryState::Commit, PageProtection::EXECUTE_READ));
        let exec_private = analyzer.exec_private_regions();
        assert_eq!(exec_private.len(), 1);
        assert_eq!(exec_private[0].base_address, 0x1000);
    }

    #[test]
    fn test_vmmap_analyzer_region_at() {
        let mut analyzer = VmMapAnalyzer::new(1);
        analyzer.add_region(make_region(0x0040_0000, 0x10000, MemoryRegionType::Image, MemoryState::Commit, PageProtection::EXECUTE_READ));
        assert!(analyzer.region_at(0x0040_5000).is_some());
        assert!(analyzer.region_at(0x0050_0000).is_none());
    }

    #[test]
    fn test_vmmap_analyzer_csv() {
        let mut analyzer = VmMapAnalyzer::new(1);
        analyzer.add_region(make_region(0x1000, 0x1000, MemoryRegionType::Private, MemoryState::Commit, PageProtection::READWRITE));
        let csv = analyzer.to_csv();
        assert!(csv.contains("BaseAddress"));
        assert!(csv.contains("Private"));
    }

    #[test]
    fn test_vmmap_analyzer_sort() {
        let mut analyzer = VmMapAnalyzer::new(1);
        analyzer.add_region(make_region(0x5000, 0x1000, MemoryRegionType::Private, MemoryState::Commit, PageProtection::READWRITE));
        analyzer.add_region(make_region(0x1000, 0x1000, MemoryRegionType::Private, MemoryState::Commit, PageProtection::READWRITE));
        analyzer.sort_by_address();
        assert_eq!(analyzer.all_regions()[0].base_address, 0x1000);
        assert_eq!(analyzer.all_regions()[1].base_address, 0x5000);
    }

    #[test]
    fn test_vmmap_filter_filename() {
        let mut analyzer = VmMapAnalyzer::new(1);
        let mut r = make_region(0x0040_0000, 0x10000, MemoryRegionType::Image, MemoryState::Commit, PageProtection::EXECUTE_READ);
        r.filename = "ntdll.dll".into();
        analyzer.add_region(r);
        analyzer.add_region(make_region(0x0050_0000, 0x1000, MemoryRegionType::Private, MemoryState::Commit, PageProtection::READWRITE));
        let mut filter = VmMapFilter::new();
        filter.filename_contains = Some("ntdll".into());
        let results = analyzer.query(&filter);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].filename, "ntdll.dll");
    }

    #[test]
    fn test_mapped_file_summary() {
        let mut analyzer = VmMapAnalyzer::new(1);
        let r1 = RegionBuilder::new(0x0040_0000, 0x10000)
            .region_type(MemoryRegionType::Image)
            .state(MemoryState::Commit)
            .protection(PageProtection::EXECUTE_READ)
            .committed(0x10000)
            .filename("ntdll.dll")
            .build();
        let r2 = RegionBuilder::new(0x0050_0000, 0x8000)
            .region_type(MemoryRegionType::Image)
            .state(MemoryState::Commit)
            .protection(PageProtection::EXECUTE_READ)
            .committed(0x8000)
            .filename("ntdll.dll")
            .build();
        analyzer.add_region(r1);
        analyzer.add_region(r2);
        let summary = analyzer.mapped_file_summary();
        assert!(summary.contains_key("ntdll.dll"));
        assert_eq!(summary["ntdll.dll"], 0x10000 + 0x8000);
    }

    #[test]
    fn test_process_memory_footprint() {
        let mut analyzer = VmMapAnalyzer::new(42);
        analyzer.add_region(
            RegionBuilder::new(0x0040_0000, 0x10000)
                .region_type(MemoryRegionType::Image)
                .state(MemoryState::Commit)
                .protection(PageProtection::EXECUTE_READ)
                .committed(0x10000)
                .build(),
        );
        analyzer.add_region(
            RegionBuilder::new(0x1000, 0x2000)
                .region_type(MemoryRegionType::Private)
                .state(MemoryState::Commit)
                .protection(PageProtection::EXECUTE_READWRITE)
                .committed(0x2000)
                .build(),
        );
        let fp = ProcessMemoryFootprint::from_analyzer(&analyzer);
        assert_eq!(fp.pid, 42);
        assert_eq!(fp.suspicious_region_count, 1);
        assert_eq!(fp.rwx_bytes, 0x2000);
    }
}
