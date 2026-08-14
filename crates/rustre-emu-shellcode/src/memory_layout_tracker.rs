//! `memory_layout_tracker` — Track memory layout during shellcode emulation.
//!
//! Maps allocated regions, records access patterns, and detects common
//! heap-spray signatures.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// RegionKind
// ─────────────────────────────────────────────────────────────────────────────

/// The kind / origin of a tracked memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionKind {
    /// The shellcode itself.
    Code,
    /// Emulated stack region.
    Stack,
    /// Emulated heap region.
    Heap,
    /// Dynamically allocated by VirtualAlloc / mmap during emulation.
    Allocated,
    /// Mapped by a file-backed mmap stub.
    FileMapped,
    /// Contains decoded / deobfuscated payload data.
    Payload,
    /// Unknown origin.
    Unknown,
}

impl RegionKind {
    /// Returns a short string label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Code => "CODE",
            Self::Stack => "STACK",
            Self::Heap => "HEAP",
            Self::Allocated => "ALLOC",
            Self::FileMapped => "FILEMAPPED",
            Self::Payload => "PAYLOAD",
            Self::Unknown => "UNKNOWN",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryRegion
// ─────────────────────────────────────────────────────────────────────────────

/// A tracked memory region in the emulated address space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// Start virtual address.
    pub base: u64,
    /// Size in bytes.
    pub size: usize,
    /// Region kind.
    pub kind: RegionKind,
    /// Human-readable label (e.g. `"shellcode"`, `"VirtualAlloc result"`).
    pub label: String,
    /// Unix permissions mask: bit 2 = read, 1 = write, 0 = execute.
    pub perms: u8,
    /// Number of read accesses to this region.
    pub read_count: u64,
    /// Number of write accesses to this region.
    pub write_count: u64,
    /// Whether this region has been fully written (all bytes written at least once).
    pub fully_written: bool,
    /// Whether this region contains executable-looking data.
    pub executable_content: bool,
}

impl MemoryRegion {
    /// Create a new region.
    #[must_use]
    pub fn new(base: u64, size: usize, kind: RegionKind, label: impl Into<String>, perms: u8) -> Self {
        Self {
            base,
            size,
            kind,
            label: label.into(),
            perms,
            read_count: 0,
            write_count: 0,
            fully_written: false,
            executable_content: false,
        }
    }

    /// Return the exclusive end address.
    #[must_use]
    pub fn end(&self) -> u64 {
        self.base.saturating_add(self.size as u64)
    }

    /// Returns `true` if `addr` falls within this region.
    #[must_use]
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }

    /// Returns `true` if this region is readable.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.perms & 0b100 != 0
    }

    /// Returns `true` if this region is writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.perms & 0b010 != 0
    }

    /// Returns `true` if this region is executable.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.perms & 0b001 != 0
    }

    /// Record a read access.
    pub fn record_read(&mut self) {
        self.read_count += 1;
    }

    /// Record a write access and check if the region was fully written.
    ///
    /// `written_bytes` is the cumulative count of unique written bytes tracked
    /// by the caller.
    pub fn record_write(&mut self, written_bytes: usize) {
        self.write_count += 1;
        if written_bytes >= self.size {
            self.fully_written = true;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryLayoutTracker
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks the full memory layout of a shellcode emulation run.
///
/// Maintains a set of [`MemoryRegion`]s and a per-address write bitmap for
/// tracking heap spray patterns.
#[derive(Debug, Default)]
pub struct MemoryLayoutTracker {
    regions: Vec<MemoryRegion>,
    /// Per-region write bitmap: region_index → set of written byte offsets.
    write_bitmaps: HashMap<usize, Vec<bool>>,
    /// Total number of allocation events seen.
    allocation_count: usize,
    /// Addresses that have been executed (PC seen in code hooks).
    executed_pages: Vec<u64>,
}

impl MemoryLayoutTracker {
    /// Create an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a memory region.
    ///
    /// If a region with the same base already exists it is replaced.
    pub fn add_region(&mut self, region: MemoryRegion) {
        let size = region.size;
        // Remove any existing region at the same base.
        self.regions.retain(|r| r.base != region.base);
        let idx = self.regions.len();
        self.regions.push(region);
        self.write_bitmaps.insert(idx, vec![false; size]);
        if matches!(
            self.regions[idx].kind,
            RegionKind::Allocated | RegionKind::Heap
        ) {
            self.allocation_count += 1;
        }
    }

    /// Remove a region by base address.
    pub fn remove_region(&mut self, base: u64) {
        if let Some(pos) = self.regions.iter().position(|r| r.base == base) {
            self.regions.remove(pos);
            // Rebuild write bitmaps with corrected indices.
            let mut new_bitmaps = HashMap::new();
            for (old_idx, bm) in self.write_bitmaps.drain() {
                if old_idx == pos {
                    continue;
                }
                let new_idx = if old_idx > pos { old_idx - 1 } else { old_idx };
                new_bitmaps.insert(new_idx, bm);
            }
            self.write_bitmaps = new_bitmaps;
        }
    }

    /// Find the region that contains `addr`, if any.
    #[must_use]
    pub fn find_region(&self, addr: u64) -> Option<&MemoryRegion> {
        self.regions.iter().find(|r| r.contains(addr))
    }

    /// Find the mutable region that contains `addr`.
    fn find_region_mut(&mut self, addr: u64) -> Option<(usize, &mut MemoryRegion)> {
        self.regions
            .iter_mut()
            .enumerate()
            .find(|(_, r)| r.contains(addr))
    }

    /// Record a read access at `addr` of `size` bytes.
    pub fn record_read(&mut self, addr: u64, _size: usize) {
        if let Some((_, r)) = self.find_region_mut(addr) {
            r.record_read();
        }
    }

    /// Record a write access at `addr` of `size` bytes.
    pub fn record_write(&mut self, addr: u64, size: usize) {
        if let Some(idx) = self.regions.iter().position(|r| r.contains(addr)) {
            let region = &mut self.regions[idx];
            let offset = (addr - region.base) as usize;
            let region_size = region.size;
            region.write_count += 1;
            // Update write bitmap.
            if let Some(bitmap) = self.write_bitmaps.get_mut(&idx) {
                for i in offset..((offset + size).min(region_size)) {
                    bitmap[i] = true;
                }
                let written_bytes = bitmap.iter().filter(|&&b| b).count();
                if written_bytes >= region_size {
                    region.fully_written = true;
                }
            }
        }
    }

    /// Record that the PC was at `addr` (marks the containing page as executed).
    pub fn record_execution(&mut self, addr: u64) {
        let page = addr & !0xFFF;
        if !self.executed_pages.contains(&page) {
            self.executed_pages.push(page);
        }
        // Mark region as containing executable content.
        if let Some((_, r)) = self.find_region_mut(addr) {
            r.executable_content = true;
        }
    }

    /// Return all tracked regions.
    #[must_use]
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    /// Return regions of a specific kind.
    #[must_use]
    pub fn regions_of_kind(&self, kind: RegionKind) -> Vec<&MemoryRegion> {
        self.regions.iter().filter(|r| r.kind == kind).collect()
    }

    /// Return the number of allocation events.
    #[must_use]
    pub const fn allocation_count(&self) -> usize {
        self.allocation_count
    }

    /// Return regions that were written and later executed (W^X violation pattern).
    #[must_use]
    pub fn wx_regions(&self) -> Vec<&MemoryRegion> {
        self.regions
            .iter()
            .filter(|r| r.write_count > 0 && r.executable_content)
            .collect()
    }

    /// Return the write bitmap for a region at `base_addr`.
    #[must_use]
    pub fn write_bitmap(&self, base_addr: u64) -> Option<&[bool]> {
        let idx = self.regions.iter().position(|r| r.base == base_addr)?;
        self.write_bitmaps.get(&idx).map(Vec::as_slice)
    }

    /// Return coverage percentage (written bytes / total bytes) for a region.
    #[must_use]
    pub fn write_coverage(&self, base_addr: u64) -> f64 {
        let Some(idx) = self.regions.iter().position(|r| r.base == base_addr) else {
            return 0.0;
        };
        let region = &self.regions[idx];
        if region.size == 0 {
            return 0.0;
        }
        let Some(bitmap) = self.write_bitmaps.get(&idx) else {
            return 0.0;
        };
        let written = bitmap.iter().filter(|&&b| b).count();
        written as f64 / region.size as f64
    }

    /// Produce a human-readable map of the address space.
    #[must_use]
    pub fn layout_summary(&self) -> String {
        let mut sorted = self.regions.clone();
        sorted.sort_by_key(|r| r.base);
        let mut lines = vec!["Memory layout:".to_string()];
        for r in &sorted {
            lines.push(format!(
                "  [{:#010x}..{:#010x}] {:10} {:5}  R:{} W:{} X:{}  '{}'",
                r.base,
                r.end(),
                r.kind.label(),
                r.size,
                if r.is_readable() { 'r' } else { '-' },
                if r.is_writable() { 'w' } else { '-' },
                if r.is_executable() { 'x' } else { '-' },
                r.label,
            ));
        }
        lines.join("\n")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HeapSprayDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Detection threshold configuration for heap spray analysis.
#[derive(Debug, Clone)]
pub struct HeapSprayConfig {
    /// Minimum number of allocation events to trigger suspicion.
    pub min_allocations: usize,
    /// Maximum spread between lowest and highest allocation base that is
    /// still considered a spray (in bytes).
    pub max_spread: u64,
    /// Minimum write coverage (0.0–1.0) that each sprayed region must have.
    pub min_write_coverage: f64,
    /// If `true`, check for NOP-sled-like patterns in written data.
    pub check_nop_sled: bool,
}

impl Default for HeapSprayConfig {
    fn default() -> Self {
        Self {
            min_allocations: 4,
            max_spread: 256 * 1024 * 1024, // 256 MiB
            min_write_coverage: 0.5,
            check_nop_sled: true,
        }
    }
}

/// Result of a heap spray analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeapSprayResult {
    /// Whether a heap spray was detected.
    pub detected: bool,
    /// Addresses of suspected sprayed regions.
    pub sprayed_regions: Vec<u64>,
    /// Confidence score `0.0..=1.0`.
    pub confidence: f64,
    /// Human-readable description of findings.
    pub description: String,
}

/// Analyses a [`MemoryLayoutTracker`] for heap spray patterns.
#[derive(Debug)]
pub struct HeapSprayDetector {
    config: HeapSprayConfig,
}

impl HeapSprayDetector {
    /// Create a detector with the given configuration.
    #[must_use]
    pub fn new(config: HeapSprayConfig) -> Self {
        Self { config }
    }

    /// Create a detector with default thresholds.
    #[must_use]
    pub fn default_config() -> Self {
        Self::new(HeapSprayConfig::default())
    }

    /// Run heap spray detection against a `MemoryLayoutTracker`.
    #[must_use]
    pub fn detect(&self, tracker: &MemoryLayoutTracker) -> HeapSprayResult {
        let allocated: Vec<&MemoryRegion> = tracker
            .regions()
            .iter()
            .filter(|r| {
                matches!(r.kind, RegionKind::Allocated | RegionKind::Heap)
                    && r.size >= 512
            })
            .collect();

        if allocated.len() < self.config.min_allocations {
            return HeapSprayResult {
                detected: false,
                sprayed_regions: vec![],
                confidence: 0.0,
                description: format!(
                    "Only {} allocation(s), need {} for spray detection",
                    allocated.len(),
                    self.config.min_allocations
                ),
            };
        }

        // Check address spread.
        let min_base = allocated.iter().map(|r| r.base).min().unwrap_or(0);
        let max_base = allocated.iter().map(|r| r.base).max().unwrap_or(0);
        let spread = max_base.saturating_sub(min_base);

        if spread > self.config.max_spread {
            return HeapSprayResult {
                detected: false,
                sprayed_regions: vec![],
                confidence: 0.0,
                description: format!(
                    "Spread {spread:#x} exceeds maximum {:#x}",
                    self.config.max_spread
                ),
            };
        }

        // Check write coverage and content similarity.
        let mut well_covered: Vec<u64> = Vec::new();
        let mut total_confidence = 0.0f64;

        for region in &allocated {
            let coverage = tracker.write_coverage(region.base);
            if coverage >= self.config.min_write_coverage {
                well_covered.push(region.base);
                total_confidence += coverage;
            }
        }

        // `min_allocations` is a pub field and may legitimately be 0; the
        // emptiness check must be explicit, or the averaging below divides
        // 0.0 by 0.0 and `f64::min` turns the resulting NaN into 1.0 — maximum
        // confidence on zero evidence.
        if well_covered.is_empty() || well_covered.len() < self.config.min_allocations {
            return HeapSprayResult {
                detected: false,
                sprayed_regions: well_covered,
                confidence: 0.0,
                description: "Write coverage too low for heap spray".to_string(),
            };
        }

        // Check for NOP-sled-like content in write bitmaps.
        let mut nop_sled_bonus = 0.0f64;
        if self.config.check_nop_sled {
            for base in &well_covered {
                if let Some(bm) = tracker.write_bitmap(*base) {
                    // Simple heuristic: if the first 25% of bytes are written
                    // contiguously it looks like a NOP sled.
                    let quarter = bm.len() / 4;
                    if quarter > 0 && bm[..quarter].iter().all(|&b| b) {
                        nop_sled_bonus += 0.1;
                    }
                }
            }
        }

        let confidence = ((total_confidence / well_covered.len() as f64) + nop_sled_bonus).min(1.0);

        HeapSprayResult {
            detected: true,
            sprayed_regions: well_covered.clone(),
            confidence,
            description: format!(
                "Heap spray detected: {} region(s) over {spread:#x} byte spread, confidence={:.2}",
                well_covered.len(),
                confidence
            ),
        }
    }
}

impl Default for HeapSprayDetector {
    fn default() -> Self {
        Self::default_config()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AllocationHistory
// ─────────────────────────────────────────────────────────────────────────────

/// A chronological record of allocation and free events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AllocationEvent {
    Allocate {
        address: u64,
        size: usize,
        sequence: u32,
    },
    Free {
        address: u64,
        sequence: u32,
    },
    ProtectionChange {
        address: u64,
        old_perms: u8,
        new_perms: u8,
        sequence: u32,
    },
}

/// Tracks the complete allocation lifecycle.
#[derive(Debug, Default)]
pub struct AllocationHistory {
    events: Vec<AllocationEvent>,
    next_seq: u32,
}

impl AllocationHistory {
    /// Create an empty history.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an allocation.
    pub fn record_alloc(&mut self, address: u64, size: usize) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.events.push(AllocationEvent::Allocate { address, size, sequence: seq });
    }

    /// Record a free.
    pub fn record_free(&mut self, address: u64) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.events.push(AllocationEvent::Free { address, sequence: seq });
    }

    /// Record a protection change.
    pub fn record_protect(&mut self, address: u64, old_perms: u8, new_perms: u8) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.events.push(AllocationEvent::ProtectionChange {
            address,
            old_perms,
            new_perms,
            sequence: seq,
        });
    }

    /// Return all events.
    #[must_use]
    pub fn events(&self) -> &[AllocationEvent] {
        &self.events
    }

    /// Return all addresses that were allocated and later freed (no longer live).
    #[must_use]
    pub fn freed_addresses(&self) -> Vec<u64> {
        let mut allocated: Vec<u64> = Vec::new();
        let mut freed: Vec<u64> = Vec::new();
        for ev in &self.events {
            match ev {
                AllocationEvent::Allocate { address, .. } => allocated.push(*address),
                AllocationEvent::Free { address, .. } => freed.push(*address),
                AllocationEvent::ProtectionChange { .. } => {}
            }
        }
        freed
            .into_iter()
            .filter(|a| allocated.contains(a))
            .collect()
    }

    /// Return addresses whose protection changed from non-executable to executable.
    #[must_use]
    pub fn wx_transitions(&self) -> Vec<u64> {
        let mut result = Vec::new();
        for ev in &self.events {
            if let AllocationEvent::ProtectionChange {
                address,
                old_perms,
                new_perms,
                ..
            } = ev
            {
                let was_nx = old_perms & 0b001 == 0;
                let now_x = new_perms & 0b001 != 0;
                if was_nx && now_x {
                    result.push(*address);
                }
            }
        }
        result
    }

    /// Return all live allocations (allocated but not yet freed).
    #[must_use]
    pub fn live_allocations(&self) -> Vec<(u64, usize)> {
        let mut live: HashMap<u64, usize> = HashMap::new();
        for ev in &self.events {
            match ev {
                AllocationEvent::Allocate { address, size, .. } => {
                    live.insert(*address, *size);
                }
                AllocationEvent::Free { address, .. } => {
                    live.remove(address);
                }
                AllocationEvent::ProtectionChange { .. } => {}
            }
        }
        let mut v: Vec<(u64, usize)> = live.into_iter().collect();
        v.sort_by_key(|(a, _)| *a);
        v
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_region(base: u64, size: usize, kind: RegionKind) -> MemoryRegion {
        MemoryRegion::new(base, size, kind, "test", 0b110) // rw
    }

    #[test]
    fn test_region_contains() {
        let r = make_region(0x1000, 0x1000, RegionKind::Code);
        assert!(r.contains(0x1000));
        assert!(r.contains(0x1FFF));
        assert!(!r.contains(0x2000));
        assert!(!r.contains(0x0FFF));
    }

    #[test]
    fn test_region_end() {
        let r = make_region(0x1000, 0x1000, RegionKind::Code);
        assert_eq!(r.end(), 0x2000);
    }

    #[test]
    fn test_region_perms() {
        let r = MemoryRegion::new(0, 0x1000, RegionKind::Code, "", 0b111);
        assert!(r.is_readable());
        assert!(r.is_writable());
        assert!(r.is_executable());
    }

    #[test]
    fn test_tracker_add_and_find() {
        let mut t = MemoryLayoutTracker::new();
        t.add_region(make_region(0x1000, 0x1000, RegionKind::Code));
        assert!(t.find_region(0x1500).is_some());
        assert!(t.find_region(0x2000).is_none());
    }

    #[test]
    fn test_tracker_record_write_updates_count() {
        let mut t = MemoryLayoutTracker::new();
        t.add_region(make_region(0x1000, 64, RegionKind::Heap));
        t.record_write(0x1000, 4);
        let r = t.find_region(0x1000).unwrap();
        assert_eq!(r.write_count, 1);
    }

    #[test]
    fn test_tracker_write_coverage() {
        let mut t = MemoryLayoutTracker::new();
        t.add_region(make_region(0x2000, 100, RegionKind::Allocated));
        for i in 0u64..50 {
            t.record_write(0x2000 + i, 1);
        }
        let cov = t.write_coverage(0x2000);
        assert!((cov - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_tracker_fully_written() {
        let mut t = MemoryLayoutTracker::new();
        t.add_region(make_region(0x3000, 10, RegionKind::Allocated));
        for i in 0u64..10 {
            t.record_write(0x3000 + i, 1);
        }
        let r = t.find_region(0x3000).unwrap();
        assert!(r.fully_written);
    }

    #[test]
    fn test_tracker_record_execution_marks_executable() {
        let mut t = MemoryLayoutTracker::new();
        t.add_region(make_region(0x4000, 0x1000, RegionKind::Allocated));
        t.record_execution(0x4010);
        let r = t.find_region(0x4000).unwrap();
        assert!(r.executable_content);
    }

    #[test]
    fn test_tracker_wx_regions() {
        let mut t = MemoryLayoutTracker::new();
        t.add_region(make_region(0x5000, 0x1000, RegionKind::Allocated));
        t.record_write(0x5000, 4);
        t.record_execution(0x5004);
        let wx = t.wx_regions();
        assert_eq!(wx.len(), 1);
    }

    #[test]
    fn test_tracker_remove_region() {
        let mut t = MemoryLayoutTracker::new();
        t.add_region(make_region(0x1000, 0x1000, RegionKind::Code));
        t.add_region(make_region(0x2000, 0x1000, RegionKind::Stack));
        t.remove_region(0x1000);
        assert!(t.find_region(0x1000).is_none());
        assert!(t.find_region(0x2000).is_some());
    }

    #[test]
    fn test_spray_detector_not_enough_allocs() {
        let mut tracker = MemoryLayoutTracker::new();
        tracker.add_region(make_region(0x1000, 0x1000, RegionKind::Allocated));
        let d = HeapSprayDetector::default();
        let result = d.detect(&tracker);
        assert!(!result.detected);
    }

    #[test]
    fn test_spray_detector_detects_spray() {
        let mut tracker = MemoryLayoutTracker::new();
        for i in 0u64..6 {
            let base = 0x1_0000 + i * 0x1000;
            tracker.add_region(make_region(base, 0x1000, RegionKind::Allocated));
            // Write 75% of each region.
            for j in 0u64..0xC00 {
                tracker.record_write(base + j, 1);
            }
        }
        let d = HeapSprayDetector::default();
        let result = d.detect(&tracker);
        assert!(result.detected);
        assert!(result.confidence > 0.0);
    }

    #[test]
    fn test_spray_confidence_is_never_nan_with_zero_min_allocations() {
        // `min_allocations` is pub and may be 0. With no region meeting the
        // write-coverage bar, the averaging step would divide 0.0 by 0.0; since
        // `f64::min` discards NaN, `NaN.min(1.0)` is 1.0 — maximum confidence on
        // zero evidence. The result must be "not detected", never a NaN or 1.0.
        let mut tracker = MemoryLayoutTracker::new();
        for i in 0u64..3 {
            tracker.add_region(make_region(0x1_0000 + i * 0x1000, 0x1000, RegionKind::Allocated));
        }
        let d = HeapSprayDetector::new(HeapSprayConfig {
            min_allocations: 0,
            min_write_coverage: 0.5,
            ..HeapSprayConfig::default()
        });
        let result = d.detect(&tracker);
        assert!(
            !result.confidence.is_nan(),
            "confidence must never be NaN, got {}",
            result.confidence
        );
        assert!(!result.detected, "no written region means no spray");
        assert_eq!(result.confidence, 0.0);
    }

    #[test]
    fn test_allocation_history_live() {
        let mut h = AllocationHistory::new();
        h.record_alloc(0x1000, 0x1000);
        h.record_alloc(0x2000, 0x2000);
        h.record_free(0x1000);
        let live = h.live_allocations();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].0, 0x2000);
    }

    #[test]
    fn test_allocation_history_wx_transitions() {
        let mut h = AllocationHistory::new();
        h.record_protect(0x3000, 0b110, 0b111); // rw → rwx
        let wx = h.wx_transitions();
        assert_eq!(wx.len(), 1);
        assert_eq!(wx[0], 0x3000);
    }

    #[test]
    fn test_allocation_history_no_wx_when_already_executable() {
        let mut h = AllocationHistory::new();
        h.record_protect(0x4000, 0b111, 0b111); // already executable
        let wx = h.wx_transitions();
        assert!(wx.is_empty());
    }

    #[test]
    fn test_allocation_history_freed_addresses() {
        let mut h = AllocationHistory::new();
        h.record_alloc(0x1000, 100);
        h.record_free(0x1000);
        let freed = h.freed_addresses();
        assert!(freed.contains(&0x1000));
    }

    #[test]
    fn test_region_kind_labels() {
        assert_eq!(RegionKind::Code.label(), "CODE");
        assert_eq!(RegionKind::Stack.label(), "STACK");
        assert_eq!(RegionKind::Allocated.label(), "ALLOC");
    }

    #[test]
    fn test_layout_summary_non_empty() {
        let mut t = MemoryLayoutTracker::new();
        t.add_region(make_region(0x1000, 0x1000, RegionKind::Code));
        let s = t.layout_summary();
        assert!(s.contains("CODE"));
    }

    #[test]
    fn test_tracker_allocation_count() {
        let mut t = MemoryLayoutTracker::new();
        t.add_region(make_region(0x1000, 0x1000, RegionKind::Allocated));
        t.add_region(make_region(0x2000, 0x1000, RegionKind::Allocated));
        t.add_region(make_region(0x3000, 0x1000, RegionKind::Code));
        assert_eq!(t.allocation_count(), 2);
    }

    #[test]
    fn test_tracker_regions_of_kind() {
        let mut t = MemoryLayoutTracker::new();
        t.add_region(make_region(0x1000, 0x1000, RegionKind::Code));
        t.add_region(make_region(0x2000, 0x1000, RegionKind::Stack));
        t.add_region(make_region(0x3000, 0x1000, RegionKind::Heap));
        assert_eq!(t.regions_of_kind(RegionKind::Code).len(), 1);
        assert_eq!(t.regions_of_kind(RegionKind::Stack).len(), 1);
        assert_eq!(t.regions_of_kind(RegionKind::Heap).len(), 1);
    }
}
