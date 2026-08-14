//! SMC region tracker — record and query write-then-execute events.
//!
//! [`SmcRegionTracker`] maintains a list of [`SmcRegion`] descriptors produced
//! by write-monitoring passes.  Each time a memory region is written by the
//! unpacker and later executed, a [`ModificationEvent`] is appended to the
//! region's history.  Downstream passes consume this timeline to pinpoint
//! decryptors, staging buffers, and final payloads.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ModificationEvent
// ---------------------------------------------------------------------------

/// A single write or execute event observed on a tracked region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModificationEvent {
    /// Type of event.
    pub kind: EventKind,
    /// Virtual address where the modification begins.
    pub address: u64,
    /// Number of bytes affected.
    pub size: usize,
    /// The bytes written (None for execute events or when capture is disabled).
    pub bytes: Option<Vec<u8>>,
    /// Monotonically increasing sequence number within this tracking session.
    pub seq: u64,
    /// Optional tag from the monitoring layer (e.g. thread-id, hook name).
    pub tag: Option<String>,
}

impl ModificationEvent {
    /// Create a write event.
    #[must_use]
    pub const fn write(address: u64, size: usize, bytes: Option<Vec<u8>>, seq: u64) -> Self {
        Self { kind: EventKind::Write, address, size, bytes, seq, tag: None }
    }

    /// Create an execute event.
    #[must_use]
    pub const fn execute(address: u64, size: usize, seq: u64) -> Self {
        Self { kind: EventKind::Execute, address, size, bytes: None, seq, tag: None }
    }

    /// Attach a tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }
}

impl fmt::Display for ModificationEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} va={:#x} size={}",
            self.seq, self.kind, self.address, self.size
        )
    }
}

/// Kind of a [`ModificationEvent`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    /// A write to the region was observed.
    Write,
    /// An execute from the region was observed.
    Execute,
    /// The region was unmapped / freed.
    Freed,
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Write   => write!(f, "WRITE"),
            Self::Execute => write!(f, "EXEC"),
            Self::Freed   => write!(f, "FREE"),
        }
    }
}

// ---------------------------------------------------------------------------
// SmcRegion
// ---------------------------------------------------------------------------

/// A memory region that has been both written and executed (SMC pattern).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmcRegion {
    /// Unique identifier for this region.
    pub id: u64,
    /// Virtual address of the region base.
    pub base: u64,
    /// Length of the region in bytes.
    pub size: usize,
    /// All events recorded against this region, in sequence order.
    pub events: Vec<ModificationEvent>,
    /// True when the region has been executed at least once after a write.
    pub confirmed_smc: bool,
    /// Optional label provided by the analyst or monitoring layer.
    pub label: Option<String>,
    /// Entropy measured after the last write event (bits/byte).
    pub entropy: f64,
}

impl SmcRegion {
    /// Create a new, empty region.
    #[must_use]
    pub const fn new(id: u64, base: u64, size: usize) -> Self {
        Self {
            id,
            base,
            size,
            events: Vec::new(),
            confirmed_smc: false,
            label: None,
            entropy: 0.0,
        }
    }

    /// Returns `true` if the address falls within this region.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base.saturating_add(self.size as u64)
    }

    /// Returns `true` if this region overlaps another.
    #[must_use]
    pub const fn overlaps(&self, other: &Self) -> bool {
        let self_end  = self.base.saturating_add(self.size as u64);
        let other_end = other.base.saturating_add(other.size as u64);
        self.base < other_end && other.base < self_end
    }

    /// Append an event and update the `confirmed_smc` flag.
    pub fn push_event(&mut self, event: ModificationEvent) {
        if event.kind == EventKind::Execute {
            let has_write = self.events.iter().any(|e| e.kind == EventKind::Write);
            if has_write {
                self.confirmed_smc = true;
            }
        }
        self.events.push(event);
    }

    /// Number of write events.
    #[must_use]
    pub fn write_count(&self) -> usize {
        self.events.iter().filter(|e| e.kind == EventKind::Write).count()
    }

    /// Number of execute events.
    #[must_use]
    pub fn execute_count(&self) -> usize {
        self.events.iter().filter(|e| e.kind == EventKind::Execute).count()
    }

    /// Total bytes written across all write events.
    #[must_use]
    pub fn total_bytes_written(&self) -> usize {
        self.events
            .iter()
            .filter(|e| e.kind == EventKind::Write)
            .map(|e| e.size)
            .sum()
    }

    /// Collect all captured write bytes in sequence order.
    #[must_use]
    pub fn reconstruct_bytes(&self) -> Vec<u8> {
        self.events
            .iter()
            .filter_map(|e| e.bytes.as_ref())
            .flat_map(|b| b.iter().copied())
            .collect()
    }
}

impl fmt::Display for SmcRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SmcRegion#{} base={:#x} size={} smc={} writes={} execs={}",
            self.id,
            self.base,
            self.size,
            self.confirmed_smc,
            self.write_count(),
            self.execute_count()
        )
    }
}

// ---------------------------------------------------------------------------
// SmcRegionTracker
// ---------------------------------------------------------------------------

/// Tracks SMC regions and their modification history.
///
/// The tracker assigns a monotonically increasing sequence number to every
/// event and maintains an index from base address to region for fast lookup.
pub struct SmcRegionTracker {
    regions: Vec<SmcRegion>,
    address_index: HashMap<u64, usize>, // base → vec index
    next_id: u64,
    next_seq: u64,
    /// When true, write payloads are captured in [`ModificationEvent::bytes`].
    pub capture_bytes: bool,
}

impl Default for SmcRegionTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SmcRegionTracker {
    /// Create a new tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
            address_index: HashMap::new(),
            next_id: 1,
            next_seq: 0,
            capture_bytes: false,
        }
    }

    /// Enable payload capture on write events.
    #[must_use]
    pub const fn with_byte_capture(mut self) -> Self {
        self.capture_bytes = true;
        self
    }

    /// Register a new region.  Returns its assigned id.
    pub fn register(&mut self, base: u64, size: usize) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let idx = self.regions.len();
        self.regions.push(SmcRegion::new(id, base, size));
        self.address_index.insert(base, idx);
        id
    }

    /// Record a write event to the region containing `address`.
    ///
    /// Returns `None` if no tracked region contains `address`.
    pub fn record_write(&mut self, address: u64, bytes: &[u8]) -> Option<u64> {
        let idx = self.find_region_idx(address)?;
        let seq = self.next_seq();
        let payload = if self.capture_bytes { Some(bytes.to_vec()) } else { None };
        let event = ModificationEvent::write(address, bytes.len(), payload, seq);
        self.regions[idx].push_event(event);
        Some(seq)
    }

    /// Record an execute event at the region containing `address`.
    pub fn record_execute(&mut self, address: u64, size: usize) -> Option<u64> {
        let idx = self.find_region_idx(address)?;
        let seq = self.next_seq();
        let event = ModificationEvent::execute(address, size, seq);
        self.regions[idx].push_event(event);
        Some(seq)
    }

    /// Returns all confirmed SMC regions.
    #[must_use]
    pub fn confirmed_regions(&self) -> Vec<&SmcRegion> {
        self.regions.iter().filter(|r| r.confirmed_smc).collect()
    }

    /// Returns all tracked regions.
    #[must_use]
    pub fn all_regions(&self) -> &[SmcRegion] {
        &self.regions
    }

    /// Look up a region by its base address.
    #[must_use]
    pub fn get_by_base(&self, base: u64) -> Option<&SmcRegion> {
        self.address_index.get(&base).map(|&idx| &self.regions[idx])
    }

    /// Look up a region by id.
    #[must_use]
    pub fn get_by_id(&self, id: u64) -> Option<&SmcRegion> {
        self.regions.iter().find(|r| r.id == id)
    }

    /// Total number of tracked regions.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.regions.len()
    }

    /// Returns `true` when no regions are tracked.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Produce a human-readable report.
    #[must_use]
    pub fn report(&self) -> String {
        let mut lines = vec![format!(
            "SmcRegionTracker: {} regions, {} confirmed SMC",
            self.regions.len(),
            self.confirmed_regions().len()
        )];
        for r in &self.regions {
            lines.push(format!("  {r}"));
        }
        lines.join("\n")
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn find_region_idx(&self, addr: u64) -> Option<usize> {
        // Fast path: exact base match
        if let Some(&idx) = self.address_index.get(&addr) {
            return Some(idx);
        }
        // Slow path: linear scan for containment
        self.regions.iter().position(|r| r.contains(addr))
    }

    #[must_use]
    const fn next_seq(&mut self) -> u64 {
        let s = self.next_seq;
        self.next_seq += 1;
        s
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_get_by_base() {
        let mut tracker = SmcRegionTracker::new();
        let id = tracker.register(0x1000, 0x100);
        let region = tracker.get_by_base(0x1000).unwrap();
        assert_eq!(region.id, id);
        assert_eq!(region.base, 0x1000);
    }

    #[test]
    fn test_record_write_in_region() {
        let mut tracker = SmcRegionTracker::new().with_byte_capture();
        tracker.register(0x2000, 0x200);
        let seq = tracker.record_write(0x2080, &[0xAA; 16]);
        assert!(seq.is_some());
        let r = tracker.get_by_base(0x2000).unwrap();
        assert_eq!(r.write_count(), 1);
    }

    #[test]
    fn test_record_execute_confirms_smc() {
        let mut tracker = SmcRegionTracker::new();
        tracker.register(0x3000, 0x100);
        tracker.record_write(0x3000, &[0x90; 8]);
        tracker.record_execute(0x3000, 8);
        let r = tracker.get_by_base(0x3000).unwrap();
        assert!(r.confirmed_smc);
    }

    #[test]
    fn test_execute_without_prior_write_not_smc() {
        let mut tracker = SmcRegionTracker::new();
        tracker.register(0x4000, 0x100);
        tracker.record_execute(0x4000, 8);
        let r = tracker.get_by_base(0x4000).unwrap();
        assert!(!r.confirmed_smc);
    }

    #[test]
    fn test_confirmed_regions() {
        let mut tracker = SmcRegionTracker::new();
        tracker.register(0x1000, 0x100);
        tracker.register(0x2000, 0x100);
        tracker.record_write(0x1000, &[0x00; 4]);
        tracker.record_execute(0x1000, 4);
        assert_eq!(tracker.confirmed_regions().len(), 1);
    }

    #[test]
    fn test_write_outside_region_returns_none() {
        let mut tracker = SmcRegionTracker::new();
        tracker.register(0x5000, 0x100);
        let r = tracker.record_write(0x9999, &[0x00; 4]);
        assert!(r.is_none());
    }

    #[test]
    fn test_region_contains() {
        let r = SmcRegion::new(1, 0x1000, 0x100);
        assert!(r.contains(0x1000));
        assert!(r.contains(0x10FF));
        assert!(!r.contains(0x1100));
        assert!(!r.contains(0x0FFF));
    }

    #[test]
    fn test_region_overlaps() {
        let a = SmcRegion::new(1, 0x1000, 0x100);
        let b = SmcRegion::new(2, 0x1080, 0x100);
        let c = SmcRegion::new(3, 0x2000, 0x100);
        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c));
    }

    #[test]
    fn test_reconstruct_bytes() {
        let mut r = SmcRegion::new(1, 0x1000, 0x100);
        r.push_event(ModificationEvent::write(0x1000, 4, Some(vec![0xAA, 0xBB, 0xCC, 0xDD]), 0));
        r.push_event(ModificationEvent::write(0x1004, 2, Some(vec![0xEE, 0xFF]), 1));
        let bytes = r.reconstruct_bytes();
        assert_eq!(bytes, vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_event_display() {
        let e = ModificationEvent::write(0x1000, 16, None, 42);
        let s = e.to_string();
        assert!(s.contains("WRITE"));
        assert!(s.contains("42"));
    }

    #[test]
    fn test_region_display() {
        let r = SmcRegion::new(7, 0xDEAD_0000, 0x200);
        let s = r.to_string();
        assert!(s.contains("SmcRegion#7"));
        assert!(s.contains("0xdead0000"));
    }

    #[test]
    fn test_report_non_empty() {
        let mut tracker = SmcRegionTracker::new();
        tracker.register(0x1000, 0x100);
        let report = tracker.report();
        assert!(report.contains("SmcRegionTracker"));
        assert!(report.contains("SmcRegion#1"));
    }

    #[test]
    fn test_tracker_is_empty_initially() {
        let tracker = SmcRegionTracker::new();
        assert!(tracker.is_empty());
        assert_eq!(tracker.len(), 0);
    }

    #[test]
    fn test_sequence_numbers_monotone() {
        let mut tracker = SmcRegionTracker::new();
        tracker.register(0x1000, 0x200);
        let s0 = tracker.record_write(0x1000, &[0x00; 4]).unwrap();
        let s1 = tracker.record_write(0x1010, &[0x01; 4]).unwrap();
        assert!(s1 > s0);
    }
}
