//! Detect self-modifying code: track write-then-execute patterns, memory page
//! transitions, and SMC regions.
//!
//! This module provides [`SmcWriteTracker`] — a dynamic analysis helper that
//! records every memory write and execution event, then identifies addresses
//! that were written before being executed (the write-then-execute pattern
//! that characterises SMC).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// WriteXorExecute — a write-then-execute event pair
// ─────────────────────────────────────────────────────────────────────────────

/// A write event recorded by the write-execute tracker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteEvent {
    /// Program counter of the instruction that performed the write.
    pub write_pc: u64,
    /// Target memory address that was written.
    pub target_addr: u64,
    /// Byte value written.
    pub value: u8,
    /// Timestamp (instruction count or nanoseconds) of the write.
    pub timestamp: u64,
}

/// An execution event: the CPU fetched an instruction at `exec_addr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecEvent {
    /// The address that was executed.
    pub exec_addr: u64,
    /// Program counter at the moment of execution.
    pub pc: u64,
    /// Timestamp of the execution event.
    pub timestamp: u64,
}

/// A confirmed write-then-execute pair: bytes at `target_addr` were written
/// before they were executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteXorExecute {
    /// The write event.
    pub write: WriteEvent,
    /// The execution event.
    pub exec: ExecEvent,
    /// Number of additional writes to the same address before execution.
    pub write_count: u32,
}

impl fmt::Display for WriteXorExecute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SMC: write @ pc={:#x} → addr={:#x} (×{}) then exec @ pc={:#x}",
            self.write.write_pc,
            self.write.target_addr,
            self.write_count,
            self.exec.pc
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcRegion — a contiguous range of addresses that were SMC-modified
// ─────────────────────────────────────────────────────────────────────────────

/// A contiguous virtual address range that was written before being executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmcRegion {
    /// First address of the region.
    pub start: u64,
    /// Exclusive end address.
    pub end: u64,
    /// Number of write events in this region.
    pub write_count: u64,
    /// The final reconstructed bytes (last-write wins).
    pub bytes: Vec<u8>,
}

impl SmcRegion {
    /// Length of the region in bytes.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// True if the region is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// True if `addr` falls within this region.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}

impl fmt::Display for SmcRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SmcRegion [{:#x}, {:#x}) len={} writes={}",
            self.start,
            self.end,
            self.len(),
            self.write_count
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PageState — tracks the protection state of a 4 KiB page
// ─────────────────────────────────────────────────────────────────────────────

const PAGE_SIZE: u64 = 4096;

/// Current permission state of a virtual memory page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PageState {
    /// No data seen for this page.
    Unknown,
    /// The page has been written to.
    Dirty,
    /// The page has been executed at least once.
    Executed,
    /// The page was written then executed (confirmed SMC).
    WrittenThenExecuted,
}

impl fmt::Display for PageState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Unknown => "unknown",
            Self::Dirty => "dirty",
            Self::Executed => "executed",
            Self::WrittenThenExecuted => "written+executed (SMC)",
        };
        write!(f, "{s}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcEvent — a unified event type
// ─────────────────────────────────────────────────────────────────────────────

/// A unified SMC-relevant event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SmcEvent {
    Write(WriteEvent),
    Exec(ExecEvent),
    Confirmed(WriteXorExecute),
}

impl fmt::Display for SmcEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Write(w) => write!(
                f,
                "WRITE pc={:#x} addr={:#x} val={:#04x} t={}",
                w.write_pc, w.target_addr, w.value, w.timestamp
            ),
            Self::Exec(e) => write!(
                f,
                "EXEC addr={:#x} pc={:#x} t={}",
                e.exec_addr, e.pc, e.timestamp
            ),
            Self::Confirmed(c) => write!(f, "{c}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SmcWriteTracker
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the write tracker.
#[derive(Debug, Clone)]
pub struct SmcWriteTrackerConfig {
    /// Maximum number of write events to buffer before eviction (0 = unlimited).
    pub max_write_events: usize,
    /// If `true`, keep the full write-event history.
    pub retain_write_history: bool,
    /// Page size to use for page-state tracking.
    pub page_size: u64,
}

impl Default for SmcWriteTrackerConfig {
    fn default() -> Self {
        Self {
            max_write_events: 1_000_000,
            retain_write_history: true,
            page_size: PAGE_SIZE,
        }
    }
}

/// Statistics maintained by [`SmcWriteTracker`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SmcWriteTrackerStats {
    /// Total write events recorded.
    pub write_events: u64,
    /// Total execution events recorded.
    pub exec_events: u64,
    /// Total confirmed SMC pairs found.
    pub smc_pairs: u64,
    /// Unique addresses that were written.
    pub unique_write_addrs: usize,
    /// Unique addresses that were executed.
    pub unique_exec_addrs: usize,
    /// Number of pages in the `WrittenThenExecuted` state.
    pub smc_pages: usize,
}

/// Tracks write-then-execute patterns across a dynamic execution trace.
///
/// For each byte that is written and later executed, a [`WriteXorExecute`]
/// event is produced.  Page-level state is also maintained to detect when an
/// entire 4 KiB page transitions from writable to executable.
#[derive(Debug)]
pub struct SmcWriteTracker {
    /// All write events indexed by target address.
    write_map: HashMap<u64, Vec<WriteEvent>>,
    /// Set of addresses that have been executed.
    exec_set: HashSet<u64>,
    /// All execution events.
    exec_events: Vec<ExecEvent>,
    /// Confirmed SMC pairs.
    confirmed: Vec<WriteXorExecute>,
    /// Per-page state.
    page_states: BTreeMap<u64, PageState>,
    /// Configuration.
    pub config: SmcWriteTrackerConfig,
    /// Statistics.
    pub stats: SmcWriteTrackerStats,
    /// Event log (optional).
    event_log: Vec<SmcEvent>,
    /// Running timestamp counter.
    timestamp: u64,
}

impl SmcWriteTracker {
    /// Create a new tracker with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            write_map: HashMap::new(),
            exec_set: HashSet::new(),
            exec_events: Vec::new(),
            confirmed: Vec::new(),
            page_states: BTreeMap::new(),
            config: SmcWriteTrackerConfig::default(),
            stats: SmcWriteTrackerStats::default(),
            event_log: Vec::new(),
            timestamp: 0,
        }
    }

    /// Record a memory write from instruction at `write_pc` to `target_addr`.
    pub fn record_write(&mut self, write_pc: u64, target_addr: u64, value: u8) {
        self.timestamp += 1;
        let ev = WriteEvent {
            write_pc,
            target_addr,
            value,
            timestamp: self.timestamp,
        };

        if self.config.retain_write_history {
            self.event_log.push(SmcEvent::Write(ev));
        }

        self.write_map
            .entry(target_addr)
            .or_default()
            .push(ev);

        self.stats.write_events += 1;
        self.stats.unique_write_addrs = self.write_map.len();

        // Update page state.
        let page = self.page_base(target_addr);
        let ps = self.page_states.entry(page).or_insert(PageState::Unknown);
        if *ps == PageState::Unknown || *ps == PageState::Executed {
            *ps = PageState::Dirty;
        }

        // Enforce write-event limit.
        if self.config.max_write_events > 0 {
            let total: usize = self.write_map.values().map(Vec::len).sum();
            if total > self.config.max_write_events {
                // Evict oldest writes from the largest bucket.
                if let Some(bucket) = self.write_map.values_mut().max_by_key(|v| v.len()) && bucket.len() > 1 {
                    bucket.remove(0);
                }
            }
        }
    }

    /// Record that the CPU executed an instruction at `exec_addr`.
    ///
    /// If `exec_addr` was previously written to, a [`WriteXorExecute`] pair is
    /// confirmed and added to the internal list.
    pub fn record_exec(&mut self, pc: u64, exec_addr: u64) {
        self.timestamp += 1;
        let ev = ExecEvent {
            exec_addr,
            pc,
            timestamp: self.timestamp,
        };

        if self.config.retain_write_history {
            self.event_log.push(SmcEvent::Exec(ev));
        }

        self.exec_set.insert(exec_addr);
        self.exec_events.push(ev);
        self.stats.exec_events += 1;
        self.stats.unique_exec_addrs = self.exec_set.len();

        // Check for write-then-execute.
        if let Some(writes) = self.write_map.get(&exec_addr) && !writes.is_empty() {
            let first_write = writes[0];
            let confirmed = WriteXorExecute {
                write: first_write,
                exec: ev,
                write_count: u32::try_from(writes.len()).unwrap_or(u32::MAX),
            };
            self.stats.smc_pairs += 1;
            if self.config.retain_write_history {
                self.event_log.push(SmcEvent::Confirmed(confirmed.clone()));
            }
            self.confirmed.push(confirmed);

            // Update page state.
            let page = self.page_base(exec_addr);
            self.page_states.insert(page, PageState::WrittenThenExecuted);
        }

        // Update page state if not already SMC.
        let page = self.page_base(exec_addr);
        let ps = self.page_states.entry(page).or_insert(PageState::Unknown);
        if *ps == PageState::Unknown {
            *ps = PageState::Executed;
        }
        self.stats.smc_pages = self
            .page_states
            .values()
            .filter(|&&s| s == PageState::WrittenThenExecuted)
            .count();
    }

    /// Check whether `addr` was previously written to.
    #[must_use]
    pub fn is_written(&self, addr: u64) -> bool {
        self.write_map.contains_key(&addr)
    }

    /// Check whether `addr` was executed at some point.
    #[must_use]
    pub fn is_executed(&self, addr: u64) -> bool {
        self.exec_set.contains(&addr)
    }

    /// All confirmed write-then-execute pairs.
    #[must_use]
    pub fn confirmed_pairs(&self) -> &[WriteXorExecute] {
        &self.confirmed
    }

    /// Compute contiguous SMC regions from confirmed pairs.
    ///
    /// Addresses within `gap_threshold` bytes of each other are merged into a
    /// single region.
    #[must_use]
    pub fn compute_regions(&self, gap_threshold: u64) -> Vec<SmcRegion> {
        if self.confirmed.is_empty() {
            return Vec::new();
        }

        // Collect (address, byte) pairs from all confirmed writes.
        let mut addr_values: BTreeMap<u64, (u8, u64)> = BTreeMap::new();
        for pair in &self.confirmed {
            let writes = self.write_map.get(&pair.write.target_addr);
            let (last_val, count) = writes.map_or((0u8, 0u64), |ws| {
                (
                    ws.last().map_or(0, |w| w.value),
                    ws.len() as u64,
                )
            });
            addr_values.insert(pair.write.target_addr, (last_val, count));
        }

        let mut regions: Vec<SmcRegion> = Vec::new();
        let mut iter = addr_values.iter().peekable();

        while let Some((&start_addr, &(val, cnt))) = iter.next() {
            let mut end_addr = start_addr + 1;
            let mut bytes = vec![val];
            let mut write_count = cnt;

            while let Some(&(&next_addr, &(next_val, next_cnt))) = iter.peek() {
                if next_addr <= end_addr + gap_threshold {
                    // Fill any gap with zeros.
                    let gap = usize::try_from(next_addr.saturating_sub(end_addr)).unwrap_or(usize::MAX);
                    bytes.extend(std::iter::repeat_n(0u8, gap));
                    bytes.push(next_val);
                    write_count += next_cnt;
                    end_addr = next_addr + 1;
                    iter.next();
                } else {
                    break;
                }
            }

            regions.push(SmcRegion {
                start: start_addr,
                end: end_addr,
                write_count,
                bytes,
            });
        }

        regions
    }

    /// Return the page state for the page containing `addr`.
    #[must_use]
    pub fn page_state(&self, addr: u64) -> PageState {
        let page = self.page_base(addr);
        self.page_states.get(&page).copied().unwrap_or(PageState::Unknown)
    }

    /// Return all pages that have been confirmed as SMC (written then executed).
    #[must_use]
    pub fn smc_pages(&self) -> Vec<u64> {
        self.page_states
            .iter()
            .filter(|&(_, s)| *s == PageState::WrittenThenExecuted)
            .map(|(&p, _)| p)
            .collect()
    }

    /// Clear all recorded events and state.
    pub fn clear(&mut self) {
        self.write_map.clear();
        self.exec_set.clear();
        self.exec_events.clear();
        self.confirmed.clear();
        self.page_states.clear();
        self.event_log.clear();
        self.stats = SmcWriteTrackerStats::default();
        self.timestamp = 0;
    }

    /// All recorded events (requires `retain_write_history = true`).
    #[must_use]
    pub fn event_log(&self) -> &[SmcEvent] {
        &self.event_log
    }

    /// Reconstruct a byte-level memory snapshot of all written addresses.
    ///
    /// Returns a map from address to the last byte written at that address.
    #[must_use]
    pub fn memory_snapshot(&self) -> HashMap<u64, u8> {
        self.write_map
            .iter()
            .filter_map(|(&addr, writes)| writes.last().map(|w| (addr, w.value)))
            .collect()
    }

    const fn page_base(&self, addr: u64) -> u64 {
        (addr / self.config.page_size) * self.config.page_size
    }
}

impl Default for SmcWriteTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_smc_when_not_executed() {
        let mut t = SmcWriteTracker::new();
        t.record_write(0x1000, 0x2000, 0xAA);
        assert!(t.confirmed_pairs().is_empty());
        assert!(t.is_written(0x2000));
        assert!(!t.is_executed(0x2000));
    }

    #[test]
    fn smc_confirmed_on_exec() {
        let mut t = SmcWriteTracker::new();
        t.record_write(0x1000, 0x2000, 0xEB);
        t.record_write(0x1000, 0x2001, 0x0F);
        t.record_exec(0x2000, 0x2000);
        assert_eq!(t.confirmed_pairs().len(), 1);
        assert_eq!(t.stats.smc_pairs, 1);
    }

    #[test]
    fn exec_without_prior_write_not_confirmed() {
        let mut t = SmcWriteTracker::new();
        t.record_exec(0x4000, 0x4000);
        assert!(t.confirmed_pairs().is_empty());
    }

    #[test]
    fn compute_regions_contiguous() {
        let mut t = SmcWriteTracker::new();
        for i in 0..10u64 {
            t.record_write(0x1000, 0x2000 + i, (i as u8) ^ 0xCC);
            t.record_exec(0x2000 + i, 0x2000 + i);
        }
        let regions = t.compute_regions(4);
        assert!(!regions.is_empty());
        let r = &regions[0];
        assert!(r.len() >= 10);
    }

    #[test]
    fn page_state_transitions() {
        let mut t = SmcWriteTracker::new();
        t.record_write(0x1000, 0x4000, 0x90);
        assert_eq!(t.page_state(0x4000), PageState::Dirty);
        t.record_exec(0x4000, 0x4000);
        assert_eq!(t.page_state(0x4000), PageState::WrittenThenExecuted);
        assert_eq!(t.smc_pages().len(), 1);
    }

    #[test]
    fn memory_snapshot_last_write_wins() {
        let mut t = SmcWriteTracker::new();
        t.record_write(0, 0x5000, 0x11);
        t.record_write(0, 0x5000, 0x22);
        t.record_write(0, 0x5000, 0x33);
        let snap = t.memory_snapshot();
        assert_eq!(snap.get(&0x5000).copied(), Some(0x33));
    }

    #[test]
    fn clear_resets_state() {
        let mut t = SmcWriteTracker::new();
        t.record_write(0x1000, 0x3000, 0xBB);
        t.record_exec(0x3000, 0x3000);
        t.clear();
        assert!(t.confirmed_pairs().is_empty());
        assert!(t.memory_snapshot().is_empty());
        assert_eq!(t.stats.write_events, 0);
    }

    #[test]
    fn write_count_in_confirmed() {
        let mut t = SmcWriteTracker::new();
        for _ in 0..5 {
            t.record_write(0x1000, 0x6000, 0xAA);
        }
        t.record_exec(0x6000, 0x6000);
        assert_eq!(t.confirmed_pairs()[0].write_count, 5);
    }

    #[test]
    fn smc_region_display() {
        let r = SmcRegion {
            start: 0x1000,
            end: 0x1010,
            write_count: 16,
            bytes: vec![0xCC; 16],
        };
        let s = r.to_string();
        assert!(s.contains("SmcRegion"));
        assert!(s.contains("writes=16"));
    }

    #[test]
    fn event_log_records_all_types() {
        let mut t = SmcWriteTracker::new();
        t.record_write(0, 0x7000, 0xFF);
        t.record_exec(0x7000, 0x7000);
        let log = t.event_log();
        let has_write = log.iter().any(|e| matches!(e, SmcEvent::Write(_)));
        let has_exec = log.iter().any(|e| matches!(e, SmcEvent::Exec(_)));
        let has_confirmed = log.iter().any(|e| matches!(e, SmcEvent::Confirmed(_)));
        assert!(has_write);
        assert!(has_exec);
        assert!(has_confirmed);
    }
}
