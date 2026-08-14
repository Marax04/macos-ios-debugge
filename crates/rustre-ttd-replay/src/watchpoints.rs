//! `rustre-ttd-replay::watchpoints`
//!
//! Data-breakpoint / memory-watchpoint system for replay sessions.
//!
//! Key types:
//! * [`DataBreakpoint`] — a single configured watchpoint with optional conditions.
//! * [`WatchpointSet`] — a managed collection of `DataBreakpoint`s.
//! * [`WatchpointEvent`] — describes why a watchpoint fired.
//! * [`MemoryAccessKind`] — read, write, or read-write.
//! * [`RangeWatchpoint`] — watches an entire address range, e.g. a memory region.
//! * [`WatchpointFilter`] — composable predicate for narrowing watchpoint events.

use std::collections::HashMap;
use std::fmt;

use rustre_ttd::TracePosition;
use serde::{Deserialize, Serialize};

// ─── MemoryAccessKind ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryAccessKind {
    Read,
    Write,
    ReadWrite,
}

impl MemoryAccessKind {
    #[must_use]
    pub const fn matches_write(self) -> bool {
        matches!(self, Self::Write | Self::ReadWrite)
    }
    #[must_use]
    pub const fn matches_read(self) -> bool {
        matches!(self, Self::Read | Self::ReadWrite)
    }
}

impl fmt::Display for MemoryAccessKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => write!(f, "R"),
            Self::Write => write!(f, "W"),
            Self::ReadWrite => write!(f, "RW"),
        }
    }
}

// ─── WatchCondition ───────────────────────────────────────────────────────────

/// Optional condition that must be true for a watchpoint to fire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WatchCondition {
    /// Always fire.
    Always,
    /// Fire only if the new written value equals `expected`.
    ValueEquals(Vec<u8>),
    /// Fire only if the new written value differs from `expected`.
    ValueNotEquals(Vec<u8>),
    /// Fire only if the new value is greater than `threshold` (u64 LE interpretation).
    ValueGt(u64),
    /// Fire only if any bit in `mask` changes.
    BitMaskChanged(u64),
    /// Fire only for accesses from `tid`.
    ThreadId(u32),
    /// Fire only on the N-th access (1-indexed).
    HitCount(u64),
}

impl WatchCondition {
    /// Evaluate the condition given `(old_bytes, new_bytes, tid, hit_count)`.
    #[must_use]
    pub fn evaluate(&self, old: &[u8], new: &[u8], tid: u32, hit: u64) -> bool {
        match self {
            Self::Always => true,
            Self::ValueEquals(exp) => new == exp.as_slice(),
            Self::ValueNotEquals(exp) => new != exp.as_slice(),
            Self::ValueGt(thresh) => {
                let v = le_bytes_to_u64(new);
                v > *thresh
            }
            Self::BitMaskChanged(mask) => {
                let o = le_bytes_to_u64(old);
                let n = le_bytes_to_u64(new);
                (o ^ n) & mask != 0
            }
            Self::ThreadId(expected_tid) => tid == *expected_tid,
            Self::HitCount(n) => hit == *n,
        }
    }
}

fn le_bytes_to_u64(b: &[u8]) -> u64 {
    let mut arr = [0u8; 8];
    let len = b.len().min(8);
    arr[..len].copy_from_slice(&b[..len]);
    u64::from_le_bytes(arr)
}

impl fmt::Display for WatchCondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Always => write!(f, "always"),
            Self::ValueEquals(v) => write!(f, "value=={v:?}"),
            Self::ValueNotEquals(v) => write!(f, "value!={v:?}"),
            Self::ValueGt(n) => write!(f, "value>{n}"),
            Self::BitMaskChanged(m) => write!(f, "bits_changed({m:#x})"),
            Self::ThreadId(t) => write!(f, "tid={t}"),
            Self::HitCount(n) => write!(f, "hit#{n}"),
        }
    }
}

// ─── DataBreakpoint ───────────────────────────────────────────────────────────

/// A fully-configured data breakpoint for replay sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataBreakpoint {
    /// Unique ID.
    pub id: u32,
    /// Start address of the watched range.
    pub address: u64,
    /// Number of bytes watched.
    pub size: usize,
    /// Which access types trigger this breakpoint.
    pub kind: MemoryAccessKind,
    /// Optional condition.
    pub condition: WatchCondition,
    /// Whether currently enabled.
    pub enabled: bool,
    /// Name / description for UI display.
    pub name: Option<String>,
    /// Number of times this breakpoint has fired.
    pub hit_count: u64,
    /// Whether to log-only without stopping.
    pub log_only: bool,
}

impl DataBreakpoint {
    #[must_use]
    pub const fn new(id: u32, address: u64, size: usize, kind: MemoryAccessKind) -> Self {
        Self {
            id,
            address,
            size,
            kind,
            condition: WatchCondition::Always,
            enabled: true,
            name: None,
            hit_count: 0,
            log_only: false,
        }
    }

    #[must_use]
    pub fn with_condition(mut self, cond: WatchCondition) -> Self {
        self.condition = cond;
        self
    }

    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    #[must_use]
    pub const fn log_only(mut self) -> Self {
        self.log_only = true;
        self
    }

    /// End address (exclusive).
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.address.saturating_add(self.size as u64)
    }

    /// Whether this breakpoint overlaps with `[addr, addr+len)`.
    #[must_use]
    pub const fn overlaps(&self, addr: u64, len: usize) -> bool {
        let acc_end = addr.saturating_add(len as u64);
        self.address < acc_end && addr < self.end()
    }

    /// Evaluate whether this breakpoint should fire for an access.
    /// `old` / `new` are the old and new bytes at the watched address.
    #[must_use]
    pub fn should_fire_write(&self, addr: u64, new_data: &[u8], old_data: &[u8], tid: u32) -> bool {
        if !self.enabled {
            return false;
        }
        if !self.kind.matches_write() {
            return false;
        }
        if !self.overlaps(addr, new_data.len()) {
            return false;
        }
        self.condition
            .evaluate(old_data, new_data, tid, self.hit_count + 1)
    }

    #[must_use]
    pub fn should_fire_read(&self, addr: u64, len: usize, tid: u32) -> bool {
        if !self.enabled {
            return false;
        }
        if !self.kind.matches_read() {
            return false;
        }
        if !self.overlaps(addr, len) {
            return false;
        }
        self.condition.evaluate(&[], &[], tid, self.hit_count + 1)
    }

    /// Increment hit count and return the new value.
    pub const fn increment_hits(&mut self) -> u64 {
        self.hit_count += 1;
        self.hit_count
    }
}

impl fmt::Display for DataBreakpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.name.as_deref().unwrap_or("");
        write!(
            f,
            "DataBP#{} [{} {:#x}+{}] cond={} hits={} {}",
            self.id,
            self.kind,
            self.address,
            self.size,
            self.condition,
            self.hit_count,
            if name.is_empty() {
                String::new()
            } else {
                format!("({name})")
            }
        )
    }
}

// ─── WatchpointEvent ──────────────────────────────────────────────────────────

/// Describes a watchpoint firing event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchpointEvent {
    pub watchpoint_id: u32,
    pub position: TracePosition,
    pub access_address: u64,
    pub access_size: usize,
    pub access_kind: MemoryAccessKind,
    pub old_value: Vec<u8>,
    pub new_value: Vec<u8>,
    pub thread_id: u32,
    pub is_log_only: bool,
}

impl WatchpointEvent {
    /// Whether any byte actually changed.
    #[must_use]
    pub fn value_changed(&self) -> bool {
        self.old_value != self.new_value
    }

    /// Delta (new XOR old) as a u64.
    #[must_use]
    pub fn change_mask(&self) -> u64 {
        let o = le_bytes_to_u64(&self.old_value);
        let n = le_bytes_to_u64(&self.new_value);
        o ^ n
    }
}

impl fmt::Display for WatchpointEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WP#{} {} @{:#x}+{} tid={} pos={}",
            self.watchpoint_id,
            self.access_kind,
            self.access_address,
            self.access_size,
            self.thread_id,
            self.position
        )
    }
}

// ─── RangeWatchpoint ──────────────────────────────────────────────────────────

/// A watchpoint that covers a named address range (e.g. a stack region, heap, .data section).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeWatchpoint {
    pub id: u32,
    pub base: u64,
    pub size: u64,
    pub kind: MemoryAccessKind,
    pub label: String,
    pub enabled: bool,
    pub hit_count: u64,
}

impl RangeWatchpoint {
    pub fn new(
        id: u32,
        base: u64,
        size: u64,
        kind: MemoryAccessKind,
        label: impl Into<String>,
    ) -> Self {
        Self {
            id,
            base,
            size,
            kind,
            label: label.into(),
            enabled: true,
            hit_count: 0,
        }
    }

    #[must_use]
    pub const fn end(&self) -> u64 {
        self.base.saturating_add(self.size)
    }

    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }

    #[must_use]
    pub const fn overlaps_range(&self, addr: u64, len: u64) -> bool {
        let acc_end = addr.saturating_add(len);
        self.base < acc_end && addr < self.end()
    }

    #[must_use]
    pub const fn matches_write(&self, addr: u64, len: usize) -> bool {
        self.enabled && self.kind.matches_write() && self.overlaps_range(addr, len as u64)
    }

    #[must_use]
    pub const fn matches_read(&self, addr: u64, len: usize) -> bool {
        self.enabled && self.kind.matches_read() && self.overlaps_range(addr, len as u64)
    }
}

impl fmt::Display for RangeWatchpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RangeWP#{} '{}' [{:#x}..{:#x}] {} hits={}",
            self.id,
            self.label,
            self.base,
            self.end(),
            self.kind,
            self.hit_count
        )
    }
}

// ─── WatchpointFilter ─────────────────────────────────────────────────────────

/// Composable filter for watchpoint events.
#[derive(Debug, Clone)]
pub enum WatchpointFilter {
    /// Accept all events.
    All,
    /// Accept only events from `tid`.
    Thread(u32),
    /// Accept only events in address range `[lo, hi)`.
    AddressRange { lo: u64, hi: u64 },
    /// Accept only events of a specific access kind.
    AccessKind(MemoryAccessKind),
    /// Accept only events where the value changed.
    ValueChanged,
    /// Accept only log-only events.
    LogOnly,
    /// Conjunction.
    And(Box<Self>, Box<Self>),
    /// Disjunction.
    Or(Box<Self>, Box<Self>),
    /// Negation.
    Not(Box<Self>),
}

impl WatchpointFilter {
    #[must_use]
    pub fn and(self, other: Self) -> Self {
        Self::And(Box::new(self), Box::new(other))
    }
    #[must_use]
    pub fn or(self, other: Self) -> Self {
        Self::Or(Box::new(self), Box::new(other))
    }
    #[must_use]
    pub fn negate(self) -> Self {
        Self::Not(Box::new(self))
    }

    #[must_use]
    pub fn matches(&self, event: &WatchpointEvent) -> bool {
        match self {
            Self::All => true,
            Self::Thread(tid) => event.thread_id == *tid,
            Self::AddressRange { lo, hi } => {
                event.access_address >= *lo && event.access_address < *hi
            }
            Self::AccessKind(k) => event.access_kind == *k,
            Self::ValueChanged => event.value_changed(),
            Self::LogOnly => event.is_log_only,
            Self::And(a, b) => a.matches(event) && b.matches(event),
            Self::Or(a, b) => a.matches(event) || b.matches(event),
            Self::Not(inner) => !inner.matches(event),
        }
    }
}

// ─── WatchpointSet ────────────────────────────────────────────────────────────

/// Managed collection of data breakpoints, with event logging and filtering.
#[derive(Debug, Default)]
pub struct WatchpointSet {
    breakpoints: Vec<DataBreakpoint>,
    ranges: Vec<RangeWatchpoint>,
    event_log: Vec<WatchpointEvent>,
    next_id: u32,
}

impl WatchpointSet {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_id: 1,
            ..Default::default()
        }
    }

    // ── breakpoint management ─────────────────────────────────────────────────

    pub fn add_breakpoint(&mut self, address: u64, size: usize, kind: MemoryAccessKind) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        self.breakpoints
            .push(DataBreakpoint::new(id, address, size, kind));
        id
    }

    pub fn add_breakpoint_configured(&mut self, bp: DataBreakpoint) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        let mut bp = bp;
        bp.id = id;
        self.breakpoints.push(bp);
        id
    }

    pub fn add_range(
        &mut self,
        base: u64,
        size: u64,
        kind: MemoryAccessKind,
        label: impl Into<String>,
    ) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        self.ranges
            .push(RangeWatchpoint::new(id, base, size, kind, label));
        id
    }

    pub fn remove(&mut self, id: u32) -> bool {
        let before = self.breakpoints.len() + self.ranges.len();
        self.breakpoints.retain(|bp| bp.id != id);
        self.ranges.retain(|r| r.id != id);
        self.breakpoints.len() + self.ranges.len() < before
    }

    pub fn enable(&mut self, id: u32) -> bool {
        for bp in &mut self.breakpoints {
            if bp.id == id {
                bp.enabled = true;
                return true;
            }
        }
        for r in &mut self.ranges {
            if r.id == id {
                r.enabled = true;
                return true;
            }
        }
        false
    }

    pub fn disable(&mut self, id: u32) -> bool {
        for bp in &mut self.breakpoints {
            if bp.id == id {
                bp.enabled = false;
                return true;
            }
        }
        for r in &mut self.ranges {
            if r.id == id {
                r.enabled = false;
                return true;
            }
        }
        false
    }

    #[must_use]
    pub const fn breakpoint_count(&self) -> usize {
        self.breakpoints.len()
    }
    #[must_use]
    pub const fn range_count(&self) -> usize {
        self.ranges.len()
    }
    #[must_use]
    pub const fn total_count(&self) -> usize {
        self.breakpoints.len() + self.ranges.len()
    }

    // ── event matching ────────────────────────────────────────────────────────

    /// Check a memory write.  Returns all events that should fire.
    pub fn check_write(
        &mut self,
        addr: u64,
        data: &[u8],
        old: &[u8],
        tid: u32,
        position: TracePosition,
    ) -> Vec<WatchpointEvent> {
        let mut fired = Vec::new();

        for bp in &mut self.breakpoints {
            if bp.should_fire_write(addr, data, old, tid) {
                let hit = bp.increment_hits();
                let evt = WatchpointEvent {
                    watchpoint_id: bp.id,
                    position,
                    access_address: addr,
                    access_size: data.len(),
                    access_kind: MemoryAccessKind::Write,
                    old_value: old.to_vec(),
                    new_value: data.to_vec(),
                    thread_id: tid,
                    is_log_only: bp.log_only,
                };
                let _ = hit;
                fired.push(evt);
            }
        }

        for rw in &mut self.ranges {
            if rw.matches_write(addr, data.len()) {
                rw.hit_count += 1;
                let evt = WatchpointEvent {
                    watchpoint_id: rw.id,
                    position,
                    access_address: addr,
                    access_size: data.len(),
                    access_kind: MemoryAccessKind::Write,
                    old_value: old.to_vec(),
                    new_value: data.to_vec(),
                    thread_id: tid,
                    is_log_only: false,
                };
                fired.push(evt);
            }
        }

        self.event_log.extend(fired.iter().cloned());
        fired
    }

    /// Check a memory read.  Returns all events that should fire.
    pub fn check_read(
        &mut self,
        addr: u64,
        len: usize,
        tid: u32,
        position: TracePosition,
    ) -> Vec<WatchpointEvent> {
        let mut fired = Vec::new();

        for bp in &mut self.breakpoints {
            if bp.should_fire_read(addr, len, tid) {
                let hit = bp.increment_hits();
                let _ = hit;
                fired.push(WatchpointEvent {
                    watchpoint_id: bp.id,
                    position,
                    access_address: addr,
                    access_size: len,
                    access_kind: MemoryAccessKind::Read,
                    old_value: vec![],
                    new_value: vec![],
                    thread_id: tid,
                    is_log_only: bp.log_only,
                });
            }
        }

        for rw in &mut self.ranges {
            if rw.matches_read(addr, len) {
                rw.hit_count += 1;
                fired.push(WatchpointEvent {
                    watchpoint_id: rw.id,
                    position,
                    access_address: addr,
                    access_size: len,
                    access_kind: MemoryAccessKind::Read,
                    old_value: vec![],
                    new_value: vec![],
                    thread_id: tid,
                    is_log_only: false,
                });
            }
        }

        self.event_log.extend(fired.iter().cloned());
        fired
    }

    // ── event log ─────────────────────────────────────────────────────────────

    #[must_use]
    pub fn event_log(&self) -> &[WatchpointEvent] {
        &self.event_log
    }

    pub fn filtered_events<'a>(
        &'a self,
        filter: &'a WatchpointFilter,
    ) -> impl Iterator<Item = &'a WatchpointEvent> {
        self.event_log.iter().filter(move |e| filter.matches(e))
    }

    pub fn clear_log(&mut self) {
        self.event_log.clear();
    }

    /// Total number of events in the log that actually stopped execution (not log-only).
    #[must_use]
    pub fn stop_event_count(&self) -> usize {
        self.event_log.iter().filter(|e| !e.is_log_only).count()
    }

    /// Events involving a specific address.
    #[must_use]
    pub fn events_for_address(&self, addr: u64) -> Vec<&WatchpointEvent> {
        self.event_log
            .iter()
            .filter(|e| e.access_address == addr)
            .collect()
    }

    /// Events for a specific watchpoint ID.
    #[must_use]
    pub fn events_for_watchpoint(&self, id: u32) -> Vec<&WatchpointEvent> {
        self.event_log
            .iter()
            .filter(|e| e.watchpoint_id == id)
            .collect()
    }

    // ── statistics ────────────────────────────────────────────────────────────

    /// Per-address write count summary.
    #[must_use]
    pub fn write_counts_by_address(&self) -> HashMap<u64, u64> {
        let mut map = HashMap::new();
        for e in &self.event_log {
            if e.access_kind.matches_write() {
                *map.entry(e.access_address).or_insert(0) += 1;
            }
        }
        map
    }

    /// Per-thread event count.
    #[must_use]
    pub fn events_per_thread(&self) -> HashMap<u32, usize> {
        let mut map = HashMap::new();
        for e in &self.event_log {
            *map.entry(e.thread_id).or_insert(0) += 1;
        }
        map
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_ttd::TracePosition;

    fn pos(seq: u64) -> TracePosition {
        TracePosition::new(seq, 0)
    }

    // ── MemoryAccessKind ──────────────────────────────────────────────────────

    #[test]
    fn access_kind_display() {
        assert_eq!(MemoryAccessKind::Read.to_string(), "R");
        assert_eq!(MemoryAccessKind::Write.to_string(), "W");
        assert_eq!(MemoryAccessKind::ReadWrite.to_string(), "RW");
    }

    #[test]
    fn access_kind_matches() {
        assert!(MemoryAccessKind::Write.matches_write());
        assert!(!MemoryAccessKind::Write.matches_read());
        assert!(MemoryAccessKind::ReadWrite.matches_read());
        assert!(MemoryAccessKind::ReadWrite.matches_write());
    }

    // ── WatchCondition ────────────────────────────────────────────────────────

    #[test]
    fn condition_always() {
        assert!(WatchCondition::Always.evaluate(&[], &[99], 1, 1));
    }

    #[test]
    fn condition_value_equals() {
        let cond = WatchCondition::ValueEquals(vec![1, 2, 3]);
        assert!(cond.evaluate(&[], &[1, 2, 3], 1, 1));
        assert!(!cond.evaluate(&[], &[4, 5, 6], 1, 1));
    }

    #[test]
    fn condition_value_not_equals() {
        let cond = WatchCondition::ValueNotEquals(vec![0]);
        assert!(cond.evaluate(&[], &[1], 1, 1));
        assert!(!cond.evaluate(&[], &[0], 1, 1));
    }

    #[test]
    fn condition_value_gt() {
        let cond = WatchCondition::ValueGt(5);
        assert!(cond.evaluate(&[], &[10, 0, 0, 0, 0, 0, 0, 0], 1, 1));
        assert!(!cond.evaluate(&[], &[3, 0, 0, 0, 0, 0, 0, 0], 1, 1));
    }

    #[test]
    fn condition_bitmask_changed() {
        let cond = WatchCondition::BitMaskChanged(0xFF);
        // Old = 0, new = 1: bit 0 changed, mask 0xFF catches it
        assert!(cond.evaluate(&[0], &[1], 1, 1));
        // No change
        assert!(!cond.evaluate(&[5], &[5], 1, 1));
    }

    #[test]
    fn condition_thread_id() {
        let cond = WatchCondition::ThreadId(2);
        assert!(cond.evaluate(&[], &[], 2, 1));
        assert!(!cond.evaluate(&[], &[], 3, 1));
    }

    #[test]
    fn condition_hit_count() {
        let cond = WatchCondition::HitCount(3);
        assert!(!cond.evaluate(&[], &[], 1, 2));
        assert!(cond.evaluate(&[], &[], 1, 3));
    }

    #[test]
    fn condition_display() {
        assert!(WatchCondition::Always.to_string().contains("always"));
        assert!(WatchCondition::ThreadId(5).to_string().contains('5'));
    }

    // ── DataBreakpoint ────────────────────────────────────────────────────────

    #[test]
    fn data_bp_overlaps() {
        let bp = DataBreakpoint::new(1, 0x1000, 8, MemoryAccessKind::Write);
        assert!(bp.overlaps(0x1004, 4));
        assert!(bp.overlaps(0x0ffc, 8));
        assert!(!bp.overlaps(0x1008, 4));
    }

    #[test]
    fn data_bp_should_fire_write() {
        let bp = DataBreakpoint::new(1, 0x1000, 4, MemoryAccessKind::Write);
        assert!(bp.should_fire_write(0x1000, &[99], &[0], 1));
        assert!(!bp.should_fire_write(0x5000, &[99], &[0], 1));
    }

    #[test]
    fn data_bp_disabled_no_fire() {
        let mut bp = DataBreakpoint::new(1, 0x1000, 4, MemoryAccessKind::Write);
        bp.enabled = false;
        assert!(!bp.should_fire_write(0x1000, &[99], &[0], 1));
    }

    #[test]
    fn data_bp_should_fire_read() {
        let bp = DataBreakpoint::new(1, 0x1000, 4, MemoryAccessKind::Read);
        assert!(bp.should_fire_read(0x1000, 4, 1));
        assert!(!bp.should_fire_read(0x2000, 4, 1));
    }

    #[test]
    fn data_bp_increment_hits() {
        let mut bp = DataBreakpoint::new(1, 0, 4, MemoryAccessKind::Write);
        assert_eq!(bp.increment_hits(), 1);
        assert_eq!(bp.increment_hits(), 2);
    }

    #[test]
    fn data_bp_display() {
        let bp = DataBreakpoint::new(1, 0x1000, 4, MemoryAccessKind::Write).with_name("test_wp");
        assert!(bp.to_string().contains("test_wp"));
        assert!(bp.to_string().contains("0x1000"));
    }

    // ── RangeWatchpoint ───────────────────────────────────────────────────────

    #[test]
    fn range_wp_contains_and_overlaps() {
        let rw = RangeWatchpoint::new(1, 0x1000, 0x1000, MemoryAccessKind::Write, "heap");
        assert!(rw.contains(0x1500));
        assert!(!rw.contains(0x2500));
        assert!(rw.overlaps_range(0x1800, 0x400));
    }

    #[test]
    fn range_wp_matches_write_read() {
        let rw = RangeWatchpoint::new(1, 0x1000, 0x100, MemoryAccessKind::ReadWrite, "stack");
        assert!(rw.matches_write(0x1010, 4));
        assert!(rw.matches_read(0x1010, 4));
    }

    #[test]
    fn range_wp_display() {
        let rw = RangeWatchpoint::new(1, 0x1000, 0x100, MemoryAccessKind::Write, "test");
        assert!(rw.to_string().contains("test"));
    }

    // ── WatchpointEvent ───────────────────────────────────────────────────────

    #[test]
    fn watchpoint_event_value_changed() {
        let e = WatchpointEvent {
            watchpoint_id: 1,
            position: pos(0),
            access_address: 0x1000,
            access_size: 4,
            access_kind: MemoryAccessKind::Write,
            old_value: vec![0],
            new_value: vec![1],
            thread_id: 1,
            is_log_only: false,
        };
        assert!(e.value_changed());
    }

    #[test]
    fn watchpoint_event_no_change() {
        let e = WatchpointEvent {
            watchpoint_id: 1,
            position: pos(0),
            access_address: 0x1000,
            access_size: 4,
            access_kind: MemoryAccessKind::Write,
            old_value: vec![5],
            new_value: vec![5],
            thread_id: 1,
            is_log_only: false,
        };
        assert!(!e.value_changed());
    }

    #[test]
    fn watchpoint_event_change_mask() {
        let e = WatchpointEvent {
            watchpoint_id: 1,
            position: pos(0),
            access_address: 0,
            access_size: 1,
            access_kind: MemoryAccessKind::Write,
            old_value: vec![0b0000_0000],
            new_value: vec![0b0000_0011],
            thread_id: 1,
            is_log_only: false,
        };
        assert_eq!(e.change_mask(), 0b11);
    }

    #[test]
    fn watchpoint_event_display() {
        let e = WatchpointEvent {
            watchpoint_id: 2,
            position: pos(1),
            access_address: 0x2000,
            access_size: 8,
            access_kind: MemoryAccessKind::Read,
            old_value: vec![],
            new_value: vec![],
            thread_id: 3,
            is_log_only: false,
        };
        assert!(e.to_string().contains("WP#2"));
    }

    // ── WatchpointFilter ──────────────────────────────────────────────────────

    fn make_write_event(addr: u64, tid: u32) -> WatchpointEvent {
        WatchpointEvent {
            watchpoint_id: 1,
            position: TracePosition::new(0, 0),
            access_address: addr,
            access_size: 4,
            access_kind: MemoryAccessKind::Write,
            old_value: vec![0],
            new_value: vec![1],
            thread_id: tid,
            is_log_only: false,
        }
    }

    #[test]
    fn filter_all() {
        let f = WatchpointFilter::All;
        assert!(f.matches(&make_write_event(0x1000, 1)));
    }

    #[test]
    fn filter_thread() {
        let f = WatchpointFilter::Thread(2);
        assert!(!f.matches(&make_write_event(0, 1)));
        assert!(f.matches(&make_write_event(0, 2)));
    }

    #[test]
    fn filter_address_range() {
        let f = WatchpointFilter::AddressRange {
            lo: 0x1000,
            hi: 0x2000,
        };
        assert!(f.matches(&make_write_event(0x1500, 1)));
        assert!(!f.matches(&make_write_event(0x3000, 1)));
    }

    #[test]
    fn filter_value_changed() {
        let f = WatchpointFilter::ValueChanged;
        assert!(f.matches(&make_write_event(0, 1))); // old=0, new=1 -> changed
    }

    #[test]
    fn filter_and_or_not() {
        let f = WatchpointFilter::Thread(1).and(WatchpointFilter::AddressRange {
            lo: 0x1000,
            hi: 0x2000,
        });
        assert!(f.matches(&make_write_event(0x1500, 1)));
        assert!(!f.matches(&make_write_event(0x1500, 2)));
        let g = WatchpointFilter::Thread(1).or(WatchpointFilter::Thread(2));
        assert!(g.matches(&make_write_event(0, 2)));
        let h = WatchpointFilter::Thread(1).negate();
        assert!(h.matches(&make_write_event(0, 2)));
        assert!(!h.matches(&make_write_event(0, 1)));
    }

    // ── WatchpointSet ─────────────────────────────────────────────────────────

    #[test]
    fn set_add_remove() {
        let mut ws = WatchpointSet::new();
        let id = ws.add_breakpoint(0x1000, 4, MemoryAccessKind::Write);
        assert_eq!(ws.breakpoint_count(), 1);
        assert!(ws.remove(id));
        assert_eq!(ws.breakpoint_count(), 0);
        assert!(!ws.remove(id));
    }

    #[test]
    fn set_add_range() {
        let mut ws = WatchpointSet::new();
        ws.add_range(0x1000, 0x1000, MemoryAccessKind::Write, "heap");
        assert_eq!(ws.range_count(), 1);
        assert_eq!(ws.total_count(), 1);
    }

    #[test]
    fn set_enable_disable() {
        let mut ws = WatchpointSet::new();
        let id = ws.add_breakpoint(0x1000, 4, MemoryAccessKind::Write);
        assert!(ws.disable(id));
        assert!(!ws.breakpoints[0].enabled);
        assert!(ws.enable(id));
        assert!(ws.breakpoints[0].enabled);
    }

    #[test]
    fn set_check_write_fires() {
        let mut ws = WatchpointSet::new();
        ws.add_breakpoint(0x1000, 4, MemoryAccessKind::Write);
        let events = ws.check_write(0x1000, &[99], &[0], 1, pos(0));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].access_address, 0x1000);
    }

    #[test]
    fn set_check_write_no_overlap() {
        let mut ws = WatchpointSet::new();
        ws.add_breakpoint(0x1000, 4, MemoryAccessKind::Write);
        let events = ws.check_write(0x5000, &[99], &[0], 1, pos(0));
        assert!(events.is_empty());
    }

    #[test]
    fn set_check_read_fires() {
        let mut ws = WatchpointSet::new();
        ws.add_breakpoint(0x1000, 4, MemoryAccessKind::Read);
        let events = ws.check_read(0x1000, 4, 1, pos(0));
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn set_event_log_accumulates() {
        let mut ws = WatchpointSet::new();
        ws.add_breakpoint(0x1000, 4, MemoryAccessKind::Write);
        ws.check_write(0x1000, &[1], &[0], 1, pos(0));
        ws.check_write(0x1000, &[2], &[1], 1, pos(1));
        assert_eq!(ws.event_log().len(), 2);
    }

    #[test]
    fn set_filtered_events() {
        let mut ws = WatchpointSet::new();
        ws.add_breakpoint(0x1000, 4, MemoryAccessKind::Write);
        ws.check_write(0x1000, &[1], &[0], 1, pos(0));
        ws.check_write(0x1000, &[2], &[1], 2, pos(1));
        let f = WatchpointFilter::Thread(1);
        
        assert_eq!(ws.filtered_events(&f).count(), 1);
    }

    #[test]
    fn set_write_counts_by_address() {
        let mut ws = WatchpointSet::new();
        ws.add_breakpoint(0x1000, 4, MemoryAccessKind::Write);
        ws.check_write(0x1000, &[1], &[0], 1, pos(0));
        ws.check_write(0x1000, &[2], &[1], 1, pos(1));
        let counts = ws.write_counts_by_address();
        assert_eq!(counts.get(&0x1000).copied(), Some(2));
    }

    #[test]
    fn set_events_per_thread() {
        let mut ws = WatchpointSet::new();
        ws.add_breakpoint(0x1000, 4, MemoryAccessKind::Write);
        ws.check_write(0x1000, &[1], &[0], 1, pos(0));
        ws.check_write(0x1000, &[2], &[1], 2, pos(1));
        let per_thread = ws.events_per_thread();
        assert_eq!(per_thread[&1], 1);
        assert_eq!(per_thread[&2], 1);
    }

    #[test]
    fn set_clear_log() {
        let mut ws = WatchpointSet::new();
        ws.add_breakpoint(0x1000, 4, MemoryAccessKind::Write);
        ws.check_write(0x1000, &[1], &[0], 1, pos(0));
        ws.clear_log();
        assert!(ws.event_log().is_empty());
    }

    #[test]
    fn set_range_wp_fires_on_write() {
        let mut ws = WatchpointSet::new();
        ws.add_range(0x1000, 0x1000, MemoryAccessKind::Write, "stack");
        let events = ws.check_write(0x1500, &[0xAB], &[0], 1, pos(0));
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn set_stop_event_count() {
        let mut ws = WatchpointSet::new();
        ws.add_breakpoint(0x1000, 4, MemoryAccessKind::Write);
        let id = ws.add_breakpoint(0x2000, 4, MemoryAccessKind::Write);
        // Mark one as log-only
        ws.breakpoints
            .iter_mut()
            .find(|b| b.id == id)
            .unwrap()
            .log_only = true;
        ws.check_write(0x1000, &[1], &[0], 1, pos(0));
        ws.check_write(0x2000, &[1], &[0], 1, pos(1));
        assert_eq!(ws.stop_event_count(), 1);
    }
}
