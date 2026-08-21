//! Navigate by address: find all trace positions where an address was executed,
//! jump between executions, compute execution frequency per address, detect
//! first/last execution, find gaps in execution.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{Address, ExecutionTrace, NavError};

// ── ExecutionEvent ────────────────────────────────────────────────────────────

/// A single execution event for an address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionEvent {
    /// Trace index when this address was executed.
    pub trace_idx: usize,
    /// Thread ID.
    pub tid: u32,
    /// Disassembly at this address (may be empty for memory events).
    pub disasm: String,
}

impl ExecutionEvent {
    /// Create a new event.
    #[must_use]
    pub fn new(trace_idx: usize, tid: u32, disasm: impl Into<String>) -> Self {
        Self { trace_idx, tid, disasm: disasm.into() }
    }
}

impl std::fmt::Display for ExecutionEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Event(idx={}, tid={}, disasm={})", self.trace_idx, self.tid, self.disasm)
    }
}

// ── ExecutionGap ─────────────────────────────────────────────────────────────

/// A gap between two consecutive executions of the same address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionGap {
    /// The address.
    pub address: Address,
    /// Trace index of the execution before the gap.
    pub before_idx: usize,
    /// Trace index of the execution after the gap.
    pub after_idx: usize,
    /// Size of the gap in trace indices.
    pub gap_size: usize,
}

impl ExecutionGap {
    /// Create a new gap.
    #[must_use]
    pub const fn new(address: Address, before_idx: usize, after_idx: usize) -> Self {
        Self { address, before_idx, after_idx, gap_size: after_idx.saturating_sub(before_idx) }
    }

    /// True if the gap is larger than `threshold` trace indices.
    #[must_use]
    pub const fn is_large(&self, threshold: usize) -> bool {
        self.gap_size > threshold
    }
}

// ── FrequencyMap ──────────────────────────────────────────────────────────────

/// Maps each address to its execution count and first/last trace index.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FrequencyMap {
    /// address -> (count, `first_idx`, `last_idx`)
    inner: HashMap<Address, (usize, usize, usize)>,
}

impl FrequencyMap {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Build from a trace.
    #[must_use]
    pub fn build(trace: &ExecutionTrace) -> Self {
        let mut fm = Self::new();
        for entry in &trace.entries {
            fm.record(entry.pc, entry.idx);
        }
        fm
    }

    /// Record one execution of `address` at `trace_idx`.
    pub fn record(&mut self, address: Address, trace_idx: usize) {
        let e = self.inner.entry(address).or_insert((0, trace_idx, trace_idx));
        e.0 += 1;
        if trace_idx < e.1 { e.1 = trace_idx; }
        if trace_idx > e.2 { e.2 = trace_idx; }
    }

    /// Execution count for `address`.
    #[must_use]
    pub fn count(&self, address: Address) -> usize {
        self.inner.get(&address).map_or(0, |e| e.0)
    }

    /// First trace index at which `address` was executed.
    #[must_use]
    pub fn first_execution(&self, address: Address) -> Option<usize> {
        self.inner.get(&address).map(|e| e.1)
    }

    /// Last trace index at which `address` was executed.
    #[must_use]
    pub fn last_execution(&self, address: Address) -> Option<usize> {
        self.inner.get(&address).map(|e| e.2)
    }

    /// All tracked addresses.
    #[must_use]
    pub fn addresses(&self) -> Vec<Address> {
        self.inner.keys().copied().collect()
    }

    /// Total unique addresses.
    #[must_use]
    pub fn unique_count(&self) -> usize { self.inner.len() }

    /// Top-N most frequently executed addresses.
    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<(Address, usize)> {
        let mut pairs: Vec<(Address, usize)> = self.inner.iter()
            .map(|(&a, &(c, _, _))| (a, c)).collect();
        pairs.sort_unstable_by_key(|b| std::cmp::Reverse(b.1));
        pairs.truncate(n);
        pairs
    }

    /// Addresses executed exactly once.
    #[must_use]
    pub fn single_execution_addresses(&self) -> Vec<Address> {
        self.inner.iter()
            .filter(|&(_, &(c, _, _))| c == 1)
            .map(|(&a, _)| a)
            .collect()
    }

    /// Normalized heat for `address` (count / `max_count`), or 0.0.
    #[must_use]
    pub fn normalized_heat(&self, address: Address) -> f64 {
        let count = self.count(address);
        if count == 0 { return 0.0; }
        let max = self.inner.values().map(|e| e.0).max().unwrap_or(1);
        f64::from(u32::try_from(count).unwrap_or(u32::MAX)) / f64::from(u32::try_from(max).unwrap_or(u32::MAX))
    }
}

// ── AddressTimeline ───────────────────────────────────────────────────────────

/// Per-address timeline of all trace positions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressTimeline {
    /// address -> sorted list of `ExecutionEvents`.
    inner: HashMap<Address, Vec<ExecutionEvent>>,
    /// Frequency map cache.
    pub freq: FrequencyMap,
}

impl AddressTimeline {
    /// Create an empty timeline.
    #[must_use]
    pub fn new() -> Self {
        Self { inner: HashMap::new(), freq: FrequencyMap::new() }
    }

    /// Build the full timeline from a trace.
    #[must_use]
    pub fn build(trace: &ExecutionTrace) -> Self {
        let mut tl = Self::new();
        tl.freq = FrequencyMap::build(trace);
        for entry in &trace.entries {
            tl.inner.entry(entry.pc).or_default().push(
                ExecutionEvent::new(entry.idx, entry.tid, entry.disasm.clone())
            );
        }
        tl
    }

    /// All execution events for `address`, in trace order.
    #[must_use]
    pub fn events_for(&self, address: Address) -> &[ExecutionEvent] {
        self.inner.get(&address).map_or(&[][..], std::vec::Vec::as_slice)
    }

    /// Number of times `address` was executed.
    #[must_use]
    pub fn execution_count(&self, address: Address) -> usize {
        self.freq.count(address)
    }

    /// Trace index of the first execution of `address`.
    #[must_use]
    pub fn first_execution(&self, address: Address) -> Option<usize> {
        self.freq.first_execution(address)
    }

    /// Trace index of the last execution of `address`.
    #[must_use]
    pub fn last_execution(&self, address: Address) -> Option<usize> {
        self.freq.last_execution(address)
    }

    /// All trace indices where `address` was executed.
    #[must_use]
    pub fn all_indices(&self, address: Address) -> Vec<usize> {
        self.events_for(address).iter().map(|e| e.trace_idx).collect()
    }

    /// Find the next execution of `address` after `after_idx`.
    #[must_use]
    pub fn next_execution_after(&self, address: Address, after_idx: usize) -> Option<usize> {
        self.events_for(address).iter()
            .find(|e| e.trace_idx > after_idx)
            .map(|e| e.trace_idx)
    }

    /// Find the previous execution of `address` before `before_idx`.
    #[must_use]
    pub fn prev_execution_before(&self, address: Address, before_idx: usize) -> Option<usize> {
        self.events_for(address).iter()
            .rev()
            .find(|e| e.trace_idx < before_idx)
            .map(|e| e.trace_idx)
    }

    /// Compute all execution gaps for `address`.
    #[must_use]
    pub fn gaps_for(&self, address: Address) -> Vec<ExecutionGap> {
        let events = self.events_for(address);
        if events.len() < 2 { return Vec::new(); }
        events.windows(2).map(|w| {
            ExecutionGap::new(address, w[0].trace_idx, w[1].trace_idx)
        }).collect()
    }

    /// Find the largest gap for `address`.
    #[must_use]
    pub fn largest_gap(&self, address: Address) -> Option<ExecutionGap> {
        self.gaps_for(address).into_iter().max_by_key(|g| g.gap_size)
    }

    /// Number of distinct addresses in the timeline.
    #[must_use]
    pub fn unique_address_count(&self) -> usize { self.inner.len() }

    /// All addresses with at least one execution.
    #[must_use]
    pub fn all_addresses(&self) -> Vec<Address> {
        self.inner.keys().copied().collect()
    }
}

impl Default for AddressTimeline {
    fn default() -> Self { Self::new() }
}

// ── AddressQuery ──────────────────────────────────────────────────────────────

/// Query for searching by address execution patterns.
#[derive(Debug, Clone, Default)]
pub struct AddressQuery {
    /// The address to query (required).
    pub address: Option<Address>,
    /// Only events at or after this trace index.
    pub min_idx: Option<usize>,
    /// Only events at or before this trace index.
    pub max_idx: Option<usize>,
    /// Only events from this thread.
    pub tid: Option<u32>,
    /// Maximum results.
    pub limit: Option<usize>,
}

impl AddressQuery {
    /// Create a new query for a specific address.
    #[must_use]
    pub fn for_address(address: Address) -> Self {
        Self { address: Some(address), ..Default::default() }
    }

    /// Set trace index range.
    #[must_use]
    pub const fn idx_range(mut self, min: usize, max: usize) -> Self {
        self.min_idx = Some(min);
        self.max_idx = Some(max);
        self
    }

    /// Set thread filter.
    #[must_use]
    pub const fn tid(mut self, tid: u32) -> Self {
        self.tid = Some(tid);
        self
    }

    /// Limit results.
    #[must_use]
    pub const fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    /// Test whether `event` matches this query.
    #[must_use]
    pub const fn event_matches(&self, event: &ExecutionEvent) -> bool {
        if let Some(min) = self.min_idx
            && event.trace_idx < min { return false; }
        if let Some(max) = self.max_idx
            && event.trace_idx > max { return false; }
        if let Some(tid) = self.tid
            && event.tid != tid { return false; }
        true
    }

    /// Run the query against `timeline`, returning matching events.
    ///
    /// # Errors
    /// Returns `NavError::NoResults` if `address` is None or has no events.
    pub fn execute<'a>(&self, timeline: &'a AddressTimeline) -> Result<Vec<&'a ExecutionEvent>, NavError> {
        let addr = self.address.ok_or(NavError::NoResults)?;
        let events = timeline.events_for(addr);
        if events.is_empty() {
            return Err(NavError::NoResults);
        }
        let mut results: Vec<&ExecutionEvent> = events.iter()
            .filter(|e| self.event_matches(e))
            .collect();
        if let Some(lim) = self.limit {
            results.truncate(lim);
        }
        Ok(results)
    }
}

// ── TimelineNavigator ─────────────────────────────────────────────────────────

/// Interactive navigator that jumps between executions of a focused address.
pub struct TimelineNavigator {
    /// The address timeline.
    pub timeline: AddressTimeline,
    /// Currently focused address.
    pub focused_address: Option<Address>,
    /// Current position in the events list for the focused address.
    event_cursor: usize,
    /// Current global trace index.
    pub trace_idx: usize,
}

impl TimelineNavigator {
    /// Build from a trace.
    #[must_use]
    pub fn from_trace(trace: &ExecutionTrace) -> Self {
        Self {
            timeline: AddressTimeline::build(trace),
            focused_address: None,
            event_cursor: 0,
            trace_idx: 0,
        }
    }

    /// Focus on an address for navigation.
    ///
    /// # Errors
    /// Returns `NavError::NoResults` if the address was never executed.
    pub fn focus(&mut self, address: Address) -> Result<usize, NavError> {
        let count = self.timeline.execution_count(address);
        if count == 0 { return Err(NavError::NoResults); }
        self.focused_address = Some(address);
        self.event_cursor = 0;
        let first = self.timeline.first_execution(address).unwrap_or(0);
        self.trace_idx = first;
        Ok(first)
    }

    /// Jump to the next execution of the focused address.
    ///
    /// # Errors
    /// Returns `NavError::OutOfBounds` at the last execution.
    pub fn next_execution(&mut self) -> Result<usize, NavError> {
        let addr = self.focused_address.ok_or(NavError::NoResults)?;
        let events = self.timeline.events_for(addr);
        let next_cursor = self.event_cursor + 1;
        if next_cursor >= events.len() {
            return Err(NavError::OutOfBounds { idx: next_cursor, max: events.len().saturating_sub(1) });
        }
        self.event_cursor = next_cursor;
        self.trace_idx = events[next_cursor].trace_idx;
        Ok(self.trace_idx)
    }

    /// Jump to the previous execution of the focused address.
    ///
    /// # Errors
    /// Returns `NavError::OutOfBounds` at the first execution.
    pub fn prev_execution(&mut self) -> Result<usize, NavError> {
        let addr = self.focused_address.ok_or(NavError::NoResults)?;
        let events = self.timeline.events_for(addr);
        if self.event_cursor == 0 {
            return Err(NavError::OutOfBounds { idx: 0, max: 0 });
        }
        self.event_cursor -= 1;
        self.trace_idx = events[self.event_cursor].trace_idx;
        Ok(self.trace_idx)
    }

    /// Jump to the first execution of the focused address.
    ///
    /// # Errors
    /// Returns `NavError::NoResults` if nothing is focused.
    pub fn first_execution(&mut self) -> Result<usize, NavError> {
        let addr = self.focused_address.ok_or(NavError::NoResults)?;
        let idx = self.timeline.first_execution(addr).ok_or(NavError::NoResults)?;
        self.event_cursor = 0;
        self.trace_idx = idx;
        Ok(idx)
    }

    /// Jump to the last execution of the focused address.
    ///
    /// # Errors
    /// Returns `NavError::NoResults` if nothing is focused.
    pub fn last_execution(&mut self) -> Result<usize, NavError> {
        let addr = self.focused_address.ok_or(NavError::NoResults)?;
        let events = self.timeline.events_for(addr);
        if events.is_empty() { return Err(NavError::NoResults); }
        self.event_cursor = events.len() - 1;
        self.trace_idx = events[self.event_cursor].trace_idx;
        Ok(self.trace_idx)
    }

    /// Jump to the Nth execution (0-based).
    ///
    /// # Errors
    /// Returns `NavError::OutOfBounds` if N is out of range.
    pub fn jump_to_nth(&mut self, n: usize) -> Result<usize, NavError> {
        let addr = self.focused_address.ok_or(NavError::NoResults)?;
        let events = self.timeline.events_for(addr);
        if n >= events.len() {
            return Err(NavError::OutOfBounds { idx: n, max: events.len().saturating_sub(1) });
        }
        self.event_cursor = n;
        self.trace_idx = events[n].trace_idx;
        Ok(self.trace_idx)
    }

    /// Current event for the focused address.
    #[must_use]
    pub fn current_event(&self) -> Option<&ExecutionEvent> {
        let addr = self.focused_address?;
        self.timeline.events_for(addr).get(self.event_cursor)
    }

    /// Number of executions of the focused address.
    #[must_use]
    pub fn focused_execution_count(&self) -> usize {
        self.focused_address.map_or(0, |a| self.timeline.execution_count(a))
    }

    /// Current event cursor position (0-based).
    #[must_use]
    pub const fn cursor(&self) -> usize { self.event_cursor }

    /// Progress fraction for the focused address: cursor / count.
    #[must_use]
    pub fn execution_progress(&self) -> f64 {
        let count = self.focused_execution_count();
        if count <= 1 { return 1.0; }
        f64::from(u32::try_from(self.event_cursor).unwrap_or(u32::MAX)) / f64::from(u32::try_from(count - 1).unwrap_or(u32::MAX))
    }

    /// All gaps for the focused address.
    #[must_use]
    pub fn gaps(&self) -> Vec<ExecutionGap> {
        self.focused_address.map_or_else(Vec::new, |a| self.timeline.gaps_for(a))
    }

    /// Hottest addresses (top-N by execution count).
    #[must_use]
    pub fn hot_addresses(&self, n: usize) -> Vec<(Address, usize)> {
        self.timeline.freq.top_n(n)
    }

    /// Run an address query against the timeline.
    ///
    /// # Errors
    /// See `AddressQuery::execute`.
    pub fn query<'a>(&'a self, q: &AddressQuery) -> Result<Vec<&'a ExecutionEvent>, NavError> {
        q.execute(&self.timeline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TraceBuilder;

    fn make_trace() -> ExecutionTrace {
        let mut b = TraceBuilder::new("test");
        // PC 0x1000 executed at idx 0, 2, 4
        b.insn(0x1000, 0, "nop");  // idx 0
        b.insn(0x2000, 0, "push"); // idx 1
        b.insn(0x1000, 0, "nop");  // idx 2
        b.insn(0x3000, 0, "pop");  // idx 3
        b.insn(0x1000, 0, "nop");  // idx 4
        b.build()
    }

    #[test]
    fn test_build_timeline() {
        let trace = make_trace();
        let tl = AddressTimeline::build(&trace);
        assert_eq!(tl.execution_count(0x1000), 3);
        assert_eq!(tl.execution_count(0x2000), 1);
    }

    #[test]
    fn test_first_last_execution() {
        let trace = make_trace();
        let tl = AddressTimeline::build(&trace);
        assert_eq!(tl.first_execution(0x1000), Some(0));
        assert_eq!(tl.last_execution(0x1000), Some(4));
    }

    #[test]
    fn test_next_prev_execution() {
        let trace = make_trace();
        let tl = AddressTimeline::build(&trace);
        assert_eq!(tl.next_execution_after(0x1000, 0), Some(2));
        assert_eq!(tl.prev_execution_before(0x1000, 4), Some(2));
    }

    #[test]
    fn test_gaps_for() {
        let trace = make_trace();
        let tl = AddressTimeline::build(&trace);
        let gaps = tl.gaps_for(0x1000);
        assert_eq!(gaps.len(), 2);
        assert_eq!(gaps[0].before_idx, 0);
        assert_eq!(gaps[0].after_idx, 2);
        assert_eq!(gaps[0].gap_size, 2);
    }

    #[test]
    fn test_navigator_focus_and_navigate() {
        let trace = make_trace();
        let mut nav = TimelineNavigator::from_trace(&trace);
        let first = nav.focus(0x1000).unwrap();
        assert_eq!(first, 0);
        let next = nav.next_execution().unwrap();
        assert_eq!(next, 2);
        let prev = nav.prev_execution().unwrap();
        assert_eq!(prev, 0);
    }

    #[test]
    fn test_navigator_last() {
        let trace = make_trace();
        let mut nav = TimelineNavigator::from_trace(&trace);
        nav.focus(0x1000).unwrap();
        let last = nav.last_execution().unwrap();
        assert_eq!(last, 4);
    }

    #[test]
    fn test_navigator_progress() {
        let trace = make_trace();
        let mut nav = TimelineNavigator::from_trace(&trace);
        nav.focus(0x1000).unwrap();
        nav.jump_to_nth(1).unwrap();
        let p = nav.execution_progress();
        assert!((p - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_frequency_map_top_n() {
        let trace = make_trace();
        let fm = FrequencyMap::build(&trace);
        let top = fm.top_n(1);
        assert_eq!(top[0].0, 0x1000);
        assert_eq!(top[0].1, 3);
    }

    #[test]
    fn test_address_query() {
        let trace = make_trace();
        let tl = AddressTimeline::build(&trace);
        let q = AddressQuery::for_address(0x1000).idx_range(0, 2);
        let events = q.execute(&tl).unwrap();
        assert!(events.iter().all(|e| e.trace_idx <= 2));
    }
}
