//! Time-travel navigation over an execution trace.
//!
//! Provides `TimeTravelNavigator` for jumping to specific timestamps, addresses,
//! and function call occurrences, with a full undo/redo navigation history and
//! configurable breakpoints.

use crate::trace_search_engine::TraceEntry;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Direction
// ---------------------------------------------------------------------------

/// Direction of navigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Search forward in time (increasing timestamp).
    Forward,
    /// Search backward in time (decreasing timestamp).
    Backward,
}

// ---------------------------------------------------------------------------
// NavigationPoint
// ---------------------------------------------------------------------------

/// A single point in the navigation history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavigationPoint {
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Thread ID at this point.
    pub thread_id: u32,
    /// Instruction address.
    pub address: u64,
    /// User-assigned label (e.g. `"entry point"`, `"crash site"`).
    pub label: Option<String>,
    /// Index of this point in the backing trace.
    pub trace_index: usize,
}

impl NavigationPoint {
    /// Create a new navigation point from a trace entry and its index.
    #[must_use]
    pub const fn from_entry(entry: &TraceEntry, trace_index: usize) -> Self {
        Self {
            timestamp_ns: entry.timestamp_ns,
            thread_id: entry.thread_id,
            address: entry.address,
            label: None,
            trace_index,
        }
    }

    /// Attach a label to this navigation point.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

// ---------------------------------------------------------------------------
// BpCondition
// ---------------------------------------------------------------------------

/// The trigger condition for a `Breakpoint`.
#[derive(Debug, Clone)]
pub enum BpCondition {
    /// Fire when execution reaches this address.
    AtAddress(u64),
    /// Fire when the trace timestamp equals or exceeds this value.
    AtTimestamp(u64),
    /// Fire when the named register holds the specified value.
    WhenRegEquals { reg: String, val: u64 },
    /// Fire when an API call by name is encountered.
    ApiCallByName(String),
}

impl BpCondition {
    /// Returns `true` if this condition is satisfied by the given trace entry.
    #[must_use]
    pub fn matches(&self, entry: &TraceEntry) -> bool {
        match self {
            Self::AtAddress(a) => entry.address == *a,
            Self::AtTimestamp(t) => entry.timestamp_ns >= *t,
            Self::WhenRegEquals { reg, val } => {
                entry.registers.get(reg).copied() == Some(*val)
            }
            Self::ApiCallByName(name) => {
                entry.disasm.to_lowercase().contains(&name.to_lowercase())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Breakpoint
// ---------------------------------------------------------------------------

/// A named breakpoint with a trigger condition.
#[derive(Debug, Clone)]
pub struct Breakpoint {
    /// Unique identifier.
    pub id: u32,
    /// The trigger condition.
    pub condition: BpCondition,
    /// Optional user label.
    pub label: Option<String>,
    /// Whether this breakpoint is enabled.
    pub enabled: bool,
    /// Number of times this breakpoint has been hit.
    pub hit_count: u32,
}

impl Breakpoint {
    /// Create a new enabled breakpoint.
    #[must_use]
    pub const fn new(id: u32, condition: BpCondition) -> Self {
        Self {
            id,
            condition,
            label: None,
            enabled: true,
            hit_count: 0,
        }
    }

    /// Create with a label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Disable the breakpoint without removing it.
    pub const fn disable(&mut self) {
        self.enabled = false;
    }

    /// Re-enable the breakpoint.
    pub const fn enable(&mut self) {
        self.enabled = true;
    }
}

// ---------------------------------------------------------------------------
// NavigationHistory
// ---------------------------------------------------------------------------

/// A navigable history of `NavigationPoint`s (undo/redo stack).
#[derive(Debug, Default, Clone)]
pub struct NavigationHistory {
    /// All history entries.
    pub points: Vec<NavigationPoint>,
    /// The index of the current position in `points`.
    pub current: usize,
}

impl NavigationHistory {
    /// Create an empty history.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a new point onto the history, discarding any "forward" entries
    /// that would have been reachable via redo.
    pub fn push(&mut self, point: NavigationPoint) {
        // Discard everything after current
        self.points.truncate(self.current + 1);
        self.points.push(point);
        self.current = self.points.len() - 1;
    }

    /// Go back one step.  Returns the new current point, or `None` if at start.
    pub fn go_back(&mut self) -> Option<&NavigationPoint> {
        if self.current == 0 {
            return None;
        }
        self.current -= 1;
        self.points.get(self.current)
    }

    /// Go forward one step.  Returns the new current point, or `None` if at end.
    pub fn go_forward(&mut self) -> Option<&NavigationPoint> {
        if self.current + 1 >= self.points.len() {
            return None;
        }
        self.current += 1;
        self.points.get(self.current)
    }

    /// Returns the current navigation point.
    #[must_use]
    pub fn current_point(&self) -> Option<&NavigationPoint> {
        self.points.get(self.current)
    }

    /// Returns `true` if back navigation is possible.
    #[must_use]
    pub const fn can_go_back(&self) -> bool {
        self.current > 0
    }

    /// Returns `true` if forward navigation is possible.
    #[must_use]
    pub const fn can_go_forward(&self) -> bool {
        self.current + 1 < self.points.len()
    }

    /// Returns the length of the history.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.points.len()
    }

    /// Returns `true` if the history is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.points.is_empty()
    }
}

// ---------------------------------------------------------------------------
// TimeTravelNavigator
// ---------------------------------------------------------------------------

/// Full-featured time-travel navigator over an execution trace.
///
/// All navigation methods record the destination in the `NavigationHistory`
/// so that the user can undo/redo their navigation.
pub struct TimeTravelNavigator {
    /// The backing trace.
    entries: Vec<TraceEntry>,
    /// Current position in the trace (index).
    pub current_index: usize,
    /// Navigation history for undo/redo.
    pub history: NavigationHistory,
    /// Registered breakpoints, keyed by ID.
    breakpoints: HashMap<u32, Breakpoint>,
    /// Next breakpoint ID.
    next_bp_id: u32,
    /// Index for address lookups: address → sorted list of trace indices.
    address_index: HashMap<u64, Vec<usize>>,
}

impl TimeTravelNavigator {
    /// Create a new navigator over the given trace.
    #[must_use]
    pub fn new(entries: Vec<TraceEntry>) -> Self {
        let address_index = build_address_index(&entries);
        let mut nav = Self {
            entries,
            current_index: 0,
            history: NavigationHistory::new(),
            breakpoints: HashMap::new(),
            next_bp_id: 1,
            address_index,
        };
        // Record the starting position if the trace is non-empty
        if let Some(entry) = nav.entries.first() {
            let point = NavigationPoint::from_entry(entry, 0);
            nav.history.push(point);
        }
        nav
    }

    /// Returns the number of entries in the trace.
    #[must_use]
    pub const fn trace_len(&self) -> usize {
        self.entries.len()
    }

    /// Returns the current `TraceEntry`.
    #[must_use]
    pub fn current_entry(&self) -> Option<&TraceEntry> {
        self.entries.get(self.current_index)
    }

    // ── basic stepping ─────────────────────────────────────────────────────

    /// Step one entry forward.  Returns the new entry, or `None` at the end.
    pub fn step_forward(&mut self) -> Option<&TraceEntry> {
        if self.current_index + 1 >= self.entries.len() {
            return None;
        }
        self.current_index += 1;
        self.record_current();
        self.entries.get(self.current_index)
    }

    /// Step one entry backward.  Returns the new entry, or `None` at the start.
    pub fn step_backward(&mut self) -> Option<&TraceEntry> {
        if self.current_index == 0 {
            return None;
        }
        self.current_index -= 1;
        self.record_current();
        self.entries.get(self.current_index)
    }

    // ── timestamp navigation ───────────────────────────────────────────────

    /// Jump to the entry whose timestamp is closest to `ts` (first match).
    ///
    /// Returns the matched `NavigationPoint` or `None` if the trace is empty.
    pub fn go_to_timestamp(&mut self, ts: u64) -> Option<NavigationPoint> {
        if self.entries.is_empty() {
            return None;
        }
        // Binary search for the closest timestamp
        let idx = self
            .entries
            .partition_point(|e| e.timestamp_ns < ts)
            .min(self.entries.len() - 1);
        self.jump_to(idx)
    }

    // ── address navigation ─────────────────────────────────────────────────

    /// Jump to the next (or previous) occurrence of `addr` from the current
    /// position.
    pub fn go_to_address(&mut self, addr: u64, dir: Direction) -> Option<NavigationPoint> {
        let indices = self.address_index.get(&addr)?;
        let target_idx = match dir {
            Direction::Forward => {
                indices.iter().copied().find(|&i| i > self.current_index)
            }
            Direction::Backward => {
                indices.iter().rev().copied().find(|&i| i < self.current_index)
            }
        }?;
        self.jump_to(target_idx)
    }

    // ── call navigation ────────────────────────────────────────────────────

    /// Jump to the `occurrence`-th call to `func_addr` (1-based).
    ///
    /// A "call to `func_addr`" is any trace entry whose address is the
    /// *destination* of a CALL instruction (i.e., the address immediately after
    /// a CALL entry is `func_addr` in a real trace, but here we approximate by
    /// looking for entries at `func_addr` that are preceded by a CALL).
    pub fn go_to_call(
        &mut self,
        func_addr: u64,
        occurrence: u32,
    ) -> Option<NavigationPoint> {
        let mut count = 0u32;
        let len = self.entries.len();
        for i in 1..len {
            let prev = &self.entries[i - 1];
            let curr = &self.entries[i];
            if curr.address == func_addr && prev.is_call() {
                count += 1;
                if count == occurrence {
                    return self.jump_to(i);
                }
            }
        }
        None
    }

    // ── breakpoint navigation ──────────────────────────────────────────────

    /// Navigate to the next/previous trace entry satisfying `bp` from the
    /// current position.
    pub fn navigate_to_breakpoint(
        &mut self,
        bp: &Breakpoint,
        from: u64,
        dir: Direction,
    ) -> Option<NavigationPoint> {
        if !bp.enabled {
            return None;
        }

        // Find the starting index
        let start = self
            .entries
            .iter()
            .position(|e| e.timestamp_ns >= from)
            .unwrap_or(0);

        match dir {
            Direction::Forward => {
                for i in (start + 1)..self.entries.len() {
                    if bp.condition.matches(&self.entries[i]) {
                        return self.jump_to(i);
                    }
                }
            }
            Direction::Backward => {
                let end = start.min(self.entries.len().saturating_sub(1));
                for i in (0..end).rev() {
                    if bp.condition.matches(&self.entries[i]) {
                        return self.jump_to(i);
                    }
                }
            }
        }
        None
    }

    // ── history helpers ────────────────────────────────────────────────────

    /// Undo the last navigation (go back one step in the history).
    pub fn pop_history(&mut self) -> Option<&NavigationPoint> {
        let point = self.history.go_back()?;
        self.current_index = point.trace_index;
        self.history.current_point()
    }

    /// Redo the last undone navigation (go forward one step in the history).
    pub fn push_history(&mut self) -> Option<&NavigationPoint> {
        let point = self.history.go_forward()?;
        self.current_index = point.trace_index;
        self.history.current_point()
    }

    // ── breakpoint management ──────────────────────────────────────────────

    /// Register a new breakpoint and return its ID.
    pub fn add_breakpoint(&mut self, condition: BpCondition) -> u32 {
        let id = self.next_bp_id;
        self.next_bp_id += 1;
        self.breakpoints.insert(id, Breakpoint::new(id, condition));
        id
    }

    /// Remove a breakpoint by ID.
    pub fn remove_breakpoint(&mut self, id: u32) -> bool {
        self.breakpoints.remove(&id).is_some()
    }

    /// Return an immutable reference to a breakpoint by ID.
    #[must_use]
    pub fn get_breakpoint(&self, id: u32) -> Option<&Breakpoint> {
        self.breakpoints.get(&id)
    }

    /// Return a mutable reference to a breakpoint by ID.
    pub fn get_breakpoint_mut(&mut self, id: u32) -> Option<&mut Breakpoint> {
        self.breakpoints.get_mut(&id)
    }

    /// Run all enabled breakpoints from the current position in `dir`.
    ///
    /// Returns the first matching `NavigationPoint`, or `None`.
    pub fn run_to_next_breakpoint(&mut self, dir: Direction) -> Option<NavigationPoint> {
        let ts = self.current_entry().map_or(0, |e| e.timestamp_ns);
        let bp_ids: Vec<u32> = self.breakpoints.keys().copied().collect();
        for id in bp_ids {
            // Clone the bp to avoid borrow issues
            let bp = self.breakpoints[&id].clone();
            if let Some(point) = self.navigate_to_breakpoint(&bp, ts, dir) {
                if let Some(b) = self.breakpoints.get_mut(&id) { b.hit_count += 1; }
                return Some(point);
            }
        }
        None
    }

    // ── statistics ─────────────────────────────────────────────────────────

    /// Return the set of all unique addresses in the trace.
    #[must_use]
    pub fn unique_addresses(&self) -> Vec<u64> {
        let mut addrs: Vec<u64> = self.address_index.keys().copied().collect();
        addrs.sort_unstable();
        addrs
    }

    /// Return the most-visited address (excluding current position).
    #[must_use]
    pub fn hottest_address(&self) -> Option<u64> {
        self.address_index
            .iter()
            .max_by_key(|(_, v)| v.len())
            .map(|(k, _)| *k)
    }

    /// Return the timestamp range covered by the trace.
    #[must_use]
    pub fn timestamp_range(&self) -> Option<(u64, u64)> {
        let first = self.entries.first()?.timestamp_ns;
        let last = self.entries.last()?.timestamp_ns;
        Some((first, last))
    }

    // ── internal ──────────────────────────────────────────────────────────

    fn jump_to(&mut self, index: usize) -> Option<NavigationPoint> {
        let entry = self.entries.get(index)?;
        let point = NavigationPoint::from_entry(entry, index);
        self.current_index = index;
        self.history.push(point.clone());
        Some(point)
    }

    fn record_current(&mut self) {
        if let Some(entry) = self.entries.get(self.current_index) {
            let point = NavigationPoint::from_entry(entry, self.current_index);
            self.history.push(point);
        }
    }
}

// ---------------------------------------------------------------------------
// Index builder
// ---------------------------------------------------------------------------

fn build_address_index(entries: &[TraceEntry]) -> HashMap<u64, Vec<usize>> {
    let mut map: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, e) in entries.iter().enumerate() {
        map.entry(e.address).or_default().push(i);
    }
    map
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ts: u64, tid: u32, addr: u64, disasm: &str) -> TraceEntry {
        TraceEntry::new(ts, tid, addr, disasm)
    }

    fn sample() -> Vec<TraceEntry> {
        vec![
            entry(100, 1, 0x1000, "push rbp"),
            entry(200, 1, 0x1001, "mov rbp, rsp"),
            entry(300, 1, 0x2000, "call CreateFileA"),
            entry(400, 1, 0x3000, "push rbp"),        // call dest
            entry(500, 1, 0x3001, "mov eax, 0"),
            entry(600, 1, 0x1004, "ret"),
            entry(700, 1, 0x1000, "push rbp"),
        ]
    }

    #[test]
    fn test_initial_position() {
        let nav = TimeTravelNavigator::new(sample());
        assert_eq!(nav.current_index, 0);
    }

    #[test]
    fn test_step_forward() {
        let mut nav = TimeTravelNavigator::new(sample());
        let e = nav.step_forward().unwrap();
        assert_eq!(e.address, 0x1001);
        assert_eq!(nav.current_index, 1);
    }

    #[test]
    fn test_step_backward() {
        let mut nav = TimeTravelNavigator::new(sample());
        nav.step_forward();
        nav.step_forward();
        let e = nav.step_backward().unwrap();
        assert_eq!(e.address, 0x1001);
    }

    #[test]
    fn test_step_backward_at_start_returns_none() {
        let mut nav = TimeTravelNavigator::new(sample());
        assert!(nav.step_backward().is_none());
    }

    #[test]
    fn test_step_forward_at_end_returns_none() {
        let mut nav = TimeTravelNavigator::new(sample());
        for _ in 0..sample().len() {
            nav.step_forward();
        }
        assert!(nav.step_forward().is_none());
    }

    #[test]
    fn test_go_to_timestamp_exact() {
        let mut nav = TimeTravelNavigator::new(sample());
        let pt = nav.go_to_timestamp(300).unwrap();
        assert_eq!(pt.address, 0x2000);
    }

    #[test]
    fn test_go_to_timestamp_between() {
        let mut nav = TimeTravelNavigator::new(sample());
        // 150 is between 100 and 200; partition_point finds idx=1
        let pt = nav.go_to_timestamp(150).unwrap();
        assert!(pt.timestamp_ns <= 200);
    }

    #[test]
    fn test_go_to_address_forward() {
        let mut nav = TimeTravelNavigator::new(sample());
        // From index 0, first forward occurrence of 0x1000 after index 0 is index 6
        let pt = nav.go_to_address(0x1000, Direction::Forward).unwrap();
        assert_eq!(pt.address, 0x1000);
        assert!(pt.trace_index > 0);
    }

    #[test]
    fn test_go_to_address_backward() {
        let mut nav = TimeTravelNavigator::new(sample());
        nav.go_to_timestamp(700); // go to end
        let pt = nav.go_to_address(0x1000, Direction::Backward).unwrap();
        assert_eq!(pt.address, 0x1000);
    }

    #[test]
    fn test_go_to_address_not_found() {
        let mut nav = TimeTravelNavigator::new(sample());
        let result = nav.go_to_address(0xDEAD, Direction::Forward);
        assert!(result.is_none());
    }

    #[test]
    fn test_go_to_call() {
        let mut nav = TimeTravelNavigator::new(sample());
        // Call to 0x3000 is at index 3 (index 2 = call, index 3 = dest)
        let pt = nav.go_to_call(0x3000, 1).unwrap();
        assert_eq!(pt.address, 0x3000);
    }

    #[test]
    fn test_go_to_call_occurrence_2_returns_none() {
        let mut nav = TimeTravelNavigator::new(sample());
        // Only one call to 0x3000
        assert!(nav.go_to_call(0x3000, 2).is_none());
    }

    #[test]
    fn test_breakpoint_at_address() {
        let mut nav = TimeTravelNavigator::new(sample());
        let bp_id = nav.add_breakpoint(BpCondition::AtAddress(0x3000));
        let bp = nav.get_breakpoint(bp_id).unwrap().clone();
        let ts = nav.current_entry().map_or(0, |e| e.timestamp_ns);
        let result = nav.navigate_to_breakpoint(&bp, ts, Direction::Forward);
        assert!(result.is_some());
        assert_eq!(result.unwrap().address, 0x3000);
    }

    #[test]
    fn test_breakpoint_disabled() {
        let mut nav = TimeTravelNavigator::new(sample());
        let bp_id = nav.add_breakpoint(BpCondition::AtAddress(0x3000));
        nav.get_breakpoint_mut(bp_id).unwrap().disable();
        let bp = nav.get_breakpoint(bp_id).unwrap().clone();
        let ts = 0;
        let result = nav.navigate_to_breakpoint(&bp, ts, Direction::Forward);
        assert!(result.is_none());
    }

    #[test]
    fn test_navigation_history_undo_redo() {
        let mut nav = TimeTravelNavigator::new(sample());
        nav.step_forward(); // -> idx 1
        nav.step_forward(); // -> idx 2
        nav.pop_history();   // undo -> idx 1
        assert_eq!(nav.current_index, 1);
        nav.push_history(); // redo -> idx 2
        assert_eq!(nav.current_index, 2);
    }

    #[test]
    fn test_navigation_history_can_back_forward() {
        let mut nav = TimeTravelNavigator::new(sample());
        assert!(!nav.history.can_go_back()); // at start
        nav.step_forward();
        assert!(nav.history.can_go_back());
    }

    #[test]
    fn test_unique_addresses() {
        let nav = TimeTravelNavigator::new(sample());
        let addrs = nav.unique_addresses();
        assert!(addrs.contains(&0x1000));
        assert!(addrs.contains(&0x3000));
    }

    #[test]
    fn test_hottest_address() {
        let nav = TimeTravelNavigator::new(sample());
        let hot = nav.hottest_address().unwrap();
        assert_eq!(hot, 0x1000); // 0x1000 appears twice
    }

    #[test]
    fn test_timestamp_range() {
        let nav = TimeTravelNavigator::new(sample());
        let (lo, hi) = nav.timestamp_range().unwrap();
        assert_eq!(lo, 100);
        assert_eq!(hi, 700);
    }

    #[test]
    fn test_remove_breakpoint() {
        let mut nav = TimeTravelNavigator::new(sample());
        let id = nav.add_breakpoint(BpCondition::AtAddress(0x1000));
        assert!(nav.remove_breakpoint(id));
        assert!(!nav.remove_breakpoint(id));
    }

    #[test]
    fn test_bp_condition_at_timestamp() {
        let entry = TraceEntry::new(500, 1, 0x1000, "nop");
        assert!(BpCondition::AtTimestamp(400).matches(&entry));
        assert!(!BpCondition::AtTimestamp(600).matches(&entry));
    }

    #[test]
    fn test_bp_condition_api_call() {
        let entry = TraceEntry::new(100, 1, 0x1000, "call CreateFileA");
        assert!(BpCondition::ApiCallByName("CreateFileA".to_owned()).matches(&entry));
        assert!(!BpCondition::ApiCallByName("VirtualAlloc".to_owned()).matches(&entry));
    }
}
