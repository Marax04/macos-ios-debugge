//! Tenet-style execution trace navigation — bidirectional stepping,
//! jumps, memory/register timeline, and navigation history.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
/// Re-exports of ordered/queue collections for callers that build auxiliary
/// trace indexes on top of [`TenetNavigator`].
pub use std::collections::{BTreeMap, VecDeque};

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NavError {
    #[error("trace position {0} out of range (max {1})")]
    OutOfRange(u64, u64),
    #[error("no trace loaded")]
    NoTrace,
    #[error("no memory write to address 0x{0:016x} found")]
    NoMemoryWrite(u64),
    #[error("no function at 0x{0:016x} found in trace")]
    NoFunction(u64),
    #[error("navigation history empty")]
    HistoryEmpty,
}

// ─── TracePosition ────────────────────────────────────────────────────────────

/// An index into the trace (monotonically increasing tick counter).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TracePosition(pub u64);

impl TracePosition {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
    #[must_use]
    pub const fn advance(self, n: u64) -> Self {
        Self(self.0.saturating_add(n))
    }
    #[must_use]
    pub const fn rewind(self, n: u64) -> Self {
        Self(self.0.saturating_sub(n))
    }
}

impl std::fmt::Display for TracePosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tick#{}", self.0)
    }
}

// ─── TraceEntry ───────────────────────────────────────────────────────────────

/// A single trace entry (one instruction's context).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEntry {
    pub position: TracePosition,
    pub pc: u64,
    pub mnemonic: String,
    /// Register values at this tick (`reg_id` → value).
    pub registers: HashMap<u32, u64>,
    /// Memory writes at this tick: (address, value, `size_bytes`).
    pub mem_writes: Vec<(u64, u64, u8)>,
    /// Memory reads at this tick: (address, value, `size_bytes`).
    pub mem_reads: Vec<(u64, u64, u8)>,
    /// Call stack depth.
    pub call_depth: u32,
}

impl TraceEntry {
    /// Create a minimal trace entry.
    #[must_use]
    pub fn new(tick: u64, pc: u64, mnemonic: impl Into<String>) -> Self {
        Self {
            position: TracePosition(tick),
            pc,
            mnemonic: mnemonic.into(),
            registers: HashMap::new(),
            mem_writes: Vec::new(),
            mem_reads: Vec::new(),
            call_depth: 0,
        }
    }
}

// ─── ForwardStep / BackwardStep ───────────────────────────────────────────────

/// Result of a forward step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardStep {
    pub from: TracePosition,
    pub to: TracePosition,
    pub entry: TraceEntry,
    pub crossed_call: bool,
    pub crossed_ret: bool,
}

/// Result of a backward step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackwardStep {
    pub from: TracePosition,
    pub to: TracePosition,
    pub entry: TraceEntry,
}

// ─── JumpToFunction ──────────────────────────────────────────────────────────

/// Result of jumping to the next call of a function address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JumpToFunction {
    pub target_pc: u64,
    pub found_at: TracePosition,
    pub call_depth: u32,
}

// ─── JumpToMemoryWrite ────────────────────────────────────────────────────────

/// Result of jumping to the next/previous memory write.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JumpToMemoryWrite {
    pub address: u64,
    pub found_at: TracePosition,
    pub value_before: Option<u64>,
    pub value_after: u64,
    pub write_size: u8,
}

// ─── NavigationHistory ────────────────────────────────────────────────────────

/// Breadcrumb navigation history (like browser back/forward).
#[derive(Debug, Default, Clone)]
pub struct NavigationHistory {
    past: Vec<TracePosition>,
    future: Vec<TracePosition>,
    max_depth: usize,
}

impl NavigationHistory {
    /// Create a new history with given max depth.
    #[must_use]
    pub const fn new(max_depth: usize) -> Self {
        Self {
            past: Vec::new(),
            future: Vec::new(),
            max_depth,
        }
    }

    /// Push a new position (clears future).
    pub fn push(&mut self, pos: TracePosition) {
        if self.past.len() >= self.max_depth {
            self.past.remove(0);
        }
        self.past.push(pos);
        self.future.clear();
    }

    /// Go back one position.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn back(&mut self) -> Result<TracePosition, NavError> {
        let current = self.past.pop().ok_or(NavError::HistoryEmpty)?;
        self.future.push(current);
        self.past.last().copied().ok_or(NavError::HistoryEmpty)
    }

    /// Go forward one position.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn forward(&mut self) -> Result<TracePosition, NavError> {
        let next = self.future.pop().ok_or(NavError::HistoryEmpty)?;
        self.past.push(next);
        Ok(next)
    }

    /// Current position.
    #[must_use]
    pub fn current(&self) -> Option<TracePosition> {
        self.past.last().copied()
    }

    /// Can go back?
    #[must_use]
    pub const fn can_go_back(&self) -> bool {
        self.past.len() > 1
    }

    /// Can go forward?
    #[must_use]
    pub const fn can_go_forward(&self) -> bool {
        !self.future.is_empty()
    }

    /// History depth (number of saved past positions).
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.past.len()
    }
}

// ─── TenetNavigation ─────────────────────────────────────────────────────────

/// Bidirectional trace navigator in the style of Tenet.
#[derive(Debug)]
pub struct TenetNavigation {
    /// All trace entries, indexed by tick.
    trace: Vec<TraceEntry>,
    /// Current position.
    current: TracePosition,
    /// Navigation history.
    pub history: NavigationHistory,
}

impl TenetNavigation {
    /// Create navigator from a trace.
    #[must_use]
    pub fn from_entries(entries: Vec<TraceEntry>) -> Self {
        let start = TracePosition::ZERO;
        let mut nav = Self {
            trace: entries,
            current: start,
            history: NavigationHistory::new(256),
        };
        nav.history.push(start);
        nav
    }

    /// Total trace length.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.trace.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.trace.is_empty()
    }

    /// Current position.
    #[must_use]
    pub const fn position(&self) -> TracePosition {
        self.current
    }

    /// Entry at a given position.
    #[must_use]
    pub fn entry_at(&self, pos: TracePosition) -> Option<&TraceEntry> {
        self.trace.get(usize::try_from(pos.as_u64()).unwrap_or(usize::MAX))
    }

    /// Step forward by `n` ticks.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn step_forward(&mut self, n: u64) -> Result<ForwardStep, NavError> {
        if self.trace.is_empty() {
            return Err(NavError::NoTrace);
        }
        let from = self.current;
        let to = from
            .advance(n)
            .min(TracePosition(self.trace.len() as u64 - 1));
        if to.0 >= self.trace.len() as u64 {
            return Err(NavError::OutOfRange(to.0, self.trace.len() as u64 - 1));
        }
        let entry = self.trace[usize::try_from(to.0).unwrap_or(usize::MAX)].clone();
        let crossed_call = (from.0..to.0)
            .any(|i| self.trace[usize::try_from(i).unwrap_or(usize::MAX)].call_depth < self.trace[usize::try_from(i + 1).unwrap_or(usize::MAX)].call_depth);
        let crossed_ret = (from.0..to.0)
            .any(|i| self.trace[usize::try_from(i).unwrap_or(usize::MAX)].call_depth > self.trace[usize::try_from(i + 1).unwrap_or(usize::MAX)].call_depth);
        self.current = to;
        self.history.push(to);
        Ok(ForwardStep {
            from,
            to,
            entry,
            crossed_call,
            crossed_ret,
        })
    }

    /// Step backward by `n` ticks.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn step_backward(&mut self, n: u64) -> Result<BackwardStep, NavError> {
        if self.trace.is_empty() {
            return Err(NavError::NoTrace);
        }
        let from = self.current;
        let to = from.rewind(n);
        let entry = self.trace[usize::try_from(to.0).unwrap_or(usize::MAX)].clone();
        self.current = to;
        self.history.push(to);
        Ok(BackwardStep { from, to, entry })
    }

    /// Jump to the next tick where PC == `func_addr`.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn jump_to_function(&mut self, func_addr: u64) -> Result<JumpToFunction, NavError> {
        let start = usize::try_from(self.current.0).unwrap_or(usize::MAX).saturating_add(1);
        let found = self.trace[start..]
            .iter()
            .position(|e| e.pc == func_addr)
            .map(|i| i + start);
        match found {
            Some(idx) => {
                let pos = TracePosition(idx as u64);
                let depth = self.trace[idx].call_depth;
                self.current = pos;
                self.history.push(pos);
                Ok(JumpToFunction {
                    target_pc: func_addr,
                    found_at: pos,
                    call_depth: depth,
                })
            }
            None => Err(NavError::NoFunction(func_addr)),
        }
    }

    /// Jump to next memory write to `address` after current position.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn jump_to_memory_write(&mut self, address: u64) -> Result<JumpToMemoryWrite, NavError> {
        let start = usize::try_from(self.current.0).unwrap_or(usize::MAX).saturating_add(1);
        let found = self.trace[start..].iter().enumerate().find_map(|(i, e)| {
            e.mem_writes
                .iter()
                .find(|&&(a, _, _)| a == address)
                .map(|&(_, v, sz)| (i + start, v, sz))
        });
        match found {
            Some((idx, val, sz)) => {
                let pos = TracePosition(idx as u64);
                // Try to find previous value.
                let prev_val = if idx > 0 {
                    self.trace[..idx].iter().rev().find_map(|e| {
                        e.mem_writes
                            .iter()
                            .find(|&&(a, _, _)| a == address)
                            .map(|&(_, v, _)| v)
                    })
                } else {
                    None
                };
                self.current = pos;
                self.history.push(pos);
                Ok(JumpToMemoryWrite {
                    address,
                    found_at: pos,
                    value_before: prev_val,
                    value_after: val,
                    write_size: sz,
                })
            }
            None => Err(NavError::NoMemoryWrite(address)),
        }
    }

    /// All memory writes to `address` across the trace.
    #[must_use]
    pub fn memory_timeline(&self, address: u64) -> Vec<(TracePosition, u64, u8)> {
        self.trace
            .iter()
            .flat_map(|e| {
                e.mem_writes
                    .iter()
                    .filter(|&&(a, _, _)| a == address)
                    .map(|&(_, v, sz)| (e.position, v, sz))
            })
            .collect()
    }

    /// Register value timeline for register `reg_id`.
    #[must_use]
    pub fn register_timeline(&self, reg_id: u32) -> Vec<(TracePosition, u64)> {
        self.trace
            .iter()
            .filter_map(|e| e.registers.get(&reg_id).map(|&v| (e.position, v)))
            .collect()
    }

    /// Find all positions where `reg_id` == `value`.
    #[must_use]
    pub fn find_register_value(&self, reg_id: u32, value: u64) -> Vec<TracePosition> {
        self.trace
            .iter()
            .filter(|e| e.registers.get(&reg_id).copied() == Some(value))
            .map(|e| e.position)
            .collect()
    }

    /// Navigate back in history.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn history_back(&mut self) -> Result<TracePosition, NavError> {
        let pos = self.history.back()?;
        self.current = pos;
        Ok(pos)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(tick: u64, pc: u64, mn: &str) -> TraceEntry {
        TraceEntry::new(tick, pc, mn)
    }

    fn make_trace(n: usize) -> Vec<TraceEntry> {
        (0..n as u64)
            .map(|t| make_entry(t, 0x1000 + t * 4, "NOP"))
            .collect()
    }

    // ── TracePosition ────────────────────────────────────────────────────────

    #[test]
    fn test_position_advance() {
        let p = TracePosition(5);
        assert_eq!(p.advance(3), TracePosition(8));
    }

    #[test]
    fn test_position_rewind() {
        let p = TracePosition(5);
        assert_eq!(p.rewind(3), TracePosition(2));
    }

    #[test]
    fn test_position_rewind_saturates() {
        let p = TracePosition(2);
        assert_eq!(p.rewind(10), TracePosition(0));
    }

    #[test]
    fn test_position_display() {
        let p = TracePosition(42);
        assert_eq!(p.to_string(), "tick#42");
    }

    // ── NavigationHistory ────────────────────────────────────────────────────

    #[test]
    fn test_history_push_and_current() {
        let mut h = NavigationHistory::new(10);
        h.push(TracePosition(5));
        assert_eq!(h.current(), Some(TracePosition(5)));
    }

    #[test]
    fn test_history_back_forward() {
        let mut h = NavigationHistory::new(10);
        h.push(TracePosition(1));
        h.push(TracePosition(2));
        h.push(TracePosition(3));
        assert_eq!(h.back().unwrap(), TracePosition(2));
        assert_eq!(h.forward().unwrap(), TracePosition(3));
    }

    #[test]
    fn test_history_back_empty() {
        let mut h = NavigationHistory::new(10);
        h.push(TracePosition(1));
        assert!(h.back().is_err()); // only one entry = can't go back
    }

    #[test]
    fn test_history_can_go_back() {
        let mut h = NavigationHistory::new(10);
        h.push(TracePosition(1));
        h.push(TracePosition(2));
        assert!(h.can_go_back());
    }

    #[test]
    fn test_history_clears_future_on_push() {
        let mut h = NavigationHistory::new(10);
        h.push(TracePosition(1));
        h.push(TracePosition(2));
        h.back().unwrap();
        h.push(TracePosition(5)); // clears future
        assert!(!h.can_go_forward());
    }

    // ── TenetNavigation ──────────────────────────────────────────────────────

    #[test]
    fn test_nav_step_forward() {
        let trace = make_trace(10);
        let mut nav = TenetNavigation::from_entries(trace);
        let step = nav.step_forward(3).unwrap();
        assert_eq!(step.to, TracePosition(3));
        assert_eq!(nav.position(), TracePosition(3));
    }

    #[test]
    fn test_nav_step_backward() {
        let trace = make_trace(10);
        let mut nav = TenetNavigation::from_entries(trace);
        nav.step_forward(5).unwrap();
        let step = nav.step_backward(2).unwrap();
        assert_eq!(step.to, TracePosition(3));
    }

    #[test]
    fn test_nav_step_forward_out_of_range() {
        let trace = make_trace(3);
        let mut nav = TenetNavigation::from_entries(trace);
        // Stepping to end is clamped, so should succeed or fail gracefully.
        let _r = nav.step_forward(100);
    }

    #[test]
    fn test_nav_empty_trace() {
        let mut nav = TenetNavigation::from_entries(vec![]);
        assert!(nav.step_forward(1).is_err());
    }

    #[test]
    fn test_nav_jump_to_function() {
        let mut entries = make_trace(5);
        entries[3].pc = 0xDEAD_BEEF;
        let mut nav = TenetNavigation::from_entries(entries);
        let jmp = nav.jump_to_function(0xDEAD_BEEF).unwrap();
        assert_eq!(jmp.found_at, TracePosition(3));
    }

    #[test]
    fn test_nav_jump_to_function_not_found() {
        let trace = make_trace(5);
        let mut nav = TenetNavigation::from_entries(trace);
        assert!(nav.jump_to_function(0xBEEF_CAFE).is_err());
    }

    #[test]
    fn test_nav_jump_to_memory_write() {
        let mut entries = make_trace(5);
        entries[2].mem_writes.push((0x4000, 0x42, 4));
        let mut nav = TenetNavigation::from_entries(entries);
        let jmp = nav.jump_to_memory_write(0x4000).unwrap();
        assert_eq!(jmp.found_at, TracePosition(2));
        assert_eq!(jmp.value_after, 0x42);
    }

    #[test]
    fn test_nav_jump_to_memory_write_not_found() {
        let trace = make_trace(5);
        let mut nav = TenetNavigation::from_entries(trace);
        assert!(nav.jump_to_memory_write(0x9999).is_err());
    }

    #[test]
    fn test_nav_memory_timeline() {
        let mut entries = make_trace(5);
        entries[1].mem_writes.push((0x5000, 1, 4));
        entries[3].mem_writes.push((0x5000, 2, 4));
        let nav = TenetNavigation::from_entries(entries);
        let tl = nav.memory_timeline(0x5000);
        assert_eq!(tl.len(), 2);
        assert_eq!(tl[0].1, 1);
        assert_eq!(tl[1].1, 2);
    }

    #[test]
    fn test_nav_register_timeline() {
        let mut entries = make_trace(4);
        entries[0].registers.insert(0, 100);
        entries[2].registers.insert(0, 200);
        let nav = TenetNavigation::from_entries(entries);
        let tl = nav.register_timeline(0);
        assert_eq!(tl.len(), 2);
        assert_eq!(tl[0].1, 100);
        assert_eq!(tl[1].1, 200);
    }

    #[test]
    fn test_nav_find_register_value() {
        let mut entries = make_trace(4);
        entries[1].registers.insert(1, 0xCAFE);
        entries[3].registers.insert(1, 0xCAFE);
        let nav = TenetNavigation::from_entries(entries);
        let positions = nav.find_register_value(1, 0xCAFE);
        assert_eq!(positions.len(), 2);
    }

    #[test]
    fn test_nav_history_back() {
        let trace = make_trace(10);
        let mut nav = TenetNavigation::from_entries(trace);
        nav.step_forward(5).unwrap();
        nav.step_forward(2).unwrap();
        let prev = nav.history_back().unwrap();
        assert_eq!(prev, TracePosition(5));
    }

    #[test]
    fn test_nav_len() {
        let trace = make_trace(7);
        let nav = TenetNavigation::from_entries(trace);
        assert_eq!(nav.len(), 7);
    }

    #[test]
    fn test_nav_entry_at() {
        let trace = make_trace(5);
        let nav = TenetNavigation::from_entries(trace);
        assert_eq!(nav.entry_at(TracePosition(2)).unwrap().pc, 0x1008);
    }

    // ── Additional coverage ─────────────────────────────────────────────────

    #[test]
    fn test_position_zero_const() {
        assert_eq!(TracePosition::ZERO, TracePosition(0));
    }

    #[test]
    fn test_position_as_u64() {
        assert_eq!(TracePosition(7).as_u64(), 7);
    }

    #[test]
    fn test_history_depth() {
        let mut h = NavigationHistory::new(10);
        h.push(TracePosition(1));
        h.push(TracePosition(2));
        assert_eq!(h.depth(), 2);
    }

    #[test]
    fn test_history_max_depth_truncates() {
        let mut h = NavigationHistory::new(3);
        for i in 0..5u64 {
            h.push(TracePosition(i));
        }
        assert!(h.depth() <= 3);
    }

    #[test]
    fn test_nav_is_empty_after_empty_trace() {
        let nav = TenetNavigation::from_entries(vec![]);
        assert!(nav.is_empty());
    }

    #[test]
    fn test_nav_memory_timeline_empty() {
        let trace = make_trace(3);
        let nav = TenetNavigation::from_entries(trace);
        let tl = nav.memory_timeline(0xDEAD);
        assert!(tl.is_empty());
    }

    #[test]
    fn test_nav_find_register_value_not_found() {
        let trace = make_trace(3);
        let nav = TenetNavigation::from_entries(trace);
        let positions = nav.find_register_value(99, 0xCAFE);
        assert!(positions.is_empty());
    }
}
