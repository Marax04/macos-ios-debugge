//! Backward navigation in an execution trace.
//!
//! Provides:
//! - `ReverseStep` — a description of the register/memory state change to undo.
//! - `BackwardSearchResult` — the result of a backward search query.
//! - `BackwardNavigator` — step backward from a given position, undo state.
//!
//! Complements `TraceNavigator` with dedicated reverse-execution helpers:
//! `find_last_write()` and `find_caller()`.

/// Re-export of [`std::collections::HashMap`] for downstream backward-nav
/// callers that need to build per-address indexes alongside this module.
pub use std::collections::HashMap;

/// Re-export of [`crate::AccessKind`] for callers driving reverse memory
/// queries through [`BackwardNavigator`].
pub use crate::AccessKind;

use crate::{
    Address, EntryKind, ExecutionTrace, MemAccessIndex, RegId, RegTimeline, StackFrame, TraceEntry,
};

// ---------------------------------------------------------------------------
// ReverseStep
// ---------------------------------------------------------------------------

/// Describes the register and memory changes that occurred at a single
/// trace entry so they can be *undone* during backward navigation.
#[derive(Debug, Clone)]
pub struct ReverseStep {
    /// Trace index this reverse-step belongs to.
    pub trace_idx: usize,
    /// Program counter at this step.
    pub pc: Address,
    /// Register values *before* the instruction executed, so they can be
    /// restored when stepping backward past this instruction.
    pub register_restore: Vec<(RegId, u64)>,
    /// Memory addresses written *by* this instruction together with the
    /// byte values they contained *before* the write (for restoration).
    pub memory_restore: Vec<(Address, Vec<u8>)>,
    /// Whether this step crossed a function call boundary.
    pub is_call: bool,
    /// Whether this step crossed a function return boundary.
    pub is_ret: bool,
}

impl ReverseStep {
    /// Create a new `ReverseStep` from a trace entry.
    #[must_use]
    pub const fn from_entry(entry: &TraceEntry) -> Self {
        let is_call = matches!(entry.kind, EntryKind::Call { .. });
        let is_ret = matches!(entry.kind, EntryKind::Ret { .. });
        // The register_restore values represent the state *before* this
        // instruction; we record them from the snapshot of the *previous*
        // entry (handled by `BackwardNavigator::build`).
        Self {
            trace_idx: entry.idx,
            pc: entry.pc,
            register_restore: Vec::new(),
            memory_restore: Vec::new(),
            is_call,
            is_ret,
        }
    }

    /// Whether this step has any state changes to undo.
    #[must_use]
    pub const fn has_changes(&self) -> bool {
        !self.register_restore.is_empty() || !self.memory_restore.is_empty()
    }
}

impl std::fmt::Display for ReverseStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ReverseStep[{}] pc=0x{:x} regs={} mem={}",
            self.trace_idx,
            self.pc,
            self.register_restore.len(),
            self.memory_restore.len()
        )
    }
}

// ---------------------------------------------------------------------------
// BackwardSearchResult
// ---------------------------------------------------------------------------

/// The outcome of a backward search (e.g., `find_last_write`).
#[derive(Debug, Clone)]
pub struct BackwardSearchResult {
    /// Trace index where the match was found.
    pub trace_idx: usize,
    /// Program counter at the matching entry.
    pub pc: Address,
    /// The thread ID of the matching entry.
    pub tid: u32,
    /// Value written or read at the matched location.
    pub value: Option<u64>,
    /// Human-readable disassembly or description.
    pub disasm: String,
}

impl BackwardSearchResult {
    /// Construct from a `TraceEntry` plus optional value.
    #[must_use]
    pub fn from_entry(entry: &TraceEntry, value: Option<u64>) -> Self {
        Self {
            trace_idx: entry.idx,
            pc: entry.pc,
            tid: entry.tid,
            value,
            disasm: entry.disasm.clone(),
        }
    }
}

impl std::fmt::Display for BackwardSearchResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BackwardResult[{}] pc=0x{:x} tid={} {}",
            self.trace_idx, self.pc, self.tid, self.disasm
        )
    }
}

// ---------------------------------------------------------------------------
// BackwardNavigator
// ---------------------------------------------------------------------------

/// Backward-navigation helper for an `ExecutionTrace`.
///
/// Builds a `Vec<ReverseStep>` once at construction time so that any
/// backward navigation operation is O(1) per step.
pub struct BackwardNavigator {
    /// Reference to the underlying trace.
    trace: ExecutionTrace,
    /// One `ReverseStep` per trace entry, indexed by `entry.idx`.
    reverse_steps: Vec<ReverseStep>,
    /// Memory access index (forward).
    mem_index: MemAccessIndex,
    /// Register timeline (forward).
    reg_timeline: RegTimeline,
    /// Current cursor position (trace index).
    pub current_idx: usize,
}

impl BackwardNavigator {
    /// Build a `BackwardNavigator` from a complete `ExecutionTrace`.
    ///
    /// Constructs `ReverseStep` records for every entry so backward
    /// navigation can be performed without rescanning from the start.
    #[must_use]
    pub fn new(trace: ExecutionTrace) -> Self {
        let mem_index = MemAccessIndex::build(&trace);
        let reg_timeline = RegTimeline::build(&trace);

        let mut reverse_steps: Vec<ReverseStep> =
            trace.entries.iter().map(ReverseStep::from_entry).collect();

        // Populate register_restore: for each entry, the restore values
        // are the register values that were current *before* that entry
        // executed, i.e., the most recent snapshot at idx-1.
        for (i, step) in reverse_steps.iter_mut().enumerate().skip(1) {
            let idx = step.trace_idx;
            // Collect registers changed at this entry
            let changed_regs: Vec<RegId> = trace.entries[i]
                .reg_snapshot
                .iter()
                .map(|(r, _)| *r)
                .collect();
            for reg in changed_regs {
                // The value before this step is the value at idx - 1
                let prev_val = reg_timeline.value_at(reg, idx - 1);
                if let Some(val) = prev_val {
                    step.register_restore.push((reg, val));
                }
            }
            // Populate memory_restore: values written at this entry
            for (addr, _bytes) in &trace.entries[i].mem_writes {
                let prev_val = mem_index.value_at_idx(*addr, idx);
                let prev_bytes = prev_val.map_or_else(|| vec![0u8; 8], |v| v.to_le_bytes().to_vec());
                step.memory_restore.push((*addr, prev_bytes));
            }
        }

        let current_idx = if trace.entries.is_empty() {
            0
        } else {
            trace.entries.len() - 1
        };

        Self {
            trace,
            reverse_steps,
            mem_index,
            reg_timeline,
            current_idx,
        }
    }

    /// Current trace entry (at `current_idx`).
    #[must_use]
    pub fn current_entry(&self) -> Option<&TraceEntry> {
        self.trace.get(self.current_idx)
    }

    // ── Basic Backward Navigation ─────────────────────────────────────────────

    /// Step backward by one instruction.
    /// Returns `true` if successful, `false` if already at the start.
    pub const fn step_backward(&mut self) -> bool {
        if self.current_idx == 0 {
            return false;
        }
        self.current_idx -= 1;
        true
    }

    /// Step forward by one instruction.
    /// Returns `true` if successful, `false` if already at the end.
    pub const fn step_forward(&mut self) -> bool {
        if self.current_idx + 1 >= self.trace.len() {
            return false;
        }
        self.current_idx += 1;
        true
    }

    /// Jump to a specific trace index.
    pub const fn jump_to(&mut self, idx: usize) -> bool {
        if idx < self.trace.len() {
            self.current_idx = idx;
            true
        } else {
            false
        }
    }

    /// Jump to the last trace entry.
    pub const fn jump_to_end(&mut self) {
        if !self.trace.is_empty() {
            self.current_idx = self.trace.len() - 1;
        }
    }

    /// The `ReverseStep` record for the current position.
    #[must_use]
    pub fn current_reverse_step(&self) -> Option<&ReverseStep> {
        self.reverse_steps.get(self.current_idx)
    }

    // ── find_last_write ───────────────────────────────────────────────────────

    /// Find the last time `addr` was written to *before* position `before_idx`.
    ///
    /// Returns a `BackwardSearchResult` describing the write, or `None` if
    /// no write to `addr` exists before `before_idx`.
    #[must_use]
    pub fn find_last_write(
        &self,
        addr: Address,
        before_idx: usize,
    ) -> Option<BackwardSearchResult> {
        let writes = self.mem_index.writes(addr);
        // writes are in ascending idx order; find the last one < before_idx
        let (write_idx, value) = writes.into_iter().rev().find(|(i, _)| *i < before_idx)?;
        let entry = self.trace.get(write_idx)?;
        Some(BackwardSearchResult::from_entry(entry, Some(value)))
    }

    /// Find the last time `addr` was written to *at or before* `at_idx`.
    #[must_use]
    pub fn find_last_write_at_or_before(
        &self,
        addr: Address,
        at_idx: usize,
    ) -> Option<BackwardSearchResult> {
        let writes = self.mem_index.writes(addr);
        let (write_idx, value) = writes.into_iter().rev().find(|(i, _)| *i <= at_idx)?;
        let entry = self.trace.get(write_idx)?;
        Some(BackwardSearchResult::from_entry(entry, Some(value)))
    }

    /// Find all writes to `addr` before `before_idx`, newest first.
    #[must_use]
    pub fn find_all_writes_before(
        &self,
        addr: Address,
        before_idx: usize,
    ) -> Vec<BackwardSearchResult> {
        self.mem_index
            .writes(addr)
            .into_iter()
            .rev()
            .filter(|(i, _)| *i < before_idx)
            .filter_map(|(write_idx, value)| {
                let entry = self.trace.get(write_idx)?;
                Some(BackwardSearchResult::from_entry(entry, Some(value)))
            })
            .collect()
    }

    // ── find_caller ───────────────────────────────────────────────────────────

    /// Find the most recent CALL instruction that led to the function containing
    /// `at_idx` by scanning backward for a `Call` entry whose `ret_addr` appears
    /// after `at_idx` in the trace.
    ///
    /// Returns a `BackwardSearchResult` for the call site, plus the reconstructed
    /// `StackFrame` if available.
    #[must_use]
    pub fn find_caller(&self, at_idx: usize) -> Option<(BackwardSearchResult, StackFrame)> {
        // Walk backward from at_idx, tracking how many frames have already been
        // closed.
        //
        // Stopping at the first `Call` seen — as this did — hands back frames
        // that have already RETURNED: with `call A; call B; ret; …` the call to
        // B is the first one encountered going backward, but it was popped by
        // the return, and the live frame is A's.
        //
        // Every `Ret` passed on the way back means one more `Call` to skip.
        // This is the same correction already made in `rustre-ttd-replay`'s
        // backward stepper.
        //
        // The old `current_pc >= target` test is dropped: comparing addresses
        // is a weak proxy for "this call contains that instruction" — the
        // call/return nesting is the real relation, and it is now tracked
        // exactly.
        let mut closed = 0usize;
        for i in (0..at_idx).rev() {
            let entry = self.trace.get(i)?;
            match entry.kind {
                EntryKind::Ret { .. } => closed += 1,
                EntryKind::Call { target, ret_addr } => {
                    if closed > 0 {
                        closed -= 1;
                        continue;
                    }
                    let frame = StackFrame::new(target, ret_addr, 0, i);
                    let result = BackwardSearchResult::from_entry(entry, None);
                    return Some((result, frame));
                }
                _ => {}
            }
        }
        None
    }

    /// Find all CALL entries before `before_idx` whose target matches `func_addr`.
    #[must_use]
    pub fn find_all_callers(
        &self,
        func_addr: Address,
        before_idx: usize,
    ) -> Vec<BackwardSearchResult> {
        self.trace
            .entries
            .iter()
            .filter(|e| e.idx < before_idx)
            .filter_map(|e| {
                if let EntryKind::Call { target, .. } = e.kind
                    && target == func_addr {
                        return Some(BackwardSearchResult::from_entry(e, None));
                    }
                None
            })
            .collect()
    }

    // ── Register / Memory State Queries ──────────────────────────────────────

    /// Reconstruct the value of register `reg` at trace index `idx`.
    #[must_use]
    pub fn reg_at(&self, reg: RegId, idx: usize) -> Option<u64> {
        self.reg_timeline.value_at(reg, idx)
    }

    /// Reconstruct the memory value at `addr` as it was just before `idx`.
    #[must_use]
    pub fn mem_at(&self, addr: Address, idx: usize) -> Option<u64> {
        self.mem_index.value_at_idx(addr, idx)
    }

    /// All trace indices where register `reg` changed value.
    #[must_use]
    pub fn reg_change_indices(&self, reg: RegId) -> Vec<(usize, u64)> {
        self.reg_timeline.history(reg, 0..self.trace.len())
    }

    // ── Slice / Window queries ────────────────────────────────────────────────

    /// Return the `n` entries before `current_idx` (newest first).
    #[must_use]
    pub fn look_back(&self, n: usize) -> Vec<&TraceEntry> {
        let end = self.current_idx;
        let start = end.saturating_sub(n);
        self.trace.entries[start..end].iter().rev().collect()
    }

    /// Return the `ReverseStep` records for the last `n` steps.
    #[must_use]
    pub fn reverse_window(&self, n: usize) -> Vec<&ReverseStep> {
        let end = self.current_idx + 1;
        let start = end.saturating_sub(n);
        self.reverse_steps[start..end].iter().rev().collect()
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Total number of trace entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.trace.len()
    }

    /// Whether the trace is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.trace.is_empty()
    }

    /// Whether the navigator is at the beginning of the trace.
    #[must_use]
    pub const fn at_beginning(&self) -> bool {
        self.current_idx == 0
    }

    /// Whether the navigator is at the end of the trace.
    #[must_use]
    pub const fn at_end(&self) -> bool {
        self.trace.is_empty() || self.current_idx + 1 >= self.trace.len()
    }
}

impl std::fmt::Debug for BackwardNavigator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BackwardNavigator {{ len={}, current={} }}",
            self.len(),
            self.current_idx
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TraceBuilder;

    fn build_nav() -> BackwardNavigator {
        let mut tb = TraceBuilder::new("test");
        tb.insn(0x1000, 1, "push rbp");
        tb.insn(0x1001, 1, "mov rbp, rsp");
        tb.call(0x1005, 1, 0x2000, 0x100a);
        tb.insn(0x2000, 1, "xor eax, eax");
        tb.ret(0x2001, 1, 0x100a);
        tb.insn(0x100a, 1, "pop rbp");
        tb.insn(0x100b, 1, "ret");
        // Add some memory writes
        tb.mem_write(0xdead_beef, vec![0x42, 0x00, 0x00, 0x00]);
        let trace = tb.build();
        BackwardNavigator::new(trace)
    }

    #[test]
    fn test_new_starts_at_end() {
        let nav = build_nav();
        // By default starts at the last entry
        assert!(!nav.is_empty());
        assert!(nav.at_end());
    }

    #[test]
    fn test_step_backward_decrements() {
        let mut nav = build_nav();
        let start = nav.current_idx;
        assert!(nav.step_backward());
        assert_eq!(nav.current_idx, start - 1);
    }

    #[test]
    fn test_step_backward_at_zero() {
        let mut nav = build_nav();
        nav.jump_to(0);
        assert!(!nav.step_backward());
        assert_eq!(nav.current_idx, 0);
    }

    #[test]
    fn test_step_forward_increments() {
        let mut nav = build_nav();
        nav.jump_to(0);
        assert!(nav.step_forward());
        assert_eq!(nav.current_idx, 1);
    }

    #[test]
    fn test_step_forward_at_end() {
        let mut nav = build_nav();
        assert!(!nav.step_forward());
    }

    #[test]
    fn test_jump_to_valid() {
        let mut nav = build_nav();
        assert!(nav.jump_to(2));
        assert_eq!(nav.current_idx, 2);
    }

    #[test]
    fn test_jump_to_invalid() {
        let mut nav = build_nav();
        assert!(!nav.jump_to(9999));
    }

    #[test]
    fn test_at_beginning_after_jump() {
        let mut nav = build_nav();
        nav.jump_to(0);
        assert!(nav.at_beginning());
    }

    #[test]
    fn test_current_entry() {
        let mut nav = build_nav();
        nav.jump_to(0);
        let entry = nav.current_entry().unwrap();
        assert_eq!(entry.idx, 0);
        assert_eq!(entry.pc, 0x1000);
    }

    #[test]
    fn test_reverse_step_count_matches_trace() {
        let nav = build_nav();
        assert_eq!(nav.reverse_steps.len(), nav.len());
    }

    #[test]
    fn test_find_last_write_no_write() {
        let nav = build_nav();
        let result = nav.find_last_write(0x9999, nav.len());
        assert!(result.is_none());
    }

    #[test]
    fn test_find_last_write_existing() {
        let mut tb = TraceBuilder::new("mem_test");
        tb.insn(0x1000, 1, "mov [addr], 1");
        tb.mem_write(0xdead, vec![0x01, 0x00, 0x00, 0x00]);
        tb.insn(0x1001, 1, "nop");
        let trace = tb.build();
        let nav = BackwardNavigator::new(trace);
        let result = nav.find_last_write(0xdead, nav.len());
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.value, Some(0x01));
    }

    #[test]
    fn test_find_all_callers_empty_when_no_calls() {
        let mut tb = TraceBuilder::new("no_calls");
        tb.insn(0x1000, 1, "nop");
        tb.insn(0x1001, 1, "nop");
        let trace = tb.build();
        let nav = BackwardNavigator::new(trace);
        let callers = nav.find_all_callers(0x9999, nav.len());
        assert!(callers.is_empty());
    }

    #[test]
    fn test_find_all_callers_finds_call() {
        let nav = build_nav();
        let callers = nav.find_all_callers(0x2000, nav.len());
        assert!(!callers.is_empty());
        assert_eq!(callers[0].pc, 0x1005);
    }

    #[test]
    fn test_find_caller_returns_frame() {
        let nav = build_nav();
        // At trace index 3 we are inside function 0x2000
        let result = nav.find_caller(3);
        assert!(result.is_some());
        let (bsr, frame) = result.unwrap();
        assert_eq!(frame.fn_addr, 0x2000);
        assert_eq!(bsr.pc, 0x1005);
    }

    #[test]
    fn test_look_back() {
        let mut nav = build_nav();
        nav.jump_to(3);
        let entries = nav.look_back(2);
        assert_eq!(entries.len(), 2);
        // Should be entries at indices 2 and 1, newest first
        assert_eq!(entries[0].idx, 2);
    }

    #[test]
    fn test_reverse_step_display() {
        let nav = build_nav();
        let rs = &nav.reverse_steps[0];
        let s = rs.to_string();
        assert!(s.contains("ReverseStep"));
        assert!(s.contains("0x1000"));
    }

    #[test]
    fn test_backward_search_result_display() {
        let mut nav = build_nav();
        nav.jump_to(0);
        let entry = nav.current_entry().unwrap();
        let r = BackwardSearchResult::from_entry(entry, Some(42));
        let s = r.to_string();
        assert!(s.contains("0x1000"));
    }
}
