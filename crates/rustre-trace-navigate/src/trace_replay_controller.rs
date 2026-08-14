//! `trace_replay_controller` — Step-by-step replay of recorded execution traces
//! with breakpoint support, state snapshots at each step, and a `ReplaySession`.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{Address, EntryKind, ExecutionTrace, RegId, StackFrame, TraceEntry};

// ─── ReplayError ─────────────────────────────────────────────────────────────

/// Errors from the replay subsystem.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("replay index {0} is out of bounds (trace len={1})")]
    OutOfBounds(usize, usize),
    #[error("replay session has no loaded trace")]
    NoTrace,
    #[error("breakpoint already exists at pc=0x{0:x}")]
    DuplicateBreakpoint(Address),
    #[error("breakpoint not found at pc=0x{0:x}")]
    BreakpointNotFound(Address),
    #[error("snapshot {0} not found")]
    SnapshotNotFound(String),
    #[error("replay reached end of trace")]
    EndOfTrace,
    #[error("replay reached beginning of trace")]
    BeginningOfTrace,
    #[error("step limit exceeded")]
    StepLimitExceeded,
}

// ─── Breakpoint ───────────────────────────────────────────────────────────────

/// A replay breakpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Breakpoint {
    /// The PC address that triggers the breakpoint.
    pub pc: Address,
    /// Whether this breakpoint is currently active.
    pub enabled: bool,
    /// Hit count since the last reset.
    pub hit_count: u64,
    /// If `Some(n)`, the breakpoint only fires every n-th hit.
    pub hit_stride: Option<u64>,
    /// Optional human-readable label.
    pub label: Option<String>,
    /// If set, the breakpoint fires only when the call depth is exactly this value.
    pub depth_filter: Option<u32>,
}

impl Breakpoint {
    /// Create a new enabled breakpoint at `pc`.
    #[must_use]
    pub const fn new(pc: Address) -> Self {
        Self {
            pc,
            enabled: true,
            hit_count: 0,
            hit_stride: None,
            label: None,
            depth_filter: None,
        }
    }

    /// Attach a label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Set a hit stride so the breakpoint only fires every `n` hits.
    #[must_use]
    pub const fn with_stride(mut self, n: u64) -> Self {
        self.hit_stride = Some(n);
        self
    }

    /// Returns true if this breakpoint fires for the current hit.
    const fn should_fire(&self) -> bool {
        if !self.enabled {
            return false;
        }
        match self.hit_stride {
            None | Some(0) => true,
            Some(s) => self.hit_count.is_multiple_of(s),
        }
    }
}

// ─── ReplayStateSnapshot ─────────────────────────────────────────────────────

/// A named snapshot of the replay state at a specific trace index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayStateSnapshot {
    /// User-assigned name.
    pub name: String,
    /// Trace index at snapshot time.
    pub idx: usize,
    /// PC at snapshot time.
    pub pc: Address,
    /// Register values at snapshot time.
    pub regs: HashMap<RegId, u64>,
    /// Call stack at snapshot time.
    pub call_stack: Vec<StackFrame>,
    /// Memory writes seen up to this point (address → latest value).
    pub memory_view: HashMap<Address, Vec<u8>>,
    /// Wall-clock tick when the snapshot was taken (replay internal counter).
    pub replay_tick: u64,
}

// ─── StepResult ───────────────────────────────────────────────────────────────

/// Result of a single replay step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StepResult {
    /// Stepped to the next instruction.
    Stepped {
        from_idx: usize,
        to_idx: usize,
        to_pc: Address,
    },
    /// Hit a breakpoint while stepping.
    BreakpointHit {
        idx: usize,
        pc: Address,
        breakpoint_label: Option<String>,
    },
    /// Reached the end of the trace while stepping forward.
    End,
    /// Reached the beginning of the trace while stepping backward.
    Beginning,
    /// Step limit was exceeded (guard against infinite loops in `run_until`).
    StepLimitExceeded { steps_taken: usize },
}

impl StepResult {
    /// Returns true if this result indicates a breakpoint was hit.
    #[must_use]
    pub const fn is_breakpoint(&self) -> bool {
        matches!(self, Self::BreakpointHit { .. })
    }

    /// Returns true if the trace ended.
    #[must_use]
    pub const fn is_end(&self) -> bool {
        matches!(self, Self::End | Self::Beginning)
    }

    /// Current index after the step, if available.
    #[must_use]
    pub const fn current_idx(&self) -> Option<usize> {
        match self {
            Self::Stepped { to_idx, .. } => Some(*to_idx),
            Self::BreakpointHit { idx, .. } => Some(*idx),
            _ => None,
        }
    }
}

// ─── ReplaySession ────────────────────────────────────────────────────────────

/// A stateful replay session over an execution trace.
///
/// Supports:
/// - Forward and backward single-step
/// - Run until breakpoint or address (forward/backward)
/// - Step over / step out (using call depth)
/// - Named state snapshots
/// - Breakpoint management (add/remove/enable/disable)
/// - Memory view reconstruction at any point
pub struct ReplaySession {
    trace: ExecutionTrace,
    /// Current position.
    pub current_idx: usize,
    /// All registered breakpoints: pc -> breakpoint.
    pub breakpoints: HashMap<Address, Breakpoint>,
    /// Named snapshots.
    pub snapshots: HashMap<String, ReplayStateSnapshot>,
    /// Current replay tick (increments on each step).
    pub replay_tick: u64,
    /// Step limit guard for `run_until` operations.
    pub step_limit: usize,
    /// Reconstructed memory view: address -> latest bytes written.
    memory_view: HashMap<Address, Vec<u8>>,
    /// Reconstructed register view: `reg_id` -> latest value.
    reg_view: HashMap<RegId, u64>,
    /// Reconstructed call stack.
    call_stack: Vec<StackFrame>,
}

impl ReplaySession {
    /// Create a new replay session from a trace, starting at index 0.
    #[must_use]
    pub fn new(trace: ExecutionTrace) -> Self {
        let mut session = Self {
            trace,
            current_idx: 0,
            breakpoints: HashMap::new(),
            snapshots: HashMap::new(),
            replay_tick: 0,
            step_limit: 10_000_000,
            memory_view: HashMap::new(),
            reg_view: HashMap::new(),
            call_stack: Vec::new(),
        };
        session.rebuild_state_to(0);
        session
    }

    // ── State Reconstruction ──────────────────────────────────────────────────

    /// Rebuild internal state (memory, registers, call stack) by replaying
    /// all entries from 0 up to and including `to_idx`.
    fn rebuild_state_to(&mut self, to_idx: usize) {
        self.memory_view.clear();
        self.reg_view.clear();
        self.call_stack.clear();

        for entry in &self.trace.entries {
            if entry.idx > to_idx {
                break;
            }
            Self::apply_entry_fields(&mut self.memory_view, &mut self.reg_view, &mut self.call_stack, entry);
        }
    }

    fn apply_entry_fields(
        memory_view: &mut HashMap<Address, Vec<u8>>,
        reg_view: &mut HashMap<RegId, u64>,
        call_stack: &mut Vec<StackFrame>,
        entry: &TraceEntry,
    ) {
        for (addr, bytes) in &entry.mem_writes {
            memory_view.insert(*addr, bytes.clone());
        }
        for (reg, val) in &entry.reg_snapshot {
            reg_view.insert(*reg, *val);
        }
        match entry.kind {
            EntryKind::Call { target, ret_addr } => {
                let depth = u32::try_from(call_stack.len()).unwrap_or(u32::MAX);
                call_stack.push(StackFrame::new(target, ret_addr, depth, entry.idx));
            }
            EntryKind::Ret { .. } => {
                call_stack.pop();
            }
            _ => {}
        }
    }

    // ── Navigation ────────────────────────────────────────────────────────────

    /// Current trace entry.
    #[must_use]
    pub fn current_entry(&self) -> Option<&TraceEntry> {
        self.trace.get(self.current_idx)
    }

    /// Step forward by one instruction.
    pub fn step_forward(&mut self) -> StepResult {
        if self.current_idx + 1 >= self.trace.len() {
            return StepResult::End;
        }
        let from = self.current_idx;
        self.current_idx += 1;
        self.replay_tick += 1;

        let entry = &self.trace.entries[self.current_idx];
        Self::apply_entry_fields(&mut self.memory_view, &mut self.reg_view, &mut self.call_stack, entry);

        // Check breakpoints
        if let Some(bp) = self.breakpoints.get_mut(&entry.pc) {
            bp.hit_count += 1;
            if bp.should_fire() {
                let label = bp.label.clone();
                return StepResult::BreakpointHit {
                    idx: self.current_idx,
                    pc: entry.pc,
                    breakpoint_label: label,
                };
            }
        }

        StepResult::Stepped {
            from_idx: from,
            to_idx: self.current_idx,
            to_pc: entry.pc,
        }
    }

    /// Step backward by one instruction (rebuilds state from scratch).
    pub fn step_backward(&mut self) -> StepResult {
        if self.current_idx == 0 {
            return StepResult::Beginning;
        }
        let from = self.current_idx;
        self.current_idx -= 1;
        self.replay_tick += 1;

        // Rebuild state to new index
        self.rebuild_state_to(self.current_idx);

        let entry = &self.trace.entries[self.current_idx];
        StepResult::Stepped {
            from_idx: from,
            to_idx: self.current_idx,
            to_pc: entry.pc,
        }
    }

    /// Jump directly to trace index `idx`.
    ///
    /// # Errors
    /// Returns `ReplayError::OutOfBounds` if idx exceeds trace length.
    pub fn jump_to(&mut self, idx: usize) -> Result<(), ReplayError> {
        if idx >= self.trace.len() {
            return Err(ReplayError::OutOfBounds(idx, self.trace.len()));
        }
        self.current_idx = idx;
        self.rebuild_state_to(idx);
        self.replay_tick += 1;
        Ok(())
    }

    /// Run forward until a breakpoint is hit or the trace ends.
    pub fn run_forward(&mut self) -> StepResult {
        let mut steps = 0;
        loop {
            if steps >= self.step_limit {
                return StepResult::StepLimitExceeded { steps_taken: steps };
            }
            let result = self.step_forward();
            steps += 1;
            match &result {
                StepResult::BreakpointHit { .. } | StepResult::End => return result,
                _ => {}
            }
        }
    }

    /// Run backward until a breakpoint is hit or the beginning is reached.
    pub fn run_backward(&mut self) -> StepResult {
        let mut steps = 0;
        loop {
            if steps >= self.step_limit {
                return StepResult::StepLimitExceeded { steps_taken: steps };
            }
            let result = self.step_backward();
            steps += 1;
            match &result {
                StepResult::Beginning => return result,
                StepResult::Stepped { to_pc, .. } => {
                    if self.breakpoints.contains_key(to_pc)
                        && let Some(bp) = self.breakpoints.get_mut(to_pc) {
                            bp.hit_count += 1;
                            if bp.should_fire() {
                                let label = bp.label.clone();
                                return StepResult::BreakpointHit {
                                    idx: self.current_idx,
                                    pc: *to_pc,
                                    breakpoint_label: label,
                                };
                            }
                        }
                }
                _ => {}
            }
        }
    }

    /// Run forward until `pc` is hit.
    pub fn run_to_pc(&mut self, target_pc: Address) -> StepResult {
        let mut steps = 0;
        loop {
            if steps >= self.step_limit {
                return StepResult::StepLimitExceeded { steps_taken: steps };
            }
            if self.current_idx + 1 >= self.trace.len() {
                return StepResult::End;
            }
            self.current_idx += 1;
            let entry = &self.trace.entries[self.current_idx];
            Self::apply_entry_fields(&mut self.memory_view, &mut self.reg_view, &mut self.call_stack, entry);
            steps += 1;
            if entry.pc == target_pc {
                return StepResult::BreakpointHit {
                    idx: self.current_idx,
                    pc: entry.pc,
                    breakpoint_label: None,
                };
            }
        }
    }

    /// Step over: advance until call depth returns to current level.
    pub fn step_over(&mut self) -> StepResult {
        let target_depth = self.call_stack.len();
        let mut steps = 0;
        let from = self.current_idx;

        loop {
            if steps >= self.step_limit {
                return StepResult::StepLimitExceeded { steps_taken: steps };
            }
            if self.current_idx + 1 >= self.trace.len() {
                return StepResult::End;
            }
            self.current_idx += 1;
            let entry = &self.trace.entries[self.current_idx];
            Self::apply_entry_fields(&mut self.memory_view, &mut self.reg_view, &mut self.call_stack, entry);
            steps += 1;

            if self.call_stack.len() <= target_depth {
                return StepResult::Stepped {
                    from_idx: from,
                    to_idx: self.current_idx,
                    to_pc: entry.pc,
                };
            }
        }
    }

    /// Step out: advance until current function returns.
    pub fn step_out(&mut self) -> StepResult {
        let initial_depth = self.call_stack.len();
        if initial_depth == 0 {
            return StepResult::Stepped {
                from_idx: self.current_idx,
                to_idx: self.current_idx,
                to_pc: self.current_entry().map_or(0, |e| e.pc),
            };
        }
        let target_depth = initial_depth - 1;
        let mut steps = 0;
        let from = self.current_idx;

        loop {
            if steps >= self.step_limit {
                return StepResult::StepLimitExceeded { steps_taken: steps };
            }
            if self.current_idx + 1 >= self.trace.len() {
                return StepResult::End;
            }
            self.current_idx += 1;
            let entry = &self.trace.entries[self.current_idx];
            Self::apply_entry_fields(&mut self.memory_view, &mut self.reg_view, &mut self.call_stack, entry);
            steps += 1;

            if self.call_stack.len() <= target_depth {
                return StepResult::Stepped {
                    from_idx: from,
                    to_idx: self.current_idx,
                    to_pc: entry.pc,
                };
            }
        }
    }

    // ── Breakpoints ───────────────────────────────────────────────────────────

    /// Add a breakpoint at `pc`.
    ///
    /// # Errors
    /// Returns `ReplayError::DuplicateBreakpoint` if a breakpoint already exists there.
    pub fn add_breakpoint(&mut self, bp: Breakpoint) -> Result<(), ReplayError> {
        if self.breakpoints.contains_key(&bp.pc) {
            return Err(ReplayError::DuplicateBreakpoint(bp.pc));
        }
        self.breakpoints.insert(bp.pc, bp);
        Ok(())
    }

    /// Remove a breakpoint at `pc`.
    ///
    /// # Errors
    /// Returns `ReplayError::BreakpointNotFound` if no breakpoint exists there.
    pub fn remove_breakpoint(&mut self, pc: Address) -> Result<(), ReplayError> {
        self.breakpoints
            .remove(&pc)
            .ok_or(ReplayError::BreakpointNotFound(pc))?;
        Ok(())
    }

    /// Enable or disable a breakpoint.
    pub fn set_breakpoint_enabled(&mut self, pc: Address, enabled: bool) {
        if let Some(bp) = self.breakpoints.get_mut(&pc) {
            bp.enabled = enabled;
        }
    }

    /// Clear all breakpoints.
    pub fn clear_breakpoints(&mut self) {
        self.breakpoints.clear();
    }

    /// All breakpoint PCs.
    #[must_use]
    pub fn breakpoint_pcs(&self) -> Vec<Address> {
        self.breakpoints.keys().copied().collect()
    }

    // ── Snapshots ─────────────────────────────────────────────────────────────

    /// Take a named snapshot of the current replay state.
    pub fn take_snapshot(&mut self, name: impl Into<String>) {
        let name = name.into();
        let snapshot = ReplayStateSnapshot {
            name: name.clone(),
            idx: self.current_idx,
            pc: self.current_entry().map_or(0, |e| e.pc),
            regs: self.reg_view.clone(),
            call_stack: self.call_stack.clone(),
            memory_view: self.memory_view.clone(),
            replay_tick: self.replay_tick,
        };
        self.snapshots.insert(name, snapshot);
    }

    /// Restore a named snapshot.
    ///
    /// # Errors
    /// Returns `ReplayError::SnapshotNotFound` if the name is unknown.
    pub fn restore_snapshot(&mut self, name: &str) -> Result<(), ReplayError> {
        let snap = self
            .snapshots
            .get(name)
            .ok_or_else(|| ReplayError::SnapshotNotFound(name.to_owned()))?
            .clone();
        self.current_idx = snap.idx;
        self.reg_view.clone_from(&snap.regs);
        self.call_stack.clone_from(&snap.call_stack);
        self.memory_view.clone_from(&snap.memory_view);
        self.replay_tick = snap.replay_tick;
        Ok(())
    }

    /// Delete a named snapshot.
    pub fn delete_snapshot(&mut self, name: &str) -> bool {
        self.snapshots.remove(name).is_some()
    }

    /// All snapshot names.
    #[must_use]
    pub fn snapshot_names(&self) -> Vec<&str> {
        self.snapshots.keys().map(std::string::String::as_str).collect()
    }

    // ── State Queries ─────────────────────────────────────────────────────────

    /// Current register view.
    #[must_use]
    pub const fn registers(&self) -> &HashMap<RegId, u64> {
        &self.reg_view
    }

    /// Value of a specific register at the current position.
    #[must_use]
    pub fn register(&self, reg: RegId) -> Option<u64> {
        self.reg_view.get(&reg).copied()
    }

    /// Current memory view: latest written bytes at each address.
    #[must_use]
    pub const fn memory(&self) -> &HashMap<Address, Vec<u8>> {
        &self.memory_view
    }

    /// Bytes written to `addr` (most recent value), if any.
    #[must_use]
    pub fn memory_at(&self, addr: Address) -> Option<&Vec<u8>> {
        self.memory_view.get(&addr)
    }

    /// Current call stack.
    #[must_use]
    pub fn call_stack(&self) -> &[StackFrame] {
        &self.call_stack
    }

    /// Current call depth.
    #[must_use]
    pub const fn call_depth(&self) -> usize {
        self.call_stack.len()
    }

    /// Total number of entries in the trace.
    #[must_use]
    pub const fn trace_len(&self) -> usize {
        self.trace.len()
    }

    /// Progress [0.0, 1.0].
    #[must_use]
    pub fn progress(&self) -> f64 {
        if self.trace.len() <= 1 {
            return 1.0;
        }
        f64::from(u32::try_from(self.current_idx).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.trace.len() - 1).unwrap_or(u32::MAX))
    }

    /// Whether the cursor is at the end of the trace.
    #[must_use]
    pub const fn at_end(&self) -> bool {
        self.trace.is_empty() || self.current_idx + 1 >= self.trace.len()
    }

    /// Whether the cursor is at the beginning of the trace.
    #[must_use]
    pub const fn at_beginning(&self) -> bool {
        self.current_idx == 0
    }

    // ── Trace inspection ──────────────────────────────────────────────────────

    /// Peek forward `n` entries from the current position.
    #[must_use]
    pub fn peek_forward(&self, n: usize) -> Vec<&TraceEntry> {
        let start = (self.current_idx + 1).min(self.trace.len());
        let end = (start + n).min(self.trace.len());
        self.trace.entries[start..end].iter().collect()
    }

    /// Peek backward `n` entries from the current position.
    #[must_use]
    pub fn peek_backward(&self, n: usize) -> Vec<&TraceEntry> {
        let end = self.current_idx;
        let start = end.saturating_sub(n);
        self.trace.entries[start..end].iter().rev().collect()
    }

    /// Return all PCs that will be visited going forward from the current index.
    #[must_use]
    pub fn future_pcs(&self) -> HashSet<Address> {
        self.trace.entries[self.current_idx..]
            .iter()
            .map(|e| e.pc)
            .collect()
    }

    /// Binary name from the underlying trace.
    #[must_use]
    pub fn binary_name(&self) -> &str {
        &self.trace.binary_name
    }

    /// Architecture string from the underlying trace.
    #[must_use]
    pub fn arch(&self) -> &str {
        &self.trace.arch
    }
}
