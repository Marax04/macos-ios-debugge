//! TTD call stack query: reconstruct call stacks at arbitrary trace positions,
//! track return addresses, and analyze call depth.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::ttd_memory_query::MemoryPosition;

// ---------------------------------------------------------------------------
// ReturnAddress
// ---------------------------------------------------------------------------

/// A return address recorded on the call stack at a specific depth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReturnAddress {
    /// The address to return to after the called function completes.
    pub address: u64,
    /// The depth at which this return address sits (0 = outermost frame).
    pub depth: u32,
    /// The position at which this frame was entered.
    pub entered_at: MemoryPosition,
    /// Thread that owns this frame.
    pub thread_id: u32,
}

impl ReturnAddress {
    /// Create a new return address record.
    #[must_use]
    pub const fn new(
        address: u64,
        depth: u32,
        entered_at: MemoryPosition,
        thread_id: u32,
    ) -> Self {
        Self {
            address,
            depth,
            entered_at,
            thread_id,
        }
    }
}

impl std::fmt::Display for ReturnAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RetAddr({:#x}) depth={} entered={}",
            self.address, self.depth, self.entered_at
        )
    }
}

// ---------------------------------------------------------------------------
// StackFrame
// ---------------------------------------------------------------------------

/// A single frame in a reconstructed call stack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackFrame {
    /// The address of the function this frame belongs to.
    pub function_address: u64,
    /// The return address that will be restored when this frame returns.
    pub return_address: u64,
    /// Frame depth (0 = top / most-recent).
    pub depth: u32,
    /// Position when this frame was entered.
    pub entered_at: MemoryPosition,
    /// Thread ID.
    pub thread_id: u32,
    /// Optional symbolic name for the function.
    pub name: Option<String>,
}

impl StackFrame {
    /// Create a new stack frame.
    #[must_use]
    pub const fn new(
        function_address: u64,
        return_address: u64,
        depth: u32,
        entered_at: MemoryPosition,
        thread_id: u32,
    ) -> Self {
        Self {
            function_address,
            return_address,
            depth,
            entered_at,
            thread_id,
            name: None,
        }
    }

    /// Attach a symbolic name to this frame.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

impl std::fmt::Display for StackFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(name) = &self.name {
            write!(
                f,
                "  #{} {name} ({:#x}) ret={:#x}",
                self.depth, self.function_address, self.return_address
            )
        } else {
            write!(
                f,
                "  #{} {:#x} ret={:#x}",
                self.depth, self.function_address, self.return_address
            )
        }
    }
}

// ---------------------------------------------------------------------------
// CallStack
// ---------------------------------------------------------------------------

/// A reconstructed call stack at a specific trace position.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallStack {
    /// The trace position for this snapshot.
    pub position: MemoryPosition,
    /// The thread whose call stack is represented.
    pub thread_id: u32,
    /// Frames, ordered from innermost (index 0) to outermost.
    pub frames: Vec<StackFrame>,
}

impl CallStack {
    /// Create an empty call stack.
    #[must_use]
    pub const fn new(position: MemoryPosition, thread_id: u32) -> Self {
        Self {
            position,
            thread_id,
            frames: Vec::new(),
        }
    }

    /// Depth of the call stack (number of frames).
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.frames.len()
    }

    /// Whether the stack is empty (no recorded frames).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// The innermost (current) frame, if any.
    #[must_use]
    pub fn top_frame(&self) -> Option<&StackFrame> {
        self.frames.first()
    }

    /// The outermost frame, if any.
    #[must_use]
    pub fn bottom_frame(&self) -> Option<&StackFrame> {
        self.frames.last()
    }

    /// Return the function address of the innermost frame.
    #[must_use]
    pub fn current_function(&self) -> Option<u64> {
        self.top_frame().map(|f| f.function_address)
    }

    /// Return all function addresses in the stack (innermost first).
    #[must_use]
    pub fn function_addresses(&self) -> Vec<u64> {
        self.frames.iter().map(|f| f.function_address).collect()
    }

    /// Return all return addresses in the stack (innermost first).
    #[must_use]
    pub fn return_addresses(&self) -> Vec<u64> {
        self.frames.iter().map(|f| f.return_address).collect()
    }

    /// Whether the call stack contains `addr` as a function address.
    #[must_use]
    pub fn contains_function(&self, addr: u64) -> bool {
        self.frames.iter().any(|f| f.function_address == addr)
    }

    /// Format the call stack for display.
    #[must_use]
    pub fn format_stack(&self) -> String {
        use std::fmt::Write as _;
        let mut s = format!(
            "Call stack @ {} thread={}\n",
            self.position, self.thread_id
        );
        for frame in &self.frames {
            let _ = writeln!(s, "{frame}");
        }
        s
    }
}

impl std::fmt::Display for CallStack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CallStack @ {} tid={} depth={}",
            self.position,
            self.thread_id,
            self.depth()
        )
    }
}

// ---------------------------------------------------------------------------
// CallEvent — internal record of a call or return
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum CallEvent {
    Call {
        from: u64,
        to: u64,
        return_addr: u64,
        thread_id: u32,
    },
    Return {
        from: u64,
        to: u64,
        thread_id: u32,
    },
}

// ---------------------------------------------------------------------------
// ThreadCallState — tracks per-thread call state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ThreadCallState {
    /// Current call stack: (`function_addr`, `return_addr`, `entered_at`)
    stack: Vec<(u64, u64, MemoryPosition)>,
}

impl ThreadCallState {
    const fn new() -> Self {
        Self { stack: Vec::new() }
    }

    fn push(&mut self, function_addr: u64, return_addr: u64, pos: MemoryPosition) {
        self.stack.push((function_addr, return_addr, pos));
    }

    fn pop(&mut self, return_to: u64) -> Option<(u64, u64, MemoryPosition)> {
        // Try to find the frame whose return address matches
        if let Some(idx) = self
            .stack
            .iter()
            .rposition(|(_, ra, _)| *ra == return_to)
        {
            let frame = self.stack.remove(idx);
            // If the match is not at the top, unwind intermediate frames
            while self.stack.len() > idx {
                self.stack.pop();
            }
            Some(frame)
        } else {
            // Graceful pop of top frame
            self.stack.pop()
        }
    }

    fn build_stack(&self, pos: MemoryPosition, thread_id: u32) -> CallStack {
        let mut stack = CallStack::new(pos, thread_id);
        for (depth, (func_addr, ret_addr, entered)) in self.stack.iter().rev().enumerate() {
            stack.frames.push(StackFrame::new(
                *func_addr,
                *ret_addr,
                depth as u32,
                *entered,
                thread_id,
            ));
        }
        stack
    }
}

// ---------------------------------------------------------------------------
// TtdCallStackQuery
// ---------------------------------------------------------------------------

/// Query engine for reconstructing call stacks at arbitrary TTD positions.
///
/// Feed call and return events in chronological order via [`record_call`] and
/// [`record_return`], then query the call stack at any past position.
pub struct TtdCallStackQuery {
    /// All events sorted by position
    events: BTreeMap<MemoryPosition, Vec<CallEvent>>,
    /// Snapshot cache: position -> per-thread state at that position
    snapshots: BTreeMap<MemoryPosition, HashMap<u32, ThreadCallState>>,
    /// Total events recorded
    total_events: usize,
    /// Maximum observed call depth per thread
    max_depth: HashMap<u32, usize>,
    /// Live per-thread call state, maintained incrementally so that
    /// `max_depth_on` and `compute_max_depths` cannot disagree.
    ///
    /// A scalar counter was wrong here: a return unwinds every frame up to the
    /// one whose return address matches, so decrementing by one per return
    /// left the running depth permanently above the real one and inflated the
    /// reported maximum.
    running_state: HashMap<u32, ThreadCallState>,
}

impl TtdCallStackQuery {
    /// Create a new call stack query engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: BTreeMap::new(),
            snapshots: BTreeMap::new(),
            total_events: 0,
            max_depth: HashMap::new(),
            running_state: HashMap::new(),
        }
    }

    /// Record a call event.
    pub fn record_call(
        &mut self,
        position: MemoryPosition,
        from: u64,
        to: u64,
        return_addr: u64,
        thread_id: u32,
    ) {
        self.events
            .entry(position)
            .or_default()
            .push(CallEvent::Call {
                from,
                to,
                return_addr,
                thread_id,
            });
        self.total_events += 1;
        // Maintain a running per-thread depth tally so callers can ask for the
        // peak depth without invoking the O(N) `compute_max_depths`.
        let state = self
            .running_state
            .entry(thread_id)
            .or_insert_with(ThreadCallState::new);
        state.push(to, return_addr, position);
        let depth = state.stack.len();
        let max = self.max_depth.entry(thread_id).or_insert(0);
        if depth > *max {
            *max = depth;
        }
        self.snapshots.clear(); // invalidate cache
    }

    /// All call sites (i.e. `from` addresses) recorded on `thread_id`.
    ///
    /// Lets external consumers distinguish, for instance, JIT-thunk callers
    /// from cold-path callers without reimplementing event iteration.
    #[must_use]
    pub fn call_sites_for_thread(&self, thread_id: u32) -> Vec<u64> {
        let mut sites = Vec::new();
        for events in self.events.values() {
            for ev in events {
                match ev {
                    CallEvent::Call { from, thread_id: tid, .. } if *tid == thread_id => {
                        sites.push(*from);
                    }
                    CallEvent::Return { from, thread_id: tid, .. } if *tid == thread_id => {
                        // Returning instruction's address — useful for
                        // pairing with the call site to identify the function
                        // body's exit point.
                        sites.push(*from);
                    }
                    _ => {}
                }
            }
        }
        sites
    }

    /// Maximum call depth seen on `thread_id`, computed incrementally during
    /// recording (O(1) per query).
    #[must_use]
    pub fn max_depth_on(&self, thread_id: u32) -> usize {
        self.max_depth.get(&thread_id).copied().unwrap_or(0)
    }

    /// Snapshot of the per-thread maximum call depths.
    #[must_use]
    pub const fn max_depths(&self) -> &HashMap<u32, usize> {
        &self.max_depth
    }

    /// Record a return event.
    pub fn record_return(
        &mut self,
        position: MemoryPosition,
        from: u64,
        to: u64,
        thread_id: u32,
    ) {
        self.events
            .entry(position)
            .or_default()
            .push(CallEvent::Return {
                from,
                to,
                thread_id,
            });
        self.total_events += 1;
        self.running_state
            .entry(thread_id)
            .or_insert_with(ThreadCallState::new)
            .pop(to);
        self.snapshots.clear();
    }

    /// Reconstruct the call stack for `thread_id` at `pos`.
    #[must_use]
    pub fn call_stack_at(&self, pos: MemoryPosition, thread_id: u32) -> CallStack {
        let mut thread_states: HashMap<u32, ThreadCallState> = HashMap::new();

        for (event_pos, events) in self.events.range(..=pos) {
            for event in events {
                match event {
                    CallEvent::Call {
                        to,
                        return_addr,
                        thread_id: tid,
                        ..
                    } => {
                        thread_states
                            .entry(*tid)
                            .or_insert_with(ThreadCallState::new)
                            .push(*to, *return_addr, *event_pos);
                    }
                    CallEvent::Return {
                        to,
                        thread_id: tid,
                        ..
                    } => {
                        thread_states
                            .entry(*tid)
                            .or_insert_with(ThreadCallState::new)
                            .pop(*to);
                    }
                }
            }
        }

        thread_states
            .get(&thread_id).map_or_else(|| CallStack::new(pos, thread_id), |s| s.build_stack(pos, thread_id))
    }

    /// Reconstruct call stacks for all threads at `pos`.
    #[must_use]
    pub fn all_call_stacks_at(&self, pos: MemoryPosition) -> Vec<CallStack> {
        let mut thread_states: HashMap<u32, ThreadCallState> = HashMap::new();

        for (event_pos, events) in self.events.range(..=pos) {
            for event in events {
                match event {
                    CallEvent::Call {
                        to,
                        return_addr,
                        thread_id,
                        ..
                    } => {
                        thread_states
                            .entry(*thread_id)
                            .or_insert_with(ThreadCallState::new)
                            .push(*to, *return_addr, *event_pos);
                    }
                    CallEvent::Return {
                        to,
                        thread_id,
                        ..
                    } => {
                        thread_states
                            .entry(*thread_id)
                            .or_insert_with(ThreadCallState::new)
                            .pop(*to);
                    }
                }
            }
        }

        thread_states
            .iter()
            .map(|(&tid, state)| state.build_stack(pos, tid))
            .collect()
    }

    /// Find all positions where `function_addr` appears in the call stack of `thread_id`.
    #[must_use]
    pub fn positions_with_function_on_stack(
        &self,
        function_addr: u64,
        thread_id: u32,
    ) -> Vec<MemoryPosition> {
        let mut result = Vec::new();
        let mut state = ThreadCallState::new();

        for (pos, events) in &self.events {
            for event in events {
                match event {
                    CallEvent::Call {
                        to,
                        return_addr,
                        thread_id: tid,
                        ..
                    } if *tid == thread_id => {
                        state.push(*to, *return_addr, *pos);
                    }
                    CallEvent::Return {
                        to,
                        thread_id: tid,
                        ..
                    } if *tid == thread_id => {
                        state.pop(*to);
                    }
                    _ => {}
                }
            }
            if state.stack.iter().any(|(fa, _, _)| *fa == function_addr) {
                result.push(*pos);
            }
        }
        result
    }

    /// Return all positions where a call to `target_addr` was recorded.
    #[must_use]
    pub fn calls_to(&self, target_addr: u64) -> Vec<(MemoryPosition, u32)> {
        let mut result = Vec::new();
        for (pos, events) in &self.events {
            for event in events {
                if let CallEvent::Call { to, thread_id, .. } = event
                    && *to == target_addr {
                        result.push((*pos, *thread_id));
                    }
            }
        }
        result
    }

    /// Return all positions where a return to `ret_addr` was recorded.
    #[must_use]
    pub fn returns_to(&self, ret_addr: u64) -> Vec<(MemoryPosition, u32)> {
        let mut result = Vec::new();
        for (pos, events) in &self.events {
            for event in events {
                if let CallEvent::Return { to, thread_id, .. } = event
                    && *to == ret_addr {
                        result.push((*pos, *thread_id));
                    }
            }
        }
        result
    }

    /// Compute the maximum call depth observed for each thread.
    #[must_use]
    pub fn compute_max_depths(&self) -> HashMap<u32, usize> {
        let mut thread_states: HashMap<u32, ThreadCallState> = HashMap::new();
        let mut max_depths: HashMap<u32, usize> = HashMap::new();

        for (pos, events) in &self.events {
            for event in events {
                match event {
                    CallEvent::Call {
                        to,
                        return_addr,
                        thread_id,
                        ..
                    } => {
                        let state = thread_states
                            .entry(*thread_id)
                            .or_insert_with(ThreadCallState::new);
                        state.push(*to, *return_addr, *pos);
                        let depth = state.stack.len();
                        let max = max_depths.entry(*thread_id).or_insert(0);
                        if depth > *max {
                            *max = depth;
                        }
                    }
                    CallEvent::Return {
                        to,
                        thread_id,
                        ..
                    } => {
                        thread_states
                            .entry(*thread_id)
                            .or_insert_with(ThreadCallState::new)
                            .pop(*to);
                    }
                }
            }
        }
        max_depths
    }

    /// Count total call events (calls + returns) recorded.
    #[must_use]
    pub const fn total_events(&self) -> usize {
        self.total_events
    }

    /// Unique threads observed in call events.
    #[must_use]
    pub fn unique_threads(&self) -> Vec<u32> {
        let mut threads: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for events in self.events.values() {
            for ev in events {
                let tid = match ev {
                    CallEvent::Call { thread_id, .. } | CallEvent::Return { thread_id, .. } => {
                        *thread_id
                    }
                };
                threads.insert(tid);
            }
        }
        let mut result: Vec<u32> = threads.into_iter().collect();
        result.sort_unstable();
        result
    }

    /// Find recursive functions: functions that appear more than once on the same stack.
    #[must_use]
    pub fn find_recursive_functions(&self) -> Vec<u64> {
        let mut recursive: std::collections::HashSet<u64> = std::collections::HashSet::new();
        let mut thread_states: HashMap<u32, ThreadCallState> = HashMap::new();

        for (pos, events) in &self.events {
            for event in events {
                if let CallEvent::Call {
                    to,
                    return_addr,
                    thread_id,
                    ..
                } = event
                {
                    let state = thread_states
                        .entry(*thread_id)
                        .or_insert_with(ThreadCallState::new);
                    // Check if `to` is already on the stack
                    if state.stack.iter().any(|(fa, _, _)| fa == to) {
                        recursive.insert(*to);
                    }
                    state.push(*to, *return_addr, *pos);
                } else if let CallEvent::Return { to, thread_id, .. } = event {
                    thread_states
                        .entry(*thread_id)
                        .or_insert_with(ThreadCallState::new)
                        .pop(*to);
                }
            }
        }

        let mut result: Vec<u64> = recursive.into_iter().collect();
        result.sort_unstable();
        result
    }

    /// Build a call frequency map: `target_addr` -> call count.
    #[must_use]
    pub fn call_frequency(&self) -> HashMap<u64, usize> {
        let mut freq: HashMap<u64, usize> = HashMap::new();
        for events in self.events.values() {
            for ev in events {
                if let CallEvent::Call { to, .. } = ev {
                    *freq.entry(*to).or_default() += 1;
                }
            }
        }
        freq
    }
}

impl Default for TtdCallStackQuery {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for TtdCallStackQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TtdCallStackQuery")
            .field("total_events", &self.total_events)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn pos(seq: u64) -> MemoryPosition {
        MemoryPosition::new(seq, 0)
    }

    #[test]
    fn test_empty_stack() {
        let q = TtdCallStackQuery::new();
        let stack = q.call_stack_at(pos(10), 1);
        assert!(stack.is_empty());
    }

    #[test]
    fn test_single_call() {
        let mut q = TtdCallStackQuery::new();
        q.record_call(pos(1), 0x1000, 0x2000, 0x1005, 1);

        let stack = q.call_stack_at(pos(2), 1);
        assert_eq!(stack.depth(), 1);
        assert_eq!(stack.current_function(), Some(0x2000));
    }

    #[test]
    fn test_call_and_return() {
        let mut q = TtdCallStackQuery::new();
        q.record_call(pos(1), 0x1000, 0x2000, 0x1005, 1);
        q.record_return(pos(5), 0x2000, 0x1005, 1);

        let stack_during = q.call_stack_at(pos(3), 1);
        assert_eq!(stack_during.depth(), 1);

        let stack_after = q.call_stack_at(pos(6), 1);
        assert!(stack_after.is_empty());
    }

    #[test]
    fn test_nested_calls() {
        let mut q = TtdCallStackQuery::new();
        q.record_call(pos(1), 0x1000, 0x2000, 0x1005, 1);
        q.record_call(pos(2), 0x2000, 0x3000, 0x2010, 1);
        q.record_call(pos(3), 0x3000, 0x4000, 0x3008, 1);

        let stack = q.call_stack_at(pos(4), 1);
        assert_eq!(stack.depth(), 3);
        assert_eq!(stack.current_function(), Some(0x4000));
    }

    #[test]
    fn test_calls_to() {
        let mut q = TtdCallStackQuery::new();
        q.record_call(pos(1), 0x1000, 0x5000, 0x1005, 1);
        q.record_call(pos(3), 0x2000, 0x5000, 0x2005, 1);
        q.record_call(pos(5), 0x3000, 0x6000, 0x3005, 2);

        let calls = q.calls_to(0x5000);
        assert_eq!(calls.len(), 2);
    }

    #[test]
    fn test_recursive_function() {
        let mut q = TtdCallStackQuery::new();
        q.record_call(pos(1), 0x1000, 0x9000, 0x1005, 1);
        q.record_call(pos(2), 0x9000, 0x9000, 0x9010, 1); // recursive

        let rec = q.find_recursive_functions();
        assert!(rec.contains(&0x9000));
    }

    #[test]
    fn test_max_depth() {
        let mut q = TtdCallStackQuery::new();
        q.record_call(pos(1), 0x1000, 0x2000, 0x1005, 1);
        q.record_call(pos(2), 0x2000, 0x3000, 0x2005, 1);
        q.record_call(pos(3), 0x3000, 0x4000, 0x3005, 1);
        q.record_return(pos(4), 0x4000, 0x3005, 1);

        let depths = q.compute_max_depths();
        assert_eq!(*depths.get(&1).unwrap(), 3);
    }

    #[test]
    fn test_unique_threads() {
        let mut q = TtdCallStackQuery::new();
        q.record_call(pos(1), 0x1000, 0x2000, 0x1005, 1);
        q.record_call(pos(2), 0x1000, 0x2000, 0x1005, 2);
        q.record_call(pos(3), 0x1000, 0x2000, 0x1005, 3);

        let threads = q.unique_threads();
        assert_eq!(threads, vec![1, 2, 3]);
    }

    #[test]
    fn test_call_frequency() {
        let mut q = TtdCallStackQuery::new();
        q.record_call(pos(1), 0x1000, 0x5000, 0x1005, 1);
        q.record_call(pos(2), 0x1000, 0x5000, 0x1005, 1);
        q.record_call(pos(3), 0x1000, 0x6000, 0x1005, 1);

        let freq = q.call_frequency();
        assert_eq!(*freq.get(&0x5000).unwrap(), 2);
        assert_eq!(*freq.get(&0x6000).unwrap(), 1);
    }

    #[test]
    fn test_stack_frame_display() {
        let f = StackFrame::new(0xDEAD, 0xBEEF, 0, MemoryPosition::new(1, 0), 1)
            .with_name("my_func");
        let s = format!("{f}");
        assert!(s.contains("my_func"));
    }

    #[test]
    fn test_return_address() {
        let ra = ReturnAddress::new(0x1234, 2, MemoryPosition::new(5, 0), 1);
        assert_eq!(ra.address, 0x1234);
        assert_eq!(ra.depth, 2);
    }
}
