//! `rustre-ttd-replay::call_stack`
//!
//! Call-stack reconstruction from a TTD replay position.
//!
//! Key types:
//! * [`CallFrame`] — a single frame on the call stack.
//! * [`CallStack`] — an ordered list of frames (index 0 = innermost).
//! * [`SourceLocation`] — optional file/line/column annotation.
//! * [`InlineInfo`] — inlined call chain within a frame.
//! * [`CallStackReconstructor`] — builds stacks from a stream of call/return events.
//! * [`CallHistory`] — per-thread history of every call seen.

use std::collections::{HashMap, VecDeque};

pub use std::collections::BTreeMap;
use std::fmt;

use rustre_ttd::{EventKind, TraceEvent, TracePosition};
use serde::{Deserialize, Serialize};

// ─── SourceLocation ───────────────────────────────────────────────────────────

/// Source file / line / column annotation for a frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: String,
    pub line: u32,
    pub column: u32,
}

impl SourceLocation {
    pub fn new(file: impl Into<String>, line: u32, column: u32) -> Self {
        Self {
            file: file.into(),
            line,
            column,
        }
    }
}

impl fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.file, self.line, self.column)
    }
}

// ─── InlineInfo ───────────────────────────────────────────────────────────────

/// Represents inlined callee information inside a single machine frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineInfo {
    /// Name of the inlined function.
    pub function_name: String,
    /// Call site of the inline (address in the outer function).
    pub call_site: u64,
    /// Source location of the inline, if available.
    pub source_location: Option<SourceLocation>,
}

impl InlineInfo {
    pub fn new(function_name: impl Into<String>, call_site: u64) -> Self {
        Self {
            function_name: function_name.into(),
            call_site,
            source_location: None,
        }
    }

    #[must_use]
    pub fn with_source(mut self, loc: SourceLocation) -> Self {
        self.source_location = Some(loc);
        self
    }
}

impl fmt::Display for InlineInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "inline {}@{:#x}", self.function_name, self.call_site)?;
        if let Some(ref loc) = self.source_location {
            write!(f, " [{loc}]")?;
        }
        Ok(())
    }
}

// ─── CallFrame ────────────────────────────────────────────────────────────────

/// A single frame on a reconstructed call stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallFrame {
    /// Return address (where the call will return to).
    pub return_address: u64,
    /// Address of the called function entry point, if known.
    pub function_address: u64,
    /// Symbol name of the function, if resolved.
    pub symbol: Option<String>,
    /// Source location of the call site, if available.
    pub source_location: Option<SourceLocation>,
    /// Inlined calls inside this machine frame (innermost first).
    pub inlines: Vec<InlineInfo>,
    /// Trace position at which this frame was created.
    pub call_position: TracePosition,
    /// Thread ID this frame belongs to.
    pub tid: u32,
    /// Frame number (0 = innermost / current).
    pub frame_number: usize,
}

impl CallFrame {
    #[must_use]
    pub const fn new(
        tid: u32,
        return_address: u64,
        function_address: u64,
        call_position: TracePosition,
    ) -> Self {
        Self {
            return_address,
            function_address,
            symbol: None,
            source_location: None,
            inlines: Vec::new(),
            call_position,
            tid,
            frame_number: 0,
        }
    }

    #[must_use]
    pub fn with_symbol(mut self, sym: impl Into<String>) -> Self {
        self.symbol = Some(sym.into());
        self
    }

    #[must_use]
    pub fn with_source(mut self, loc: SourceLocation) -> Self {
        self.source_location = Some(loc);
        self
    }

    pub fn add_inline(&mut self, info: InlineInfo) {
        self.inlines.push(info);
    }

    /// Human-readable name: symbol if present, else hex address.
    #[must_use]
    pub fn name(&self) -> String {
        self.symbol
            .clone()
            .unwrap_or_else(|| format!("{:#x}", self.function_address))
    }

    /// Whether this frame has any inlined calls.
    #[must_use]
    pub const fn has_inlines(&self) -> bool {
        !self.inlines.is_empty()
    }
}

impl fmt::Display for CallFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "#{} {} ({:#x}) -> ret={:#x}",
            self.frame_number,
            self.name(),
            self.function_address,
            self.return_address
        )?;
        if let Some(ref loc) = self.source_location {
            write!(f, " [{loc}]")?;
        }
        for inline in &self.inlines {
            write!(f, "\n     (inlined: {inline})")?;
        }
        Ok(())
    }
}

// ─── CallStack ────────────────────────────────────────────────────────────────

/// An ordered call stack — frame[0] is the innermost (most recently called) frame.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallStack {
    pub frames: Vec<CallFrame>,
    pub thread_id: u32,
    pub position: TracePosition,
}

impl CallStack {
    #[must_use]
    pub const fn new(tid: u32, position: TracePosition) -> Self {
        Self {
            frames: Vec::new(),
            thread_id: tid,
            position,
        }
    }

    #[must_use]
    pub const fn depth(&self) -> usize {
        self.frames.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    #[must_use]
    pub fn innermost(&self) -> Option<&CallFrame> {
        self.frames.first()
    }
    #[must_use]
    pub fn outermost(&self) -> Option<&CallFrame> {
        self.frames.last()
    }

    pub fn push(&mut self, mut frame: CallFrame) {
        frame.frame_number = self.frames.len();
        self.frames.push(frame);
    }

    pub fn pop(&mut self) -> Option<CallFrame> {
        self.frames.pop()
    }

    /// Re-number all frames.
    fn renumber(&mut self) {
        for (i, f) in self.frames.iter_mut().enumerate() {
            f.frame_number = i;
        }
    }

    /// Return all symbol names from innermost to outermost.
    #[must_use]
    pub fn symbol_chain(&self) -> Vec<String> {
        self.frames.iter().map(CallFrame::name).collect()
    }

    /// Find the deepest frame whose function address falls in `[lo, hi)`.
    #[must_use]
    pub fn find_frame_in_range(&self, lo: u64, hi: u64) -> Option<&CallFrame> {
        self.frames
            .iter()
            .find(|f| f.function_address >= lo && f.function_address < hi)
    }

    /// Number of frames with a resolved symbol.
    #[must_use]
    pub fn resolved_count(&self) -> usize {
        self.frames.iter().filter(|f| f.symbol.is_some()).count()
    }
}

impl fmt::Display for CallStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "CallStack [tid={}, pos={}, depth={}]:",
            self.thread_id,
            self.position,
            self.depth()
        )?;
        for frame in &self.frames {
            writeln!(f, "  {frame}")?;
        }
        Ok(())
    }
}

// ─── CallEvent ────────────────────────────────────────────────────────────────

/// A recorded call or return event, for history tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEvent {
    pub position: TracePosition,
    pub tid: u32,
    pub kind: CallEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallEventKind {
    Call { from: u64, to: u64 },
    Return { from: u64, to: u64 },
    Tailcall { from: u64, to: u64 },
}

impl fmt::Display for CallEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            CallEventKind::Call { from, to } => {
                write!(f, "CALL  {:#x} -> {:#x} @{}", from, to, self.position)
            }
            CallEventKind::Return { from, to } => {
                write!(f, "RET   {:#x} -> {:#x} @{}", from, to, self.position)
            }
            CallEventKind::Tailcall { from, to } => {
                write!(f, "JMPCC {:#x} -> {:#x} @{}", from, to, self.position)
            }
        }
    }
}

// ─── CallHistory ──────────────────────────────────────────────────────────────

/// Per-thread call/return history — ordered by trace position.
#[derive(Debug, Clone, Default)]
pub struct CallHistory {
    /// `tid -> ordered list of call events`.
    events: HashMap<u32, Vec<CallEvent>>,
}

impl CallHistory {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, event: CallEvent) {
        self.events.entry(event.tid).or_default().push(event);
    }

    /// All events for `tid` up to and including `pos`.
    #[must_use]
    pub fn events_for_thread_up_to(&self, tid: u32, pos: TracePosition) -> &[CallEvent] {
        let Some(events) = self.events.get(&tid) else { return &[] };
        let end = events.partition_point(|e| e.position <= pos);
        &events[..end]
    }

    /// All events for `tid`.
    #[must_use]
    pub fn all_events_for_thread(&self, tid: u32) -> &[CallEvent] {
        self.events.get(&tid).map_or(&[], std::vec::Vec::as_slice)
    }

    #[must_use]
    pub fn thread_count(&self) -> usize {
        self.events.len()
    }

    /// Total events recorded.
    #[must_use]
    pub fn total_event_count(&self) -> usize {
        self.events.values().map(std::vec::Vec::len).sum()
    }

    /// Count calls to `addr` from any thread.
    #[must_use]
    pub fn call_count_to(&self, addr: u64) -> usize {
        self.events
            .values()
            .flat_map(|v| v.iter())
            .filter(|e| matches!(&e.kind, CallEventKind::Call { to, .. } if *to == addr))
            .count()
    }

    pub fn clear(&mut self) {
        self.events.clear();
    }
}

// ─── CallStackReconstructor ───────────────────────────────────────────────────

/// Reconstructs per-thread call stacks by processing a stream of trace events.
///
/// Maintains a live stack per thread.  After processing all events up to a
/// desired replay position, call [`CallStackReconstructor::stack_at`] to get
/// the reconstructed stack.
pub struct CallStackReconstructor {
    /// Live stack per thread (thread id -> frame stack, innermost at back).
    stacks: HashMap<u32, VecDeque<CallFrame>>,
    /// Symbol resolver callback (optional).
    symbol_resolver: Option<Box<dyn Fn(u64) -> Option<String> + Send + Sync>>,
    /// History of all call events seen.
    history: CallHistory,
    /// Map from `(tid, return_address) -> function_address` to recover function
    /// entry on return.
    pending_returns: HashMap<(u32, u64), u64>,
}

impl std::fmt::Debug for CallStackReconstructor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallStackReconstructor")
            .field("stacks", &self.stacks)
            .field(
                "symbol_resolver",
                &self.symbol_resolver.as_ref().map(|_| "<fn>"),
            )
            .field("history", &self.history)
            .field("pending_returns", &self.pending_returns)
            .finish_non_exhaustive()
    }
}

impl CallStackReconstructor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            stacks: HashMap::new(),
            symbol_resolver: None,
            history: CallHistory::new(),
            pending_returns: HashMap::new(),
        }
    }

    /// Install a symbol resolver.  The closure receives an address and returns
    /// an optional symbol name.
    #[must_use]
    pub fn with_symbol_resolver<F>(mut self, f: F) -> Self
    where
        F: Fn(u64) -> Option<String> + Send + Sync + 'static,
    {
        self.symbol_resolver = Some(Box::new(f));
        self
    }

    fn resolve(&self, addr: u64) -> Option<String> {
        self.symbol_resolver.as_ref().and_then(|f| f(addr))
    }

    /// Process a single trace event, updating internal stacks.
    pub fn process_event(&mut self, event: &TraceEvent) {
        match &event.kind {
            EventKind::Call { from, to } => {
                let symbol = self.resolve(*to);
                let mut frame = CallFrame::new(event.thread_id, *from, *to, event.position);
                frame.symbol = symbol;
                let stack = self.stacks.entry(event.thread_id).or_default();
                let depth = stack.len();
                frame.frame_number = depth;
                stack.push_back(frame);
                self.pending_returns.insert((event.thread_id, *from), *to);
                self.history.record(CallEvent {
                    position: event.position,
                    tid: event.thread_id,
                    kind: CallEventKind::Call {
                        from: *from,
                        to: *to,
                    },
                });
            }
            EventKind::Return { from, to } => {
                let stack = self.stacks.entry(event.thread_id).or_default();
                // Pop frames until we find one with matching return address or exhausted
                let orig_depth = stack.len();
                let mut popped = 0;
                while let Some(top_ret) = stack.back().map(|f| f.return_address) {
                    if top_ret == *to || popped == 0 {
                        stack.pop_back();
                        popped += 1;
                        if top_ret == *to {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                // Renumber remaining frames
                for (i, f) in stack.iter_mut().enumerate() {
                    f.frame_number = i;
                }
                let _ = orig_depth;
                self.history.record(CallEvent {
                    position: event.position,
                    tid: event.thread_id,
                    kind: CallEventKind::Return {
                        from: *from,
                        to: *to,
                    },
                });
            }
            EventKind::ThreadCreate { tid } => {
                self.stacks.entry(*tid).or_default();
            }
            EventKind::ThreadExit { tid, .. } => {
                self.stacks.remove(tid);
            }
            _ => {}
        }
    }

    /// Process a slice of events in order.
    pub fn process_events(&mut self, events: &[TraceEvent]) {
        for e in events {
            self.process_event(e);
        }
    }

    /// Get the current call stack for `tid`.
    #[must_use]
    pub fn stack_for_thread(&self, tid: u32) -> CallStack {
        let pos = TracePosition::start(); // caller should track position
        let frames_deque = self.stacks.get(&tid);
        let mut cs = CallStack::new(tid, pos);
        if let Some(frames) = frames_deque {
            // front = oldest (outermost), back = newest (innermost)
            for (i, f) in frames.iter().rev().enumerate() {
                let mut frame = f.clone();
                frame.frame_number = i;
                cs.frames.push(frame);
            }
        }
        cs.renumber();
        cs
    }

    /// Reconstruct the call stack for `tid` at `pos` by replaying from `events`
    /// from scratch up to `pos`.
    #[must_use]
    pub fn stack_at(events: &[TraceEvent], tid: u32, pos: TracePosition) -> CallStack {
        let mut recon = Self::new();
        for e in events {
            if e.position > pos {
                break;
            }
            recon.process_event(e);
        }
        let mut cs = recon.stack_for_thread(tid);
        cs.position = pos;
        cs
    }

    /// Reconstruct call stacks for all threads at `pos`.
    #[must_use]
    pub fn all_stacks_at(events: &[TraceEvent], pos: TracePosition) -> HashMap<u32, CallStack> {
        let mut recon = Self::new();
        let mut active_tids: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for e in events {
            // `continue`, not `break`: a multi-threaded trace is not
            // necessarily sorted by position, and breaking on the first
            // out-of-range event silently dropped every thread whose events
            // came later in the list — the caller got a map missing entire
            // threads rather than their stacks.
            if e.position > pos {
                continue;
            }
            active_tids.insert(e.thread_id);
            recon.process_event(e);
        }
        let mut result = HashMap::new();
        for tid in active_tids {
            let mut cs = recon.stack_for_thread(tid);
            cs.position = pos;
            result.insert(tid, cs);
        }
        result
    }

    #[must_use]
    pub const fn history(&self) -> &CallHistory {
        &self.history
    }
    #[must_use]
    pub fn active_thread_count(&self) -> usize {
        self.stacks.len()
    }

    /// Return all addresses that were called from `from_addr`.
    #[must_use]
    pub fn call_targets_from(&self, from_addr: u64) -> Vec<u64> {
        let mut targets = Vec::new();
        for events in self.history.events.values() {
            for e in events {
                if let CallEventKind::Call { from, to } = &e.kind
                    && *from == from_addr
                    && !targets.contains(to)
                {
                    targets.push(*to);
                }
            }
        }
        targets
    }

    /// Maximum call depth ever observed for `tid`.
    #[must_use]
    pub fn max_depth_for_thread(&self, tid: u32) -> usize {
        let events = self.history.all_events_for_thread(tid);
        let mut depth = 0usize;
        let mut current = 0usize;
        for e in events {
            match &e.kind {
                CallEventKind::Call { .. } => {
                    current += 1;
                    if current > depth {
                        depth = current;
                    }
                }
                CallEventKind::Return { .. } => {
                    current = current.saturating_sub(1);
                }
                CallEventKind::Tailcall { .. } => {}
            }
        }
        depth
    }
}

impl Default for CallStackReconstructor {
    fn default() -> Self {
        Self::new()
    }
}

// ─── CallTreeNode ─────────────────────────────────────────────────────────────

/// A node in the call tree (derived from call history).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallTreeNode {
    pub address: u64,
    pub symbol: Option<String>,
    pub call_count: u64,
    pub children: Vec<Self>,
}

impl CallTreeNode {
    #[must_use]
    pub const fn new(address: u64) -> Self {
        Self {
            address,
            symbol: None,
            call_count: 0,
            children: Vec::new(),
        }
    }

    #[must_use]
    pub fn total_calls(&self) -> u64 {
        self.call_count + self.children.iter().map(Self::total_calls).sum::<u64>()
    }

    pub fn add_child(&mut self, node: Self) {
        if let Some(existing) = self.children.iter_mut().find(|c| c.address == node.address) {
            existing.call_count += node.call_count;
        } else {
            self.children.push(node);
        }
    }
}

impl fmt::Display for CallTreeNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.symbol.as_deref().unwrap_or("?");
        write!(f, "{:#x} ({name}) x{}", self.address, self.call_count)
    }
}

/// Build a call-tree from a sorted list of call events for a single thread.
#[must_use]
pub fn build_call_tree(events: &[CallEvent]) -> Vec<CallTreeNode> {
    let mut roots: Vec<CallTreeNode> = Vec::new();
    // The PATH from the root to the currently executing frame, as child
    // indices. The previous version kept only the parent's ADDRESS and looked
    // it up among the roots, so at depth 2 the lookup failed, a phantom root
    // was invented for the parent, and the tree came out flattened: the same
    // function appeared both as a child and as a second root.
    let mut path: Vec<usize> = Vec::new();

    /// Index of `addr` among `nodes`, appending a fresh node if absent.
    fn find_or_insert(nodes: &mut Vec<CallTreeNode>, addr: u64) -> usize {
        if let Some(idx) = nodes.iter().position(|n| n.address == addr) {
            idx
        } else {
            nodes.push(CallTreeNode::new(addr));
            nodes.len() - 1
        }
    }

    /// Follow `path` down from `roots` to the child list of the current frame.
    fn children_at<'a>(
        roots: &'a mut Vec<CallTreeNode>,
        path: &[usize],
    ) -> &'a mut Vec<CallTreeNode> {
        let mut nodes = roots;
        for &idx in path {
            nodes = &mut nodes[idx].children;
        }
        nodes
    }

    for e in events {
        match &e.kind {
            CallEventKind::Call { to, .. } => {
                let siblings = children_at(&mut roots, &path);
                let idx = find_or_insert(siblings, *to);
                siblings[idx].call_count += 1;
                path.push(idx);
            }
            CallEventKind::Return { .. } => {
                path.pop();
            }
            CallEventKind::Tailcall { to, .. } => {
                // A tail call replaces the current frame: it becomes a sibling
                // of the frame it displaces, not a child of it.
                path.pop();
                let siblings = children_at(&mut roots, &path);
                let idx = find_or_insert(siblings, *to);
                siblings[idx].call_count += 1;
                path.push(idx);
            }
        }
    }
    roots
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_ttd::{EventKind, TraceEvent, TracePosition};
    

    fn pos(seq: u64) -> TracePosition {
        TracePosition::new(seq, 0)
    }

    fn make_events() -> Vec<TraceEvent> {
        vec![
            TraceEvent {
                position: pos(0),
                thread_id: 1,
                kind: EventKind::Call {
                    from: 0x1000,
                    to: 0x2000,
                },
            },
            TraceEvent {
                position: pos(1),
                thread_id: 1,
                kind: EventKind::Call {
                    from: 0x2010,
                    to: 0x3000,
                },
            },
            TraceEvent {
                position: pos(2),
                thread_id: 1,
                kind: EventKind::Return {
                    from: 0x3050,
                    to: 0x2014,
                },
            },
            TraceEvent {
                position: pos(3),
                thread_id: 1,
                kind: EventKind::Return {
                    from: 0x2050,
                    to: 0x1004,
                },
            },
        ]
    }

    // ── SourceLocation ────────────────────────────────────────────────────────

    #[test]
    fn source_location_display() {
        let loc = SourceLocation::new("foo.rs", 42, 3);
        assert_eq!(loc.to_string(), "foo.rs:42:3");
    }

    // ── InlineInfo ────────────────────────────────────────────────────────────

    #[test]
    fn inline_info_display() {
        let info = InlineInfo::new("my_inline", 0x1234);
        assert!(info.to_string().contains("my_inline"));
        assert!(info.to_string().contains("0x1234"));
    }

    // ── CallFrame ─────────────────────────────────────────────────────────────

    #[test]
    fn call_frame_name_with_symbol() {
        let f = CallFrame::new(1, 0x1004, 0x1000, pos(0)).with_symbol("main");
        assert_eq!(f.name(), "main");
    }

    #[test]
    fn call_frame_name_without_symbol() {
        let f = CallFrame::new(1, 0x1004, 0x1000, pos(0));
        assert!(f.name().contains("0x1000"));
    }

    #[test]
    fn call_frame_has_inlines() {
        let mut f = CallFrame::new(1, 0x1004, 0x1000, pos(0));
        assert!(!f.has_inlines());
        f.add_inline(InlineInfo::new("inner", 0x1010));
        assert!(f.has_inlines());
    }

    #[test]
    fn call_frame_display() {
        let f = CallFrame::new(1, 0x2000, 0x1000, pos(0)).with_symbol("foo");
        assert!(f.to_string().contains("foo"));
    }

    // ── CallStack ─────────────────────────────────────────────────────────────

    #[test]
    fn call_stack_push_pop() {
        let mut cs = CallStack::new(1, pos(0));
        cs.push(CallFrame::new(1, 0x1000, 0x2000, pos(0)));
        cs.push(CallFrame::new(1, 0x2000, 0x3000, pos(1)));
        assert_eq!(cs.depth(), 2);
        let f = cs.pop().unwrap();
        assert_eq!(f.return_address, 0x2000);
        assert_eq!(cs.depth(), 1);
    }

    #[test]
    fn call_stack_innermost_outermost() {
        let mut cs = CallStack::new(1, pos(0));
        cs.push(CallFrame::new(1, 0x1000, 0x2000, pos(0)).with_symbol("outer"));
        cs.push(CallFrame::new(1, 0x2000, 0x3000, pos(1)).with_symbol("inner"));
        assert_eq!(cs.innermost().unwrap().symbol.as_deref(), Some("outer"));
        assert_eq!(cs.outermost().unwrap().symbol.as_deref(), Some("inner"));
    }

    #[test]
    fn call_stack_symbol_chain() {
        let mut cs = CallStack::new(1, pos(0));
        cs.push(CallFrame::new(1, 0x0, 0x1000, pos(0)).with_symbol("a"));
        cs.push(CallFrame::new(1, 0x0, 0x2000, pos(1)).with_symbol("b"));
        assert_eq!(cs.symbol_chain(), vec!["a", "b"]);
    }

    #[test]
    fn call_stack_resolved_count() {
        let mut cs = CallStack::new(1, pos(0));
        cs.push(CallFrame::new(1, 0x0, 0x1000, pos(0)).with_symbol("a"));
        cs.push(CallFrame::new(1, 0x0, 0x2000, pos(1)));
        assert_eq!(cs.resolved_count(), 1);
    }

    #[test]
    fn call_stack_find_in_range() {
        let mut cs = CallStack::new(1, pos(0));
        cs.push(CallFrame::new(1, 0x0, 0x2000, pos(0)));
        let found = cs.find_frame_in_range(0x1000, 0x3000);
        assert!(found.is_some());
    }

    #[test]
    fn call_stack_display() {
        let cs = CallStack::new(1, pos(0));
        assert!(cs.to_string().contains("CallStack"));
    }

    // ── CallStackReconstructor ────────────────────────────────────────────────

    #[test]
    fn reconstructor_builds_stack_on_call() {
        let mut recon = CallStackReconstructor::new();
        let events = make_events();
        recon.process_event(&events[0]);
        let cs = recon.stack_for_thread(1);
        assert_eq!(cs.depth(), 1);
        assert_eq!(cs.innermost().unwrap().function_address, 0x2000);
    }

    #[test]
    fn reconstructor_pops_on_return() {
        let mut recon = CallStackReconstructor::new();
        let events = make_events();
        for e in &events {
            recon.process_event(e);
        }
        let cs = recon.stack_for_thread(1);
        assert_eq!(cs.depth(), 0);
    }

    #[test]
    fn reconstructor_nested_calls() {
        let mut recon = CallStackReconstructor::new();
        let events = make_events();
        // After 2 calls
        recon.process_event(&events[0]);
        recon.process_event(&events[1]);
        let cs = recon.stack_for_thread(1);
        assert_eq!(cs.depth(), 2);
    }

    #[test]
    fn reconstructor_with_resolver() {
        let mut recon = CallStackReconstructor::new().with_symbol_resolver(|addr| {
            if addr == 0x2000 {
                Some("foo".into())
            } else {
                None
            }
        });
        let events = make_events();
        recon.process_event(&events[0]);
        let cs = recon.stack_for_thread(1);
        assert_eq!(cs.innermost().unwrap().symbol.as_deref(), Some("foo"));
    }

    #[test]
    fn stack_at_static() {
        let events = make_events();
        // After event[1] (two calls), stack depth should be 2
        let cs = CallStackReconstructor::stack_at(&events, 1, pos(1));
        assert_eq!(cs.depth(), 2);
    }

    #[test]
    fn all_stacks_at() {
        let mut events = make_events();
        // Add events for thread 2
        events.push(TraceEvent {
            position: pos(0),
            thread_id: 2,
            kind: EventKind::Call {
                from: 0x5000,
                to: 0x6000,
            },
        });
        let stacks = CallStackReconstructor::all_stacks_at(&events, pos(1));
        assert!(stacks.contains_key(&1));
        assert!(stacks.contains_key(&2));
    }

    #[test]
    fn history_total_event_count() {
        let mut recon = CallStackReconstructor::new();
        let events = make_events();
        for e in &events {
            recon.process_event(e);
        }
        assert_eq!(recon.history().total_event_count(), 4);
    }

    #[test]
    fn history_call_count_to() {
        let mut recon = CallStackReconstructor::new();
        let events = make_events();
        for e in &events {
            recon.process_event(e);
        }
        assert_eq!(recon.history().call_count_to(0x2000), 1);
    }

    #[test]
    fn max_depth_for_thread() {
        let mut recon = CallStackReconstructor::new();
        let events = make_events();
        for e in &events {
            recon.process_event(e);
        }
        let depth = recon.max_depth_for_thread(1);
        assert_eq!(depth, 2);
    }

    // ── CallHistory ───────────────────────────────────────────────────────────

    #[test]
    fn call_history_events_up_to() {
        let mut hist = CallHistory::new();
        hist.record(CallEvent {
            position: pos(0),
            tid: 1,
            kind: CallEventKind::Call { from: 0, to: 1 },
        });
        hist.record(CallEvent {
            position: pos(5),
            tid: 1,
            kind: CallEventKind::Call { from: 1, to: 2 },
        });
        let up_to = hist.events_for_thread_up_to(1, pos(3));
        assert_eq!(up_to.len(), 1);
    }

    #[test]
    fn call_history_clear() {
        let mut hist = CallHistory::new();
        hist.record(CallEvent {
            position: pos(0),
            tid: 1,
            kind: CallEventKind::Call { from: 0, to: 1 },
        });
        hist.clear();
        assert_eq!(hist.total_event_count(), 0);
    }

    // ── CallTreeNode ──────────────────────────────────────────────────────────

    #[test]
    fn call_tree_node_total_calls() {
        let mut root = CallTreeNode::new(0x1000);
        root.call_count = 2;
        let mut child = CallTreeNode::new(0x2000);
        child.call_count = 3;
        root.add_child(child);
        assert_eq!(root.total_calls(), 5);
    }

    #[test]
    fn build_call_tree_basic() {
        let events = vec![
            CallEvent {
                position: pos(0),
                tid: 1,
                kind: CallEventKind::Call {
                    from: 0x100,
                    to: 0x200,
                },
            },
            CallEvent {
                position: pos(1),
                tid: 1,
                kind: CallEventKind::Call {
                    from: 0x210,
                    to: 0x300,
                },
            },
            CallEvent {
                position: pos(2),
                tid: 1,
                kind: CallEventKind::Return {
                    from: 0x350,
                    to: 0x214,
                },
            },
            CallEvent {
                position: pos(3),
                tid: 1,
                kind: CallEventKind::Return {
                    from: 0x250,
                    to: 0x104,
                },
            },
        ];
        let tree = build_call_tree(&events);
        assert!(!tree.is_empty());
    }

    // ── CallEvent display ─────────────────────────────────────────────────────

    #[test]
    fn call_event_display() {
        let e = CallEvent {
            position: pos(0),
            tid: 1,
            kind: CallEventKind::Call {
                from: 0x1000,
                to: 0x2000,
            },
        };
        assert!(e.to_string().contains("CALL"));
        let e2 = CallEvent {
            position: pos(1),
            tid: 1,
            kind: CallEventKind::Return {
                from: 0x2050,
                to: 0x1004,
            },
        };
        assert!(e2.to_string().contains("RET"));
    }
}
