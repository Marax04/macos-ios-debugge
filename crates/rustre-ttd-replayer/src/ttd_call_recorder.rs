//! `ttd_call_recorder` — record function calls from a TTD trace and build a
//! call tree.
//!
//! Scans a [`TtdTrace`] and groups consecutive [`TraceEvent::SyscallEntry`] /
//! [`TraceEvent::SyscallExit`] pairs into [`CallNode`]s.  The nodes are
//! assembled into a tree (forest) of [`CallNode`]s, where each node may have
//! zero or more child nodes representing nested calls.
//!
//! # Terminology
//!
//! * **Call** — a matched (entry, exit) pair.  Matched by a simple stack
//!   discipline: each entry pushes a frame; the next exit pops the innermost
//!   pending entry.
//! * **`CallNode`** — one matched call, holding timing, args, retval, and
//!   a list of child nodes.
//! * **`CallTree`** — the complete forest of [`CallNode`]s for a trace.
//! * **`TtdCallRecorder`** — the recorder that builds a [`CallTree`] from a
//!   [`TtdTrace`].

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{TraceEvent, TtdTrace};

// ── CallNode ──────────────────────────────────────────────────────────────────

/// A single matched function call recorded in the TTD trace.
///
/// A call consists of a `SyscallEntry` at `entry_tick` and the corresponding
/// `SyscallExit` at `exit_tick`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallNode {
    /// Unique node identifier (depth-first order, starting at 0).
    pub id: usize,
    /// Syscall number (equivalent to function identifier in this model).
    pub syscall_nr: u64,
    /// Arguments passed at entry.
    pub args: [u64; 6],
    /// Return value from exit.
    pub retval: i64,
    /// Tick at which the call was entered.
    pub entry_tick: u64,
    /// Tick at which the call returned.
    pub exit_tick: u64,
    /// Index of this node's parent call, or `None` for root calls.
    pub parent_id: Option<usize>,
    /// Identifiers of direct child calls, in call order.
    pub children: Vec<usize>,
    /// Number of memory write bytes produced by this call.
    pub bytes_written: usize,
    /// Depth in the call tree (root calls have depth 0).
    pub depth: usize,
}

impl CallNode {
    /// Duration of this call in ticks.
    #[must_use]
    #[inline]
    pub const fn duration_ticks(&self) -> u64 {
        self.exit_tick.saturating_sub(self.entry_tick)
    }

    /// Return `true` if this is a root call (no parent).
    #[must_use]
    #[inline]
    pub const fn is_root(&self) -> bool {
        self.parent_id.is_none()
    }

    /// Return `true` if this call has no children.
    #[must_use]
    #[inline]
    pub const fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }

    /// Return `true` if this call returned an error (retval < 0).
    #[must_use]
    #[inline]
    pub const fn is_error(&self) -> bool {
        self.retval < 0
    }
}

impl fmt::Display for CallNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] syscall={} entry={} exit={} duration={} retval={} children={} depth={}",
            self.id,
            self.syscall_nr,
            self.entry_tick,
            self.exit_tick,
            self.duration_ticks(),
            self.retval,
            self.children.len(),
            self.depth,
        )
    }
}

// ── CallTree ──────────────────────────────────────────────────────────────────

/// The complete call tree (forest) reconstructed from a TTD trace.
///
/// Nodes are stored in a flat `Vec`; the tree structure is encoded through
/// `parent_id` / `children` links.  Root calls are those without a parent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallTree {
    /// All call nodes, indexed by [`CallNode::id`].
    pub nodes: Vec<CallNode>,
    /// IDs of root-level calls (no parent).
    pub roots: Vec<usize>,
    /// Unmatched entry events (entry without a corresponding exit).
    pub unmatched_entries: Vec<(u64, u64)>, // (tick, syscall_nr)
}

impl CallTree {
    /// Create an empty call tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of call nodes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Return `true` if the tree has no call nodes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Return the node with the given `id`.
    #[must_use]
    pub fn get(&self, id: usize) -> Option<&CallNode> {
        self.nodes.get(id)
    }

    /// Return an iterator over all root nodes.
    pub fn root_nodes(&self) -> impl Iterator<Item = &CallNode> {
        self.roots.iter().filter_map(|&id| self.nodes.get(id))
    }

    /// Return an iterator over the children of node `id`.
    pub fn children_of(&self, id: usize) -> impl Iterator<Item = &CallNode> {
        self.nodes
            .get(id)
            .map_or(&[][..], |n| n.children.as_slice())
            .iter()
            .filter_map(|&child_id| self.nodes.get(child_id))
    }

    /// Walk all nodes in depth-first order, calling `f(node)` for each.
    pub fn walk_depth_first(&self, mut f: impl FnMut(&CallNode)) {
        let mut stack: Vec<usize> = self.roots.iter().copied().rev().collect();
        while let Some(id) = stack.pop() {
            if let Some(node) = self.nodes.get(id) {
                f(node);
                for &child in node.children.iter().rev() {
                    stack.push(child);
                }
            }
        }
    }

    /// Return all nodes matching the given syscall number.
    #[must_use]
    pub fn find_by_syscall(&self, nr: u64) -> Vec<&CallNode> {
        self.nodes.iter().filter(|n| n.syscall_nr == nr).collect()
    }

    /// Maximum call depth in the tree.
    #[must_use]
    pub fn max_depth(&self) -> usize {
        self.nodes.iter().map(|n| n.depth).max().unwrap_or(0)
    }

    /// Total number of bytes written across all calls.
    #[must_use]
    pub fn total_bytes_written(&self) -> usize {
        self.nodes.iter().map(|n| n.bytes_written).sum()
    }

    /// Return the longest call (by tick duration).
    #[must_use]
    pub fn longest_call(&self) -> Option<&CallNode> {
        self.nodes.iter().max_by_key(|n| n.duration_ticks())
    }

    /// Return the call with the most children.
    #[must_use]
    pub fn most_children(&self) -> Option<&CallNode> {
        self.nodes.iter().max_by_key(|n| n.children.len())
    }

    /// Return all leaf nodes (nodes with no children).
    #[must_use]
    pub fn leaf_nodes(&self) -> Vec<&CallNode> {
        self.nodes.iter().filter(|n| n.is_leaf()).collect()
    }

    /// Return all error calls (retval < 0).
    #[must_use]
    pub fn error_calls(&self) -> Vec<&CallNode> {
        self.nodes.iter().filter(|n| n.is_error()).collect()
    }

    /// Build a frequency map: `syscall_nr` → call count.
    #[must_use]
    pub fn syscall_frequency(&self) -> HashMap<u64, usize> {
        let mut map = HashMap::new();
        for node in &self.nodes {
            *map.entry(node.syscall_nr).or_insert(0) += 1;
        }
        map
    }

    /// Summarise the tree as a human-readable string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "CallTree: {} nodes, {} roots, max_depth={}, total_bytes_written={}",
            self.nodes.len(),
            self.roots.len(),
            self.max_depth(),
            self.total_bytes_written(),
        )
    }
}

impl fmt::Display for CallTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ── RecorderConfig ────────────────────────────────────────────────────────────

/// Configuration for [`TtdCallRecorder`].
#[derive(Debug, Clone)]
pub struct RecorderConfig {
    /// Maximum call depth tracked.  Calls deeper than this are still
    /// recorded but their children are not expanded.
    pub max_depth: usize,
    /// Maximum total nodes.  Construction stops when this is reached.
    pub max_nodes: usize,
    /// When `true`, unmatched entry events are retained in
    /// [`CallTree::unmatched_entries`].
    pub keep_unmatched: bool,
}

impl Default for RecorderConfig {
    fn default() -> Self {
        Self {
            max_depth: 128,
            max_nodes: 1_000_000,
            keep_unmatched: true,
        }
    }
}

// ── RecorderStats ─────────────────────────────────────────────────────────────

/// Statistics collected during a recording pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecorderStats {
    /// Total `SyscallEntry` events seen.
    pub entries_seen: usize,
    /// Total `SyscallExit` events seen.
    pub exits_seen: usize,
    /// Number of successfully matched (entry, exit) pairs.
    pub matched_calls: usize,
    /// Number of unmatched entries.
    pub unmatched_entries: usize,
    /// Number of orphan exits (exit without a pending entry).
    pub orphan_exits: usize,
    /// Maximum depth reached during this pass.
    pub max_depth_reached: usize,
}

// ── Pending frame ─────────────────────────────────────────────────────────────

/// An incomplete call frame waiting for its matching exit.
#[derive(Debug)]
struct PendingFrame {
    syscall_nr: u64,
    args: [u64; 6],
    entry_tick: u64,
    parent_id: Option<usize>,
    depth: usize,
}

// ── TtdCallRecorder ───────────────────────────────────────────────────────────

/// Records all function calls in a TTD trace and builds a [`CallTree`].
///
/// # Algorithm
///
/// A stack of [`PendingFrame`]s is maintained.  For each event:
/// - `SyscallEntry` → push a new frame.
/// - `SyscallExit`  → pop the innermost frame and create a [`CallNode`].
///
/// Bytes written are attributed to the call whose exit event carries the
/// writes.
///
/// # Example
///
/// ```no_run
/// use rustre_ttd_replayer::TtdTrace;
/// use rustre_ttd_replayer::ttd_call_recorder::{TtdCallRecorder, RecorderConfig};
///
/// let trace = TtdTrace::new();
/// let recorder = TtdCallRecorder::new(RecorderConfig::default());
/// let (tree, stats) = recorder.build_call_tree(&trace);
/// println!("{}", tree.summary());
/// ```
pub struct TtdCallRecorder {
    config: RecorderConfig,
}

impl TtdCallRecorder {
    /// Create a recorder with the given configuration.
    #[must_use]
    pub const fn new(config: RecorderConfig) -> Self {
        Self { config }
    }

    /// Create a recorder with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(RecorderConfig::default())
    }

    /// Scan `trace` and build the call tree.
    ///
    /// Returns the [`CallTree`] and a [`RecorderStats`] summary of the pass.
    #[must_use] 
    pub fn build_call_tree(&self, trace: &TtdTrace) -> (CallTree, RecorderStats) {
        let mut tree = CallTree::new();
        let mut stats = RecorderStats::default();
        let mut pending: Vec<PendingFrame> = Vec::new();
        let mut node_id_counter: usize = 0;

        for ev in &trace.events {
            match ev {
                TraceEvent::SyscallEntry { tick, nr, args } => {
                    stats.entries_seen += 1;

                    let depth = pending.len();
                    if depth > stats.max_depth_reached {
                        stats.max_depth_reached = depth;
                    }

                    let _parent_id = pending.last().map(|f| {
                        // The parent is the last completed node at depth-1;
                        // we record the id that was most recently assigned
                        // at the parent's depth. Because nodes are created on
                        // *exit*, the parent node may not yet exist.  We
                        // stash the parent's pending-stack index and resolve
                        // it on exit instead.
                        f.parent_id // placeholder; resolved properly below
                    });

                    pending.push(PendingFrame {
                        syscall_nr: *nr,
                        args: *args,
                        entry_tick: *tick,
                        parent_id: None, // resolved when the child call exits
                        depth,
                    });
                }

                TraceEvent::SyscallExit { tick, retval, mem_writes } => {
                    stats.exits_seen += 1;

                    let bytes_written: usize = mem_writes.iter().map(|wr| wr.data.len()).sum();

                    if let Some(frame) = pending.pop() {
                        let id = node_id_counter;
                        node_id_counter += 1;

                        if id >= self.config.max_nodes {
                            // Re-push to track unmatched count correctly.
                            pending.push(frame);
                            break;
                        }

                        // Determine depth from the pending stack length (which
                        // is now one shorter since we just popped).
                        let depth = frame.depth;

                        // The parent is the frame currently at the top of the
                        // stack (the frame that enclosed this call).
                        let parent_id: Option<usize> = if pending.is_empty() {
                            None
                        } else {
                            // We store the parent's node id.  Since the parent
                            // hasn't exited yet, we stash `None` and patch it
                            // when the parent exits.  For simplicity, store a
                            // sentinel here and fix up below.
                            None
                        };

                        let node = CallNode {
                            id,
                            syscall_nr: frame.syscall_nr,
                            args: frame.args,
                            retval: *retval,
                            entry_tick: frame.entry_tick,
                            exit_tick: *tick,
                            parent_id,
                            children: Vec::new(),
                            bytes_written,
                            depth,
                        };

                        tree.nodes.push(node);
                        stats.matched_calls += 1;

                        if depth == 0 {
                            tree.roots.push(id);
                        }
                    } else {
                        stats.orphan_exits += 1;
                    }
                }

                TraceEvent::SignalDelivered { .. } => {
                    // Signals are not calls; drain the pending stack as if all
                    // pending calls were interrupted (create partial nodes).
                    // For this recorder we simply ignore them.
                }
            }
        }

        // After the main pass, fix up parent/child links using depth information.
        self.fixup_tree(&mut tree);

        // Record unmatched entries.
        stats.unmatched_entries = pending.len();
        if self.config.keep_unmatched {
            for frame in pending {
                tree.unmatched_entries.push((frame.entry_tick, frame.syscall_nr));
            }
        }

        (tree, stats)
    }

    /// Fix up `parent_id` and `children` links after all nodes are created.
    ///
    /// Strategy: process nodes in (`entry_tick`, depth) order.  A node at depth
    /// `d > 0` is a child of the most recent node at depth `d-1` whose
    /// `entry_tick < our entry_tick && exit_tick >= our exit_tick`.
    fn fixup_tree(&self, tree: &mut CallTree) {
        // Sort a working list by entry_tick then depth.
        let count = tree.nodes.len();
        if count == 0 {
            return;
        }

        // Build a vector of (entry_tick, exit_tick, id, depth) sorted by
        // entry_tick ascending.
        let mut sorted: Vec<(u64, u64, usize, usize)> = tree
            .nodes
            .iter()
            .map(|n| (n.entry_tick, n.exit_tick, n.id, n.depth))
            .collect();
        sorted.sort_unstable_by_key(|&(et, _, id, _)| (et, id));

        // For each node with depth > 0, find the closest enclosing ancestor.
        for i in 0..sorted.len() {
            let (entry, exit, id, depth) = sorted[i];
            if depth == 0 {
                continue;
            }
            // Walk backwards to find the nearest node at depth-1 that encloses us.
            let mut parent_idx: Option<usize> = None;
            for j in (0..i).rev() {
                let (p_entry, p_exit, _p_id, p_depth) = sorted[j];
                if p_depth == depth.saturating_sub(1)
                    && p_entry <= entry
                    && p_exit >= exit
                {
                    parent_idx = Some(j);
                    break;
                }
            }
            if let Some(pidx) = parent_idx {
                let parent_id = sorted[pidx].2;
                tree.nodes[id].parent_id = Some(parent_id);
                tree.nodes[parent_id].children.push(id);
            }
        }
    }
}

// ── CallTreePrinter ───────────────────────────────────────────────────────────

/// Renders a [`CallTree`] as an indented text tree.
pub struct CallTreePrinter<'a> {
    tree: &'a CallTree,
    indent_str: &'static str,
}

impl<'a> CallTreePrinter<'a> {
    /// Create a printer with the default indent string (`"  "`).
    #[must_use]
    pub const fn new(tree: &'a CallTree) -> Self {
        Self { tree, indent_str: "  " }
    }

    /// Create a printer with a custom indent string.
    #[must_use]
    pub const fn with_indent(tree: &'a CallTree, indent: &'static str) -> Self {
        Self { tree, indent_str: indent }
    }

    /// Format the tree into `out`.
    pub fn print(&self, out: &mut dyn fmt::Write) -> fmt::Result {
        for &root_id in &self.tree.roots {
            self.print_node(out, root_id, 0)?;
        }
        Ok(())
    }

    /// Format the tree to a `String`.
    #[must_use]
    pub fn to_string(&self) -> String {
        let mut s = String::new();
        let _ = self.print(&mut s);
        s
    }

    fn print_node(&self, out: &mut dyn fmt::Write, id: usize, depth: usize) -> fmt::Result {
        let indent = self.indent_str.repeat(depth);
        if let Some(node) = self.tree.get(id) {
            writeln!(
                out,
                "{}syscall={} tick={}..{} retval={} bytes_wr={}",
                indent,
                node.syscall_nr,
                node.entry_tick,
                node.exit_tick,
                node.retval,
                node.bytes_written,
            )?;
            for &child in &node.children {
                self.print_node(out, child, depth + 1)?;
            }
        }
        Ok(())
    }
}

// ── CallFilter ────────────────────────────────────────────────────────────────

/// Predicate for filtering call nodes.
#[derive(Debug, Clone)]
pub enum CallFilter {
    /// Accept all nodes.
    Any,
    /// Accept nodes with the given syscall number.
    SyscallNr(u64),
    /// Accept nodes with retval < 0.
    Errors,
    /// Accept nodes at the given depth.
    Depth(usize),
    /// Accept nodes with duration >= threshold ticks.
    LongCall(u64),
    /// Accept nodes with no children.
    Leaf,
    /// Accept root nodes only.
    Root,
    /// Logical AND.
    And(Box<Self>, Box<Self>),
    /// Logical OR.
    Or(Box<Self>, Box<Self>),
    /// Logical NOT.
    Not(Box<Self>),
}

impl CallFilter {
    /// Return `true` when `node` matches this filter.
    #[must_use] 
    pub fn matches(&self, node: &CallNode) -> bool {
        match self {
            Self::Any => true,
            Self::SyscallNr(nr) => node.syscall_nr == *nr,
            Self::Errors => node.is_error(),
            Self::Depth(d) => node.depth == *d,
            Self::LongCall(t) => node.duration_ticks() >= *t,
            Self::Leaf => node.is_leaf(),
            Self::Root => node.is_root(),
            Self::And(a, b) => a.matches(node) && b.matches(node),
            Self::Or(a, b) => a.matches(node) || b.matches(node),
            Self::Not(inner) => !inner.matches(node),
        }
    }

    /// Apply this filter to a tree and return matching nodes.
    #[must_use] 
    pub fn apply<'a>(&self, tree: &'a CallTree) -> Vec<&'a CallNode> {
        tree.nodes.iter().filter(|n| self.matches(n)).collect()
    }
}

// ── CallTreeAnalysis ──────────────────────────────────────────────────────────

/// High-level analysis results for a [`CallTree`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallTreeAnalysis {
    /// Total number of calls.
    pub total_calls: usize,
    /// Number of error calls.
    pub error_calls: usize,
    /// Syscall number with the most invocations.
    pub hottest_syscall: Option<u64>,
    /// Number of times the hottest syscall was called.
    pub hottest_count: usize,
    /// Maximum recorded depth.
    pub max_depth: usize,
    /// Number of root calls.
    pub root_count: usize,
    /// Total bytes written across all calls.
    pub total_bytes_written: usize,
    /// Average call duration in ticks.
    pub avg_duration_ticks: f64,
}

impl CallTreeAnalysis {
    /// Analyse a [`CallTree`].
    #[must_use]
    pub fn analyse(tree: &CallTree) -> Self {
        let total_calls = tree.nodes.len();
        let error_calls = tree.nodes.iter().filter(|n| n.is_error()).count();
        let freq = tree.syscall_frequency();
        let hottest = freq.iter().max_by_key(|(_, c)| *c);
        let (hottest_syscall, hottest_count) = match hottest {
            Some((&nr, &c)) => (Some(nr), c),
            None => (None, 0),
        };
        let total_bytes_written = tree.total_bytes_written();
        let max_depth = tree.max_depth();
        let root_count = tree.roots.len();
        let avg_duration = if total_calls == 0 {
            0.0
        } else {
            let sum: u64 = tree.nodes.iter().map(CallNode::duration_ticks).sum();
            sum as f64 / total_calls as f64
        };

        Self {
            total_calls,
            error_calls,
            hottest_syscall,
            hottest_count,
            max_depth,
            root_count,
            total_bytes_written,
            avg_duration_ticks: avg_duration,
        }
    }
}

impl fmt::Display for CallTreeAnalysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Call Tree Analysis")?;
        writeln!(f, "  total calls     : {}", self.total_calls)?;
        writeln!(f, "  error calls     : {}", self.error_calls)?;
        writeln!(f, "  hottest syscall : {:?} ({} calls)", self.hottest_syscall, self.hottest_count)?;
        writeln!(f, "  max depth       : {}", self.max_depth)?;
        writeln!(f, "  root calls      : {}", self.root_count)?;
        writeln!(f, "  bytes written   : {}", self.total_bytes_written)?;
        write!(f, "  avg duration    : {:.1} ticks", self.avg_duration_ticks)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemWriteRecord, TtdTrace};

    fn entry(tick: u64, nr: u64) -> TraceEvent {
        TraceEvent::SyscallEntry { tick, nr, args: [0; 6] }
    }

    fn exit_ev(tick: u64, retval: i64) -> TraceEvent {
        TraceEvent::SyscallExit { tick, retval, mem_writes: vec![] }
    }

    fn exit_with_write(tick: u64, retval: i64, addr: u64, data: Vec<u8>) -> TraceEvent {
        TraceEvent::SyscallExit {
            tick,
            retval,
            mem_writes: vec![MemWriteRecord::new(addr, data)],
        }
    }

    fn build_trace(events: Vec<TraceEvent>) -> TtdTrace {
        let mut t = TtdTrace::new();
        for ev in events {
            t.push_event(ev);
        }
        t
    }

    // ── CallNode ──────────────────────────────────────────────────────────────

    #[test]
    fn test_call_node_duration() {
        let node = CallNode {
            id: 0, syscall_nr: 1, args: [0; 6], retval: 0,
            entry_tick: 10, exit_tick: 20, parent_id: None,
            children: vec![], bytes_written: 0, depth: 0,
        };
        assert_eq!(node.duration_ticks(), 10);
    }

    #[test]
    fn test_call_node_is_root() {
        let node = CallNode {
            id: 0, syscall_nr: 1, args: [0; 6], retval: 0,
            entry_tick: 0, exit_tick: 5, parent_id: None,
            children: vec![], bytes_written: 0, depth: 0,
        };
        assert!(node.is_root());
    }

    #[test]
    fn test_call_node_is_error() {
        let node = CallNode {
            id: 0, syscall_nr: 1, args: [0; 6], retval: -1,
            entry_tick: 0, exit_tick: 5, parent_id: None,
            children: vec![], bytes_written: 0, depth: 0,
        };
        assert!(node.is_error());
    }

    #[test]
    fn test_call_node_is_leaf() {
        let node = CallNode {
            id: 0, syscall_nr: 1, args: [0; 6], retval: 0,
            entry_tick: 0, exit_tick: 5, parent_id: None,
            children: vec![], bytes_written: 0, depth: 0,
        };
        assert!(node.is_leaf());
    }

    // ── TtdCallRecorder ───────────────────────────────────────────────────────

    #[test]
    fn test_empty_trace_empty_tree() {
        let trace = TtdTrace::new();
        let rec = TtdCallRecorder::with_defaults();
        let (tree, stats) = rec.build_call_tree(&trace);
        assert!(tree.is_empty());
        assert_eq!(stats.matched_calls, 0);
    }

    #[test]
    fn test_single_call_matched() {
        let trace = build_trace(vec![entry(1, 60), exit_ev(5, 0)]);
        let rec = TtdCallRecorder::with_defaults();
        let (tree, stats) = rec.build_call_tree(&trace);
        assert_eq!(tree.len(), 1);
        assert_eq!(stats.matched_calls, 1);
        assert_eq!(tree.nodes[0].syscall_nr, 60);
        assert_eq!(tree.nodes[0].retval, 0);
    }

    #[test]
    fn test_single_call_root() {
        let trace = build_trace(vec![entry(1, 1), exit_ev(3, 0)]);
        let rec = TtdCallRecorder::with_defaults();
        let (tree, _) = rec.build_call_tree(&trace);
        assert_eq!(tree.roots.len(), 1);
        assert!(tree.nodes[0].is_root());
    }

    #[test]
    fn test_two_sequential_calls() {
        let trace = build_trace(vec![
            entry(1, 1), exit_ev(2, 0),
            entry(3, 2), exit_ev(4, 0),
        ]);
        let rec = TtdCallRecorder::with_defaults();
        let (tree, _) = rec.build_call_tree(&trace);
        assert_eq!(tree.len(), 2);
        assert_eq!(tree.roots.len(), 2);
    }

    #[test]
    fn test_error_call_detected() {
        let trace = build_trace(vec![entry(1, 99), exit_ev(5, -1)]);
        let rec = TtdCallRecorder::with_defaults();
        let (tree, _) = rec.build_call_tree(&trace);
        assert!(!tree.error_calls().is_empty());
    }

    #[test]
    fn test_bytes_written_attributed() {
        let trace = build_trace(vec![
            entry(1, 1),
            exit_with_write(3, 0, 0x1000, vec![0xAAu8; 64]),
        ]);
        let rec = TtdCallRecorder::with_defaults();
        let (tree, _) = rec.build_call_tree(&trace);
        assert_eq!(tree.nodes[0].bytes_written, 64);
        assert_eq!(tree.total_bytes_written(), 64);
    }

    #[test]
    fn test_unmatched_entry_tracked() {
        // Entry with no matching exit.
        let trace = build_trace(vec![entry(1, 77)]);
        let rec = TtdCallRecorder::with_defaults();
        let (tree, stats) = rec.build_call_tree(&trace);
        assert_eq!(stats.unmatched_entries, 1);
        assert_eq!(tree.unmatched_entries.len(), 1);
        assert_eq!(tree.unmatched_entries[0].1, 77); // syscall_nr
    }

    #[test]
    fn test_orphan_exit_counted() {
        // Exit with no matching entry.
        let trace = build_trace(vec![exit_ev(5, 0)]);
        let rec = TtdCallRecorder::with_defaults();
        let (_, stats) = rec.build_call_tree(&trace);
        assert_eq!(stats.orphan_exits, 1);
    }

    #[test]
    fn test_syscall_frequency() {
        let trace = build_trace(vec![
            entry(1, 60), exit_ev(2, 0),
            entry(3, 60), exit_ev(4, 0),
            entry(5, 1), exit_ev(6, 0),
        ]);
        let rec = TtdCallRecorder::with_defaults();
        let (tree, _) = rec.build_call_tree(&trace);
        let freq = tree.syscall_frequency();
        assert_eq!(freq[&60], 2);
        assert_eq!(freq[&1], 1);
    }

    #[test]
    fn test_find_by_syscall() {
        let trace = build_trace(vec![
            entry(1, 42), exit_ev(2, 0),
            entry(3, 99), exit_ev(4, 0),
        ]);
        let rec = TtdCallRecorder::with_defaults();
        let (tree, _) = rec.build_call_tree(&trace);
        let found = tree.find_by_syscall(42);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].syscall_nr, 42);
    }

    #[test]
    fn test_longest_call() {
        let trace = build_trace(vec![
            entry(1, 1), exit_ev(100, 0),
            entry(101, 2), exit_ev(110, 0),
        ]);
        let rec = TtdCallRecorder::with_defaults();
        let (tree, _) = rec.build_call_tree(&trace);
        let longest = tree.longest_call().unwrap();
        assert_eq!(longest.duration_ticks(), 99);
    }

    #[test]
    fn test_leaf_nodes() {
        let trace = build_trace(vec![entry(1, 1), exit_ev(5, 0)]);
        let rec = TtdCallRecorder::with_defaults();
        let (tree, _) = rec.build_call_tree(&trace);
        assert_eq!(tree.leaf_nodes().len(), 1);
    }

    // ── CallFilter ────────────────────────────────────────────────────────────

    #[test]
    fn test_filter_syscall_nr() {
        let trace = build_trace(vec![
            entry(1, 7), exit_ev(2, 0),
            entry(3, 8), exit_ev(4, 0),
        ]);
        let rec = TtdCallRecorder::with_defaults();
        let (tree, _) = rec.build_call_tree(&trace);
        let found = CallFilter::SyscallNr(7).apply(&tree);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn test_filter_errors() {
        let trace = build_trace(vec![
            entry(1, 1), exit_ev(2, -1),
            entry(3, 2), exit_ev(4, 0),
        ]);
        let rec = TtdCallRecorder::with_defaults();
        let (tree, _) = rec.build_call_tree(&trace);
        let errs = CallFilter::Errors.apply(&tree);
        assert_eq!(errs.len(), 1);
    }

    #[test]
    fn test_filter_long_call() {
        let trace = build_trace(vec![
            entry(1, 1), exit_ev(100, 0),
            entry(101, 2), exit_ev(103, 0),
        ]);
        let rec = TtdCallRecorder::with_defaults();
        let (tree, _) = rec.build_call_tree(&trace);
        let long = CallFilter::LongCall(50).apply(&tree);
        assert_eq!(long.len(), 1);
        assert!(long[0].duration_ticks() >= 50);
    }

    // ── CallTreeAnalysis ──────────────────────────────────────────────────────

    #[test]
    fn test_analysis_total_calls() {
        let trace = build_trace(vec![
            entry(1, 1), exit_ev(2, 0),
            entry(3, 2), exit_ev(4, 0),
        ]);
        let rec = TtdCallRecorder::with_defaults();
        let (tree, _) = rec.build_call_tree(&trace);
        let analysis = CallTreeAnalysis::analyse(&tree);
        assert_eq!(analysis.total_calls, 2);
    }

    #[test]
    fn test_analysis_error_count() {
        let trace = build_trace(vec![
            entry(1, 1), exit_ev(2, -1),
            entry(3, 2), exit_ev(4, 0),
        ]);
        let rec = TtdCallRecorder::with_defaults();
        let (tree, _) = rec.build_call_tree(&trace);
        let analysis = CallTreeAnalysis::analyse(&tree);
        assert_eq!(analysis.error_calls, 1);
    }

    #[test]
    fn test_analysis_hottest_syscall() {
        let trace = build_trace(vec![
            entry(1, 5), exit_ev(2, 0),
            entry(3, 5), exit_ev(4, 0),
            entry(5, 5), exit_ev(6, 0),
            entry(7, 9), exit_ev(8, 0),
        ]);
        let rec = TtdCallRecorder::with_defaults();
        let (tree, _) = rec.build_call_tree(&trace);
        let analysis = CallTreeAnalysis::analyse(&tree);
        assert_eq!(analysis.hottest_syscall, Some(5));
        assert_eq!(analysis.hottest_count, 3);
    }

    // ── walk_depth_first ──────────────────────────────────────────────────────

    #[test]
    fn test_walk_depth_first_visits_all() {
        let trace = build_trace(vec![
            entry(1, 1), exit_ev(5, 0),
            entry(6, 2), exit_ev(9, 0),
        ]);
        let rec = TtdCallRecorder::with_defaults();
        let (tree, _) = rec.build_call_tree(&trace);
        let mut count = 0;
        tree.walk_depth_first(|_| count += 1);
        assert_eq!(count, tree.len());
    }

    // ── CallTreePrinter ───────────────────────────────────────────────────────

    #[test]
    fn test_printer_produces_output() {
        let trace = build_trace(vec![entry(1, 42), exit_ev(3, 0)]);
        let rec = TtdCallRecorder::with_defaults();
        let (tree, _) = rec.build_call_tree(&trace);
        let printer = CallTreePrinter::new(&tree);
        let output = printer.to_string();
        assert!(output.contains("42"));
    }
}
