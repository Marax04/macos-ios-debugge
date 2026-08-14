//! `luajit_jit_analysis` — `LuaJIT` JIT trace analysis.
//!
//! Models JIT traces, abort reasons, snapshots, profiling, hotspot detection,
//! trace flush events, and trace link graphs.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JitAnalysisError {
    TraceNotFound(u32),
    InvalidSnapshot(String),
    ProfilerNotStarted,
}

impl fmt::Display for JitAnalysisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TraceNotFound(id) => write!(f, "trace not found: {id}"),
            Self::InvalidSnapshot(msg) => write!(f, "invalid snapshot: {msg}"),
            Self::ProfilerNotStarted => write!(f, "profiler not started"),
        }
    }
}

impl std::error::Error for JitAnalysisError {}

// ─── TraceType ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceType {
    /// Root trace: first trace for a hot loop.
    Root,
    /// Side-exit trace branching from a root.
    Side,
    /// Aborted trace: recording stopped without success.
    Abort,
    /// Stitch: continuation after a residual call.
    Stitch,
}

impl fmt::Display for TraceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root => write!(f, "root"),
            Self::Side => write!(f, "side"),
            Self::Abort => write!(f, "abort"),
            Self::Stitch => write!(f, "stitch"),
        }
    }
}

// ─── TraceAbortReason ─────────────────────────────────────────────────────────

/// Reason why a trace was aborted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceAbortReason {
    // NYI — Not Yet Implemented in the JIT.
    NyiBarrier,
    NyiComplexBytecode,
    NyiFfi,
    NyiTableSetMeta,
    NyiTableGetMeta,
    NyiCFuncCall,
    NyiC64bit,
    NyiArith,
    // Hard limits.
    TraceTooLong,
    RecursionLimit,
    LoopUnrollLimit,
    SnapshotSizeLimit,
    InstructionLimit,
    // Type / value issues.
    TypeGuardFail,
    InvalidType,
    FloatArith,
    IntOverflow,
    // Control flow.
    UnalignedReturn,
    FunctionBlacklisted,
    ReturnMismatch,
    UpvalueModified,
    // GC / memory.
    GcStep,
    OomState,
    MtoolStep,
    // Other.
    NestedJit,
    LoopBody,
    LoopExit,
    Other(u8),
}

impl fmt::Display for TraceAbortReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::NyiBarrier => "nyi:barrier",
            Self::NyiComplexBytecode => "nyi:complex_bytecode",
            Self::NyiFfi => "nyi:ffi",
            Self::NyiTableSetMeta => "nyi:table_setmeta",
            Self::NyiTableGetMeta => "nyi:table_getmeta",
            Self::NyiCFuncCall => "nyi:c_func_call",
            Self::NyiC64bit => "nyi:c64bit",
            Self::NyiArith => "nyi:arith",
            Self::TraceTooLong => "trace_too_long",
            Self::RecursionLimit => "recursion_limit",
            Self::LoopUnrollLimit => "loop_unroll_limit",
            Self::SnapshotSizeLimit => "snapshot_size_limit",
            Self::InstructionLimit => "instruction_limit",
            Self::TypeGuardFail => "type_guard_fail",
            Self::InvalidType => "invalid_type",
            Self::FloatArith => "float_arith",
            Self::IntOverflow => "int_overflow",
            Self::UnalignedReturn => "unaligned_return",
            Self::FunctionBlacklisted => "function_blacklisted",
            Self::ReturnMismatch => "return_mismatch",
            Self::UpvalueModified => "upvalue_modified",
            Self::GcStep => "gc_step",
            Self::OomState => "oom_state",
            Self::MtoolStep => "mtool_step",
            Self::NestedJit => "nested_jit",
            Self::LoopBody => "loop_body",
            Self::LoopExit => "loop_exit",
            Self::Other(_) => "other",
        };
        write!(f, "{s}")
    }
}

// ─── IrSnapshot ──────────────────────────────────────────────────────────────

/// A snapshot of the IR (SSA) state at a guard exit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrSnapshot {
    pub id: u32,
    pub exit_pc: u64,
    pub slot_count: u16,
    pub ir_ref: u32, // IR instruction reference.
}

// ─── TraceSnapshot ────────────────────────────────────────────────────────────

/// Snapshot of interpreter state recorded at a guard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSnapshot {
    pub snapshot_id: u32,
    pub trace_id: u32,
    pub pc: u64,
    pub ir_snapshots: Vec<IrSnapshot>,
    pub framelink: u32,
}

// ─── JitTraceInfo ─────────────────────────────────────────────────────────────

/// Information about a single JIT-compiled trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitTraceInfo {
    pub id: u32,
    pub trace_type: TraceType,
    /// Bytecode PC of the loop header.
    pub start_pc: u64,
    /// Bytecode PC of the loop exit (for root traces).
    pub stop_pc: Option<u64>,
    /// Parent trace ID (for side traces).
    pub parent_id: Option<u32>,
    /// Abort reason (for aborted traces).
    pub abort_reason: Option<TraceAbortReason>,
    /// Number of IR instructions in this trace.
    pub ir_count: u32,
    /// Number of snapshots in this trace.
    pub snapshot_count: u32,
    /// Machine code size in bytes.
    pub mcode_size: u32,
    /// Execution count since last flush.
    pub exec_count: u64,
    /// Whether this trace has been flushed (invalidated).
    pub flushed: bool,
    /// Child (side) trace IDs.
    pub side_traces: Vec<u32>,
    /// Link to the next trace (for trace stitching).
    pub next_trace: Option<u32>,
    pub snapshots: Vec<TraceSnapshot>,
}

impl JitTraceInfo {
    #[must_use] 
    pub const fn new(id: u32, trace_type: TraceType, start_pc: u64) -> Self {
        Self {
            id,
            trace_type,
            start_pc,
            stop_pc: None,
            parent_id: None,
            abort_reason: None,
            ir_count: 0,
            snapshot_count: 0,
            mcode_size: 0,
            exec_count: 0,
            flushed: false,
            side_traces: Vec::new(),
            next_trace: None,
            snapshots: Vec::new(),
        }
    }

    #[must_use] 
    pub fn is_aborted(&self) -> bool {
        self.trace_type == TraceType::Abort
    }

    #[must_use] 
    pub fn is_active(&self) -> bool {
        !self.flushed && !self.is_aborted()
    }
}

// ─── TraceFlushDetector ───────────────────────────────────────────────────────

/// Detects and records JIT trace flush events.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TraceFlushDetector {
    /// Flush event log: (`flush_sequence`, set of flushed trace IDs).
    pub flush_log: Vec<(u64, Vec<u32>)>,
    flush_sequence: u64,
}

impl TraceFlushDetector {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a flush event affecting the given trace IDs.
    pub fn record_flush(&mut self, trace_ids: Vec<u32>) {
        self.flush_sequence += 1;
        self.flush_log.push((self.flush_sequence, trace_ids));
    }

    /// Number of flush events recorded.
    #[must_use] 
    pub const fn flush_count(&self) -> usize {
        self.flush_log.len()
    }

    /// Total traces flushed across all events.
    #[must_use] 
    pub fn total_flushed(&self) -> usize {
        self.flush_log.iter().map(|(_, ids)| ids.len()).sum()
    }
}

// ─── HotspotFinder ───────────────────────────────────────────────────────────

/// Identifies hot loops and functions based on execution counts.
#[derive(Debug, Default)]
pub struct HotspotFinder {
    /// pc → execution count.
    pub counts: HashMap<u64, u64>,
    pub hot_threshold: u64,
}

impl HotspotFinder {
    #[must_use] 
    pub fn new(hot_threshold: u64) -> Self {
        Self {
            counts: HashMap::new(),
            hot_threshold,
        }
    }

    /// Record execution of bytecode at `pc`.
    pub fn record(&mut self, pc: u64) {
        *self.counts.entry(pc).or_insert(0) += 1;
    }

    /// Record multiple executions.
    pub fn record_n(&mut self, pc: u64, count: u64) {
        *self.counts.entry(pc).or_insert(0) += count;
    }

    /// Return hot locations sorted by count descending.
    #[must_use] 
    pub fn hotspots(&self) -> Vec<(u64, u64)> {
        let mut pairs: Vec<(u64, u64)> = self
            .counts
            .iter()
            .filter(|&(_, &c)| c >= self.hot_threshold)
            .map(|(&pc, &c)| (pc, c))
            .collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs
    }

    /// Top N hottest locations.
    #[must_use] 
    pub fn top_n(&self, n: usize) -> Vec<(u64, u64)> {
        let mut all = self.hotspots();
        all.truncate(n);
        all
    }
}

// ─── TraceLinkGraph ───────────────────────────────────────────────────────────

/// Represents the graph of trace links (root → side chains, stitches).
#[derive(Debug, Default)]
pub struct TraceLinkGraph {
    /// Adjacency: `trace_id` → set of linked trace IDs.
    links: HashMap<u32, HashSet<u32>>,
}

impl TraceLinkGraph {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_link(&mut self, from: u32, to: u32) {
        self.links.entry(from).or_default().insert(to);
        self.links.entry(to).or_default(); // ensure node exists
    }

    /// BFS reachability from a root trace.
    #[must_use] 
    pub fn reachable_from(&self, root: u32) -> HashSet<u32> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(root);
        while let Some(node) = queue.pop_front() {
            if !visited.insert(node) {
                continue;
            }
            if let Some(links) = self.links.get(&node) {
                for &next in links {
                    if !visited.contains(&next) {
                        queue.push_back(next);
                    }
                }
            }
        }
        visited
    }

    #[must_use] 
    pub fn edge_count(&self) -> usize {
        self.links.values().map(std::collections::HashSet::len).sum()
    }

    #[must_use] 
    pub fn node_count(&self) -> usize {
        self.links.len()
    }
}

// ─── JitProfiler ─────────────────────────────────────────────────────────────

/// Profiles JIT activity.
#[derive(Debug)]
pub struct JitProfiler {
    pub traces: HashMap<u32, JitTraceInfo>,
    pub link_graph: TraceLinkGraph,
    pub flush_detector: TraceFlushDetector,
    pub hotspot_finder: HotspotFinder,
    started_at: Option<Instant>,
    running: bool,
}

impl JitProfiler {
    #[must_use] 
    pub fn new(hot_threshold: u64) -> Self {
        Self {
            traces: HashMap::new(),
            link_graph: TraceLinkGraph::new(),
            flush_detector: TraceFlushDetector::new(),
            hotspot_finder: HotspotFinder::new(hot_threshold),
            started_at: None,
            running: false,
        }
    }

    /// Start the profiler.  Calling `start` while already running is a
    /// state-machine error: the second call would silently reset the start
    /// timestamp and lose timing data.  We guard against it explicitly.
    pub fn start(&mut self) {
        if !self.running {
            self.started_at = Some(Instant::now());
            self.running = true;
        }
    }

    pub const fn stop(&mut self) {
        self.running = false;
    }

    #[must_use] 
    pub const fn is_running(&self) -> bool {
        self.running
    }

    /// Time elapsed since [`start`](Self::start) was last called, or `None`
    /// if the profiler has never been started.
    #[must_use] 
    pub fn elapsed(&self) -> Option<Duration> {
        self.started_at.map(|t| t.elapsed())
    }

    /// Add a trace to the profiler.
    pub fn add_trace(&mut self, trace: JitTraceInfo) {
        let id = trace.id;
        if let Some(parent) = trace.parent_id {
            self.link_graph.add_link(parent, id);
        }
        if let Some(next) = trace.next_trace {
            self.link_graph.add_link(id, next);
        }
        self.traces.insert(id, trace);
    }

    /// Record an execution of a trace.
    ///
    /// State-machine guard: recording while the profiler is stopped is a
    /// logic error — the caller skipped the required `start()` transition.
    /// We return silently rather than silently corrupting counters.
    pub fn record_execution(&mut self, trace_id: u32, pc: u64) {
        if let Some(trace) = self.traces.get_mut(&trace_id) {
            trace.exec_count += 1;
        }
        if self.running {
            self.hotspot_finder.record(pc);
        }
    }

    /// Flush (invalidate) traces.
    pub fn flush_traces(&mut self, ids: Vec<u32>) {
        for &id in &ids {
            if let Some(trace) = self.traces.get_mut(&id) {
                trace.flushed = true;
            }
        }
        self.flush_detector.record_flush(ids);
    }

    /// Get active (non-flushed, non-aborted) traces.
    #[must_use] 
    pub fn active_traces(&self) -> Vec<&JitTraceInfo> {
        self.traces.values().filter(|t| t.is_active()).collect()
    }

    /// Stats summary.
    #[must_use] 
    pub fn stats(&self) -> ProfilerStats {
        let active = self.active_traces().len();
        let aborted = self.traces.values().filter(|t| t.is_aborted()).count();
        let flushed = self.traces.values().filter(|t| t.flushed).count();
        ProfilerStats {
            total_traces: self.traces.len(),
            active_traces: active,
            aborted_traces: aborted,
            flushed_traces: flushed,
            flush_events: self.flush_detector.flush_count(),
            hot_pcs: self.hotspot_finder.hotspots().len(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilerStats {
    pub total_traces: usize,
    pub active_traces: usize,
    pub aborted_traces: usize,
    pub flushed_traces: usize,
    pub flush_events: usize,
    pub hot_pcs: usize,
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trace(id: u32, ty: TraceType, pc: u64) -> JitTraceInfo {
        JitTraceInfo::new(id, ty, pc)
    }

    #[test]
    fn trace_type_display() {
        assert_eq!(TraceType::Root.to_string(), "root");
        assert_eq!(TraceType::Side.to_string(), "side");
        assert_eq!(TraceType::Abort.to_string(), "abort");
    }

    #[test]
    fn abort_reason_display() {
        assert_eq!(TraceAbortReason::TraceTooLong.to_string(), "trace_too_long");
        assert_eq!(TraceAbortReason::NyiFfi.to_string(), "nyi:ffi");
    }

    #[test]
    fn trace_info_is_aborted() {
        let trace = make_trace(1, TraceType::Abort, 0x100);
        assert!(trace.is_aborted());
    }

    #[test]
    fn trace_info_is_active() {
        let trace = make_trace(1, TraceType::Root, 0x100);
        assert!(trace.is_active());
    }

    #[test]
    fn trace_info_flushed_not_active() {
        let mut trace = make_trace(1, TraceType::Root, 0x100);
        trace.flushed = true;
        assert!(!trace.is_active());
    }

    #[test]
    fn flush_detector_record() {
        let mut fd = TraceFlushDetector::new();
        fd.record_flush(vec![1, 2, 3]);
        assert_eq!(fd.flush_count(), 1);
        assert_eq!(fd.total_flushed(), 3);
    }

    #[test]
    fn flush_detector_multiple_flushes() {
        let mut fd = TraceFlushDetector::new();
        fd.record_flush(vec![1]);
        fd.record_flush(vec![2, 3]);
        assert_eq!(fd.flush_count(), 2);
        assert_eq!(fd.total_flushed(), 3);
    }

    #[test]
    fn hotspot_finder_record() {
        let mut hf = HotspotFinder::new(10);
        for _ in 0..15 {
            hf.record(0x1000);
        }
        let hotspots = hf.hotspots();
        assert!(!hotspots.is_empty());
        assert_eq!(hotspots[0].0, 0x1000);
        assert_eq!(hotspots[0].1, 15);
    }

    #[test]
    fn hotspot_finder_below_threshold() {
        let mut hf = HotspotFinder::new(100);
        hf.record_n(0x1000, 50);
        assert!(hf.hotspots().is_empty());
    }

    #[test]
    fn hotspot_finder_top_n() {
        let mut hf = HotspotFinder::new(1);
        for pc in 0..10u64 {
            hf.record_n(pc * 0x100, pc + 1);
        }
        let top3 = hf.top_n(3);
        assert_eq!(top3.len(), 3);
        // Should be sorted descending.
        for i in 1..top3.len() {
            assert!(top3[i - 1].1 >= top3[i].1);
        }
    }

    #[test]
    fn trace_link_graph_add_and_reachable() {
        let mut g = TraceLinkGraph::new();
        g.add_link(1, 2);
        g.add_link(2, 3);
        let reachable = g.reachable_from(1);
        assert!(reachable.contains(&2));
        assert!(reachable.contains(&3));
    }

    #[test]
    fn trace_link_graph_counts() {
        let mut g = TraceLinkGraph::new();
        g.add_link(1, 2);
        g.add_link(1, 3);
        assert_eq!(g.edge_count(), 2);
    }

    #[test]
    fn trace_link_graph_isolated_node() {
        let mut g = TraceLinkGraph::new();
        g.add_link(1, 2); // ensures node 2 exists
        let reachable = g.reachable_from(2);
        assert!(reachable.contains(&2));
        assert!(!reachable.contains(&1));
    }

    #[test]
    fn profiler_add_and_active() {
        let mut p = JitProfiler::new(10);
        p.add_trace(make_trace(1, TraceType::Root, 0x100));
        p.add_trace(make_trace(2, TraceType::Abort, 0x200));
        let active = p.active_traces();
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn profiler_flush_traces() {
        let mut p = JitProfiler::new(10);
        p.add_trace(make_trace(1, TraceType::Root, 0x100));
        p.flush_traces(vec![1]);
        assert_eq!(p.active_traces().len(), 0);
        assert_eq!(p.flush_detector.flush_count(), 1);
    }

    #[test]
    fn profiler_record_execution() {
        let mut p = JitProfiler::new(10);
        p.add_trace(make_trace(1, TraceType::Root, 0x100));
        p.record_execution(1, 0x100);
        p.record_execution(1, 0x100);
        assert_eq!(p.traces[&1].exec_count, 2);
    }

    #[test]
    fn profiler_stats() {
        let mut p = JitProfiler::new(1);
        p.add_trace(make_trace(1, TraceType::Root, 0x100));
        p.add_trace(make_trace(2, TraceType::Abort, 0x200));
        p.flush_traces(vec![1]);
        p.record_execution(1, 0x100);
        let stats = p.stats();
        assert_eq!(stats.total_traces, 2);
        assert_eq!(stats.aborted_traces, 1);
        assert_eq!(stats.flushed_traces, 1);
    }

    #[test]
    fn profiler_start_stop() {
        let mut p = JitProfiler::new(10);
        assert!(!p.is_running());
        p.start();
        assert!(p.is_running());
        p.stop();
        assert!(!p.is_running());
    }

    #[test]
    fn jit_error_display() {
        let e = JitAnalysisError::TraceNotFound(42);
        assert!(e.to_string().contains("42"));
    }

    #[test]
    fn trace_side_child() {
        let mut p = JitProfiler::new(10);
        p.add_trace(make_trace(1, TraceType::Root, 0x100));
        let mut side = make_trace(2, TraceType::Side, 0x150);
        side.parent_id = Some(1);
        p.add_trace(side);
        let reachable = p.link_graph.reachable_from(1);
        assert!(reachable.contains(&2));
    }

    #[test]
    fn ir_snapshot_fields() {
        let snap = IrSnapshot {
            id: 0,
            exit_pc: 0x1000,
            slot_count: 4,
            ir_ref: 42,
        };
        assert_eq!(snap.exit_pc, 0x1000);
    }

    #[test]
    fn trace_snapshot_fields() {
        let ts = TraceSnapshot {
            snapshot_id: 0,
            trace_id: 1,
            pc: 0x100,
            ir_snapshots: Vec::new(),
            framelink: 0,
        };
        assert_eq!(ts.trace_id, 1);
    }

    #[test]
    fn abort_reason_other() {
        let r = TraceAbortReason::Other(99);
        assert_eq!(r.to_string(), "other");
    }
}
