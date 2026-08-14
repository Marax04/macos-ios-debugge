//! `LuaJIT` trace metadata: trace headers, links, side exits, snapshot frames, stats.

// ── Trace link kind ───────────────────────────────────────────────────────────

/// How a trace connects to its successor.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum TraceLink {
    /// Trace loops back to its own head (self-loop).
    Loop,
    /// Trace ends with an unconditional jump to another trace by number.
    Root(u32),
    /// Trace ends by returning to the interpreter (no compiled successor).
    Interp,
    /// Trace ends with a call to a function that has its own root trace.
    TailCall(u32),
    /// Trace ends with a return, linking to the caller's trace.
    Return,
    /// Trace was aborted during recording.
    Abort,
    /// Link not yet resolved.
    None,
}

impl TraceLink {
    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::Loop          => "loop",
            Self::Root(_)       => "root",
            Self::Interp        => "interp",
            Self::TailCall(_)   => "tailcall",
            Self::Return        => "return",
            Self::Abort         => "abort",
            Self::None          => "none",
        }
    }

    /// True if this link leaves the JIT entirely (back to interpreter).
    #[must_use] 
    pub const fn exits_jit(self) -> bool {
        matches!(self, Self::Interp | Self::Abort)
    }
}

impl core::fmt::Display for TraceLink {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Root(n)     => write!(f, "root#{n}"),
            Self::TailCall(n) => write!(f, "tailcall#{n}"),
            other => f.write_str(other.name()),
        }
    }
}

// ── Trace abort reason ────────────────────────────────────────────────────────

/// Why a trace was aborted.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum AbortReason {
    None,
    /// Too many bytecode instructions without a loop.
    TooLong,
    /// Recorder hit a black-listed opcode.
    Blacklisted,
    /// NYI (Not Yet Implemented) in the JIT.
    Nyi,
    /// JIT disabled by user or frame pragma.
    Disabled,
    /// Type guard mismatch during side-trace recording.
    TypeMismatch,
    /// Too many snapshots in the trace.
    TooManySnapshots,
    /// Stack overflow during trace recording.
    StackOverflow,
    /// Recursive trace attempt (inner loop already tracing).
    InnerLoop,
    /// Machine code buffer full.
    McodeFull,
    /// Trace was flushed as part of a GC cycle.
    GcFlush,
    /// Other / implementation-specific reason.
    Other(u8),
}

impl AbortReason {
    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::None           => "none",
            Self::TooLong        => "too_long",
            Self::Blacklisted    => "blacklisted",
            Self::Nyi            => "nyi",
            Self::Disabled       => "disabled",
            Self::TypeMismatch   => "type_mismatch",
            Self::TooManySnapshots => "too_many_snapshots",
            Self::StackOverflow  => "stack_overflow",
            Self::InnerLoop      => "inner_loop",
            Self::McodeFull      => "mcode_full",
            Self::GcFlush        => "gc_flush",
            Self::Other(_)       => "other",
        }
    }
}

impl core::fmt::Display for AbortReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Other(c) => write!(f, "other({c})"),
            other => f.write_str(other.name()),
        }
    }
}

// ── Trace header ─────────────────────────────────────────────────────────────

/// Metadata for a single compiled `LuaJIT` trace.
#[derive(Clone, Debug)]
pub struct TraceHeader {
    /// Unique trace identifier (1-based, `LuaJIT` internal numbering).
    pub trace_id: u32,
    /// Parent trace ID (0 = root trace).
    pub parent_id: u32,
    /// Bytecode offset (from function start) where recording began.
    pub start_pc: u32,
    /// Bytecode offset at the loop back-edge (0 for non-loops).
    pub loop_pc: u32,
    /// Function prototype index in the bytecode dump (0 = top-level).
    pub proto_idx: u32,
    /// How this trace links to its successor.
    pub link: TraceLink,
    /// Abort reason (`AbortReason::None` for successful compilations).
    pub abort_reason: AbortReason,
    /// Depth of the call chain at the trace head (0 = top-level function).
    pub call_depth: u8,
    /// Number of IR instructions in this trace.
    pub ir_count: u32,
    /// Number of machine code bytes emitted.
    pub mcode_size: u32,
    /// Number of snapshots (side-exit restore points).
    pub snap_count: u32,
    /// True if this trace is a side trace of another.
    pub is_side_trace: bool,
    /// True if the trace was blacklisted after exceeding the abort threshold.
    pub is_blacklisted: bool,
}

impl TraceHeader {
    #[must_use] 
    pub const fn new(trace_id: u32, start_pc: u32, proto_idx: u32) -> Self {
        Self {
            trace_id,
            parent_id: 0,
            start_pc,
            loop_pc: 0,
            proto_idx,
            link: TraceLink::None,
            abort_reason: AbortReason::None,
            call_depth: 0,
            ir_count: 0,
            mcode_size: 0,
            snap_count: 0,
            is_side_trace: false,
            is_blacklisted: false,
        }
    }

    /// True if this trace was compiled successfully.
    #[must_use] 
    pub fn is_compiled(&self) -> bool {
        self.abort_reason == AbortReason::None && self.mcode_size > 0
    }

    /// True if this is a root (hot-loop entry) trace.
    #[must_use] 
    pub const fn is_root(&self) -> bool {
        self.parent_id == 0 && !self.is_side_trace
    }

    /// Estimated machine-code bytes per IR instruction (code quality metric).
    #[must_use] 
    pub fn mcode_density(&self) -> f64 {
        if self.ir_count == 0 { 0.0 } else { f64::from(self.mcode_size) / f64::from(self.ir_count) }
    }
}

impl core::fmt::Display for TraceHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[T{}] proto={} pc={:#x} link={} IR={} mcode={}B snaps={}",
            self.trace_id, self.proto_idx, self.start_pc,
            self.link, self.ir_count, self.mcode_size, self.snap_count)
    }
}

// ── Side exit ─────────────────────────────────────────────────────────────────

/// A side exit / guard failure in a trace.
#[derive(Clone, Debug)]
pub struct SideExit {
    /// Exit number within the trace (0-based, matches snapshot index).
    pub exit_num: u32,
    /// Bytecode PC at which the guard is installed.
    pub guard_pc: u32,
    /// Number of times this exit has been taken at runtime.
    pub exit_count: u64,
    /// If a side trace was compiled for this exit, its ID.
    pub side_trace_id: Option<u32>,
    /// True if this exit has been blacklisted (too many aborts).
    pub is_blacklisted: bool,
    /// The guard type that triggered this exit.
    pub guard_kind: GuardKind,
}

/// What kind of guard produced this side exit.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum GuardKind {
    TypeCheck,
    IntRange,
    FloatNaN,
    TableType,
    MetamethodCheck,
    LoopInvariant,
    StackCheck,
    Other,
}

impl GuardKind {
    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::TypeCheck      => "typecheck",
            Self::IntRange       => "intrange",
            Self::FloatNaN       => "nan",
            Self::TableType      => "tabletype",
            Self::MetamethodCheck=> "metamethod",
            Self::LoopInvariant  => "loop_invariant",
            Self::StackCheck     => "stackcheck",
            Self::Other          => "other",
        }
    }
}

impl SideExit {
    #[must_use] 
    pub const fn new(exit_num: u32, guard_pc: u32, guard_kind: GuardKind) -> Self {
        Self {
            exit_num,
            guard_pc,
            exit_count: 0,
            side_trace_id: None,
            is_blacklisted: false,
            guard_kind,
        }
    }

    /// True if this exit is "hot" — taken more than the threshold.
    #[must_use] 
    pub const fn is_hot(&self, threshold: u64) -> bool { self.exit_count >= threshold }
}

impl core::fmt::Display for SideExit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "exit#{} pc={:#x} kind={} count={}",
            self.exit_num, self.guard_pc, self.guard_kind.name(), self.exit_count)?;
        if let Some(st) = self.side_trace_id { write!(f, " → T{st}")?; }
        Ok(())
    }
}

// ── Snapshot frame ────────────────────────────────────────────────────────────

/// A snapshot: the interpreter frame state at a guard failure point.
#[derive(Clone, Debug)]
pub struct SnapFrame {
    /// Snapshot index within the trace.
    pub snap_idx: u32,
    /// Bytecode PC of the instruction that may exit.
    pub pc: u32,
    /// Function prototype index.
    pub proto_idx: u32,
    /// Stack depth at this snapshot (number of live slots).
    pub stack_depth: u8,
    /// Map from Lua stack slot → IR ref that holds its live value.
    pub slot_map: Vec<(u8, crate::luajit_ir::IrRef)>,
    /// Number of upvalues closed at this snapshot.
    pub closed_upvalues: u8,
}

impl SnapFrame {
    #[must_use] 
    pub const fn new(snap_idx: u32, pc: u32, proto_idx: u32) -> Self {
        Self {
            snap_idx,
            pc,
            proto_idx,
            stack_depth: 0,
            slot_map: Vec::new(),
            closed_upvalues: 0,
        }
    }

    /// Record that stack slot `s` holds IR ref `r` at this snapshot.
    pub fn map_slot(&mut self, slot: u8, r: crate::luajit_ir::IrRef) {
        if let Some(e) = self.slot_map.iter_mut().find(|(s, _)| *s == slot) {
            e.1 = r;
        } else {
            self.slot_map.push((slot, r));
        }
    }

    /// Look up the IR ref for a stack slot.
    #[must_use] 
    pub fn slot_ref(&self, slot: u8) -> Option<crate::luajit_ir::IrRef> {
        self.slot_map.iter().find(|(s, _)| *s == slot).map(|(_, r)| *r)
    }

    /// Number of slots tracked in this snapshot.
    #[must_use] 
    pub const fn tracked_slots(&self) -> usize { self.slot_map.len() }
}

impl core::fmt::Display for SnapFrame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "snap#{} pc={:#x} proto={} depth={} slots={}",
            self.snap_idx, self.pc, self.proto_idx, self.stack_depth, self.slot_map.len())
    }
}

// ── Trace statistics ──────────────────────────────────────────────────────────

/// Aggregated statistics for a single `LuaJIT` trace.
#[derive(Clone, Debug, Default)]
pub struct TraceStats {
    /// Total times the trace was entered (hot-count hits).
    pub invocations: u32,
    /// Total times any side exit was taken.
    pub total_exits: u32,
    /// Number of GC steps triggered while in this trace.
    pub gc_steps: u32,
    /// Number of times the loop ran without exiting.
    pub loop_iters: u32,
    /// Peak number of live IR values at any point.
    pub peak_live_regs: u8,
    /// Number of spill slots used.
    pub spill_slots: u8,
    /// Total machine code bytes for this trace (including patches).
    pub total_mcode_bytes: u32,
    /// Number of times the trace was patched (code modified post-compile).
    pub patch_count: u32,
    /// Estimated total CPU cycles spent in this trace.
    pub cpu_cycles: u64,
}

impl TraceStats {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    /// Record a trace invocation.
    pub const fn record_invocation(&mut self) { self.invocations += 1; }

    /// Record a side exit.
    pub const fn record_exit(&mut self, _exit_num: u32) { self.total_exits += 1; }

    /// Record one loop iteration.
    pub const fn record_loop_iter(&mut self) { self.loop_iters += 1; }

    /// Exit rate: exits per invocation (0.0 if no invocations).
    #[must_use] 
    pub fn exit_rate(&self) -> f64 {
        if self.invocations == 0 { 0.0 }
        else { f64::from(self.total_exits) / f64::from(self.invocations) }
    }

    /// Average loop iterations per invocation.
    #[must_use] 
    pub fn avg_loop_iters(&self) -> f64 {
        if self.invocations == 0 { 0.0 }
        else { f64::from(self.loop_iters) / f64::from(self.invocations) }
    }

    /// True if this trace is performing well (exit rate < threshold).
    #[must_use] 
    pub fn is_healthy(&self, max_exit_rate: f64) -> bool {
        self.exit_rate() < max_exit_rate
    }

    /// Merge another stats object into this one (e.g., aggregate across hot paths).
    pub fn merge(&mut self, other: &Self) {
        self.invocations       += other.invocations;
        self.total_exits       += other.total_exits;
        self.gc_steps          += other.gc_steps;
        self.loop_iters        += other.loop_iters;
        self.cpu_cycles        += other.cpu_cycles;
        self.patch_count       += other.patch_count;
        self.total_mcode_bytes  = self.total_mcode_bytes.max(other.total_mcode_bytes);
        self.peak_live_regs     = self.peak_live_regs.max(other.peak_live_regs);
        self.spill_slots        = self.spill_slots.max(other.spill_slots);
    }
}

impl core::fmt::Display for TraceStats {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "inv={} exits={} ({:.1}%) loops={:.1} avg cyc={}",
            self.invocations,
            self.total_exits,
            self.exit_rate() * 100.0,
            self.avg_loop_iters(),
            if self.invocations > 0 { self.cpu_cycles / u64::from(self.invocations) } else { 0 },
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_header_compiled() {
        let mut h = TraceHeader::new(1, 0x10, 0);
        assert!(!h.is_compiled());
        h.mcode_size = 256;
        assert!(h.is_compiled());
        assert!(h.is_root());
    }

    #[test]
    fn trace_header_density() {
        let mut h = TraceHeader::new(2, 0x20, 0);
        h.ir_count = 100;
        h.mcode_size = 300;
        let d = h.mcode_density();
        assert!((d - 3.0).abs() < 1e-6);
    }

    #[test]
    fn trace_link_display() {
        assert_eq!(format!("{}", TraceLink::Loop), "loop");
        assert_eq!(format!("{}", TraceLink::Root(5)), "root#5");
        assert!(TraceLink::Interp.exits_jit());
        assert!(!TraceLink::Loop.exits_jit());
    }

    #[test]
    fn abort_reason_display() {
        assert_eq!(format!("{}", AbortReason::Nyi), "nyi");
        assert_eq!(format!("{}", AbortReason::Other(42)), "other(42)");
    }

    #[test]
    fn side_exit_hot() {
        let mut ex = SideExit::new(0, 0x100, GuardKind::TypeCheck);
        assert!(!ex.is_hot(10));
        ex.exit_count = 20;
        assert!(ex.is_hot(10));
    }

    #[test]
    fn snap_frame_slot_map() {
        use crate::luajit_ir::{IrRef, IR_BIAS};
        let mut sf = SnapFrame::new(0, 0x50, 0);
        let r = IrRef(IR_BIAS + 3);
        sf.map_slot(2, r);
        assert_eq!(sf.slot_ref(2), Some(r));
        assert_eq!(sf.slot_ref(9), None);
        assert_eq!(sf.tracked_slots(), 1);
    }

    #[test]
    fn trace_stats_merge() {
        let mut a = TraceStats::new();
        a.record_invocation(); a.record_loop_iter(); a.record_exit(0);
        let mut b = TraceStats::new();
        b.invocations = 9; b.total_exits = 4;
        a.merge(&b);
        assert_eq!(a.invocations, 10);
        assert_eq!(a.total_exits, 5);
    }

    #[test]
    fn trace_stats_exit_rate() {
        let mut s = TraceStats::new();
        s.invocations = 100; s.total_exits = 5;
        assert!((s.exit_rate() - 0.05).abs() < 1e-6);
        assert!(s.is_healthy(0.1));
        assert!(!s.is_healthy(0.01));
    }

    #[test]
    fn trace_stats_display() {
        let mut s = TraceStats::new();
        s.invocations = 1000; s.total_exits = 50; s.loop_iters = 5000;
        let text = format!("{s}");
        assert!(text.contains("inv=1000"));
        assert!(text.contains("exits=50"));
    }
}
