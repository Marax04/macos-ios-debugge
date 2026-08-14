//! `replay_analysis` — Analyze execution during TTD replay.
//!
//! Provides:
//! * [`ReplayAnalysis`]         — top-level analysis driver over a replay session
//! * [`InstructionFrequency`]   — per-address execution count histogram
//! * [`CallChainAnalysis`]      — call-chain / call-tree reconstruction
//! * [`ExceptionChain`]         — ordered list of exceptions from the trace
//! * [`MemoryPatternAnalysis`]  — detect hot/cold regions and strided accesses
//! * [`ReplayInsights`]         — aggregated human-readable insight report

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use rustre_ttd::{EventKind, TraceEvent, TracePosition, TtdTrace};

// ─── errors ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum AnalysisError {
    EmptyTrace,
    InvalidPosition(String),
    NoExceptions,
    Custom(String),
}

impl fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTrace => write!(f, "trace contains no events"),
            Self::InvalidPosition(s) => write!(f, "invalid position: {s}"),
            Self::NoExceptions => write!(f, "no exceptions in trace"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for AnalysisError {}

// ─── InstructionFrequency ────────────────────────────────────────────────────

/// Per-address instruction execution count histogram.
///
/// Populated by iterating over call/return/breakpoint events in a trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InstructionFrequency {
    /// address → hit count
    pub counts: BTreeMap<u64, u64>,
    /// total events processed
    pub total_events: u64,
}

impl InstructionFrequency {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a single execution of `addr`.
    pub fn record(&mut self, addr: u64) {
        *self.counts.entry(addr).or_insert(0) += 1;
        self.total_events += 1;
    }

    /// Return the address with the highest hit count.
    #[must_use]
    pub fn hottest(&self) -> Option<(u64, u64)> {
        self.counts
            .iter()
            .max_by_key(|(_, c)| **c)
            .map(|(a, c)| (*a, *c))
    }

    /// Return addresses sorted by frequency (descending).
    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> = self.counts.iter().map(|(a, c)| (*a, *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }

    /// Unique addresses observed.
    #[must_use]
    pub fn unique_addresses(&self) -> usize {
        self.counts.len()
    }

    /// Average hit count across all observed addresses.
    #[must_use]
    pub fn average_hits(&self) -> f64 {
        if self.counts.is_empty() {
            return 0.0;
        }
        let total: u64 = self.counts.values().sum();
        total as f64 / self.counts.len() as f64
    }

    /// Addresses hit only once (potential rare paths).
    #[must_use]
    pub fn cold_addresses(&self) -> Vec<u64> {
        self.counts
            .iter()
            .filter_map(|(a, c)| if *c == 1 { Some(*a) } else { None })
            .collect()
    }

    /// Merge another frequency map into this one.
    pub fn merge(&mut self, other: &Self) {
        for (addr, cnt) in &other.counts {
            *self.counts.entry(*addr).or_insert(0) += cnt;
        }
        self.total_events += other.total_events;
    }
}

impl fmt::Display for InstructionFrequency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "InstructionFrequency {{ unique={}, total={} }}",
            self.counts.len(),
            self.total_events
        )
    }
}

// ─── CallFrame ───────────────────────────────────────────────────────────────

/// A single frame on a reconstructed call chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallFrame {
    pub caller: u64,
    pub callee: u64,
    pub return_site: u64,
    pub enter_position: TracePosition,
    pub exit_position: Option<TracePosition>,
    pub depth: usize,
}

impl CallFrame {
    #[must_use]
    pub const fn new(caller: u64, callee: u64, ret: u64, pos: TracePosition, depth: usize) -> Self {
        Self {
            caller,
            callee,
            return_site: ret,
            enter_position: pos,
            exit_position: None,
            depth,
        }
    }

    /// Duration in trace positions (exit.seq - enter.seq), if resolved.
    #[must_use]
    pub fn duration_seq(&self) -> Option<u64> {
        self.exit_position
            .map(|ep| ep.sequence.saturating_sub(self.enter_position.sequence))
    }
}

impl fmt::Display for CallFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CallFrame {{ caller={:#x}, callee={:#x}, depth={} }}",
            self.caller, self.callee, self.depth
        )
    }
}

// ─── CallChainAnalysis ───────────────────────────────────────────────────────

/// Reconstructs the call chain from trace call/return events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallChainAnalysis {
    /// All frames recorded during analysis (in entry order).
    pub frames: Vec<CallFrame>,
    /// Maximum call depth observed.
    pub max_depth: usize,
    /// Count of call events processed.
    pub total_calls: u64,
    /// Count of return events processed.
    pub total_returns: u64,
    /// Unmatched returns (depth underflow).
    pub unmatched_returns: u64,
}

impl CallChainAnalysis {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the call chain from a slice of trace events.
    #[must_use]
    pub fn build_from_events(events: &[TraceEvent]) -> Self {
        let mut analysis = Self::new();
        let mut stack: Vec<usize> = Vec::new(); // indices into frames
        let mut current_depth = 0usize;

        for event in events {
            match &event.kind {
                EventKind::Call { from, to } => {
                    let frame = CallFrame::new(*from, *to, 0, event.position, current_depth);
                    let idx = analysis.frames.len();
                    analysis.frames.push(frame);
                    stack.push(idx);
                    current_depth += 1;
                    if current_depth > analysis.max_depth {
                        analysis.max_depth = current_depth;
                    }
                    analysis.total_calls += 1;
                }
                EventKind::Return { from: _, to } => {
                    analysis.total_returns += 1;
                    if let Some(frame_idx) = stack.pop() {
                        analysis.frames[frame_idx].exit_position = Some(event.position);
                        analysis.frames[frame_idx].return_site = *to;
                        current_depth = current_depth.saturating_sub(1);
                    } else {
                        analysis.unmatched_returns += 1;
                    }
                }
                _ => {}
            }
        }
        analysis
    }

    /// Return frames at the given depth level.
    #[must_use]
    pub fn frames_at_depth(&self, depth: usize) -> Vec<&CallFrame> {
        self.frames.iter().filter(|f| f.depth == depth).collect()
    }

    /// Return frames that called the given address.
    #[must_use]
    pub fn callers_of(&self, callee: u64) -> Vec<&CallFrame> {
        self.frames.iter().filter(|f| f.callee == callee).collect()
    }

    /// Return all unique callee addresses.
    #[must_use]
    pub fn unique_callees(&self) -> HashSet<u64> {
        self.frames.iter().map(|f| f.callee).collect()
    }

    /// Find recursion (same callee at multiple depths).
    #[must_use]
    pub fn recursive_calls(&self) -> Vec<u64> {
        let mut seen: HashMap<u64, usize> = HashMap::new();
        let mut recursive = HashSet::new();
        for frame in &self.frames {
            let count = seen.entry(frame.callee).or_insert(0);
            *count += 1;
            if *count > 1 {
                recursive.insert(frame.callee);
            }
        }
        recursive.into_iter().collect()
    }

    /// Longest call chain by frame count.
    #[must_use]
    pub fn deepest_chain(&self) -> Vec<&CallFrame> {
        // `depth` is 0-based while `max_depth` is a COUNT, so comparing them
        // was off by one and matched nothing for any non-empty trace. Take the
        // deepest depth from the frames themselves: it cannot drift from
        // whatever `max_depth` happens to count.
        let Some(deepest) = self.frames.iter().map(|f| f.depth).max() else {
            return Vec::new();
        };
        self.frames
            .iter()
            .filter(|f| f.depth == deepest)
            .collect()
    }
}

impl fmt::Display for CallChainAnalysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CallChainAnalysis {{ frames={}, max_depth={}, calls={} }}",
            self.frames.len(),
            self.max_depth,
            self.total_calls
        )
    }
}

// ─── ExceptionRecord ─────────────────────────────────────────────────────────

/// A single exception event captured from the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionRecord {
    pub position: TracePosition,
    pub code: u32,
    pub address: u64,
    pub thread_id: u32,
    pub description: String,
    pub is_first_chance: bool,
}

impl ExceptionRecord {
    #[must_use]
    pub fn new(
        position: TracePosition,
        code: u32,
        address: u64,
        thread_id: u32,
        is_first_chance: bool,
    ) -> Self {
        let description = Self::describe_code(code);
        Self {
            position,
            code,
            address,
            thread_id,
            description,
            is_first_chance,
        }
    }

    fn describe_code(code: u32) -> String {
        match code {
            0xC000_0005 => "Access Violation".into(),
            0xC000_001D => "Illegal Instruction".into(),
            0xC000_0094 => "Integer Divide by Zero".into(),
            0xC000_0095 => "Integer Overflow".into(),
            0xC000_00FD => "Stack Overflow".into(),
            0xC000_008D => "FPU: Invalid operation".into(),
            0xC000_0374 => "Heap Corruption".into(),
            0xC000_0025 => "Non-continuable exception".into(),
            0x8000_0003 => "Breakpoint".into(),
            0x8000_0004 => "Single Step".into(),
            _ => format!("Exception {code:#010x}"),
        }
    }

    #[must_use]
    pub const fn is_fatal(&self) -> bool {
        !self.is_first_chance
    }
}

impl fmt::Display for ExceptionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Exception {:#010x} ({}) @ {:#x} tid={}",
            self.code, self.description, self.address, self.thread_id
        )
    }
}

// ─── ExceptionChain ──────────────────────────────────────────────────────────

/// Ordered sequence of exceptions extracted from a replay trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExceptionChain {
    pub exceptions: Vec<ExceptionRecord>,
}

impl ExceptionChain {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from a slice of trace events.
    #[must_use]
    pub fn build_from_events(events: &[TraceEvent]) -> Self {
        let mut chain = Self::new();
        for event in events {
            if let EventKind::Exception { code, addr } = &event.kind {
                chain.exceptions.push(ExceptionRecord::new(
                    event.position,
                    *code,
                    *addr,
                    event.thread_id,
                    true,
                ));
            }
        }
        chain
    }

    /// Return only fatal (second-chance) exceptions.
    #[must_use]
    pub fn fatal_exceptions(&self) -> Vec<&ExceptionRecord> {
        self.exceptions.iter().filter(|e| e.is_fatal()).collect()
    }

    /// Return exceptions matching the given code.
    #[must_use]
    pub fn by_code(&self, code: u32) -> Vec<&ExceptionRecord> {
        self.exceptions.iter().filter(|e| e.code == code).collect()
    }

    /// First access violation, if any.
    #[must_use]
    pub fn first_access_violation(&self) -> Option<&ExceptionRecord> {
        self.exceptions.iter().find(|e| e.code == 0xC000_0005)
    }

    /// Count of unique exception codes.
    #[must_use]
    pub fn unique_codes(&self) -> HashSet<u32> {
        self.exceptions.iter().map(|e| e.code).collect()
    }

    /// Exceptions on a particular thread.
    #[must_use]
    pub fn by_thread(&self, tid: u32) -> Vec<&ExceptionRecord> {
        self.exceptions
            .iter()
            .filter(|e| e.thread_id == tid)
            .collect()
    }

    /// True if the chain contains any access violation.
    #[must_use]
    pub fn has_access_violation(&self) -> bool {
        self.exceptions.iter().any(|e| e.code == 0xC000_0005)
    }
}

impl fmt::Display for ExceptionChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExceptionChain {{ count={} }}", self.exceptions.len())
    }
}

// ─── MemoryRegion ────────────────────────────────────────────────────────────

/// A memory region observed during replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
    pub read_count: u64,
    pub write_count: u64,
    pub first_access: TracePosition,
    pub last_access: TracePosition,
}

impl MemoryRegion {
    #[must_use]
    pub const fn new(base: u64, size: u64, pos: TracePosition) -> Self {
        Self {
            base,
            size,
            read_count: 0,
            write_count: 0,
            first_access: pos,
            last_access: pos,
        }
    }

    #[must_use]
    pub const fn total_accesses(&self) -> u64 {
        self.read_count + self.write_count
    }

    #[must_use]
    pub const fn is_hot(&self, threshold: u64) -> bool {
        self.total_accesses() >= threshold
    }

    #[must_use]
    pub fn write_ratio(&self) -> f64 {
        let total = self.total_accesses();
        if total == 0 {
            return 0.0;
        }
        self.write_count as f64 / total as f64
    }
}

impl fmt::Display for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MemRegion @ {:#x}+{:#x} R={} W={}",
            self.base, self.size, self.read_count, self.write_count
        )
    }
}

// ─── StridedAccess ───────────────────────────────────────────────────────────

/// Describes a strided memory access pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StridedAccess {
    pub base: u64,
    pub stride: u64,
    pub count: u64,
    pub is_write: bool,
}

impl fmt::Display for StridedAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StridedAccess {{ base={:#x}, stride={}, count={}, write={} }}",
            self.base, self.stride, self.count, self.is_write
        )
    }
}

// ─── MemoryPatternAnalysis ───────────────────────────────────────────────────

/// Analyze memory access patterns: hotspots, cold regions, stride detection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryPatternAnalysis {
    pub regions: BTreeMap<u64, MemoryRegion>,
    pub strided_accesses: Vec<StridedAccess>,
    pub total_reads: u64,
    pub total_writes: u64,
    pub unique_addresses_read: HashSet<u64>,
    pub unique_addresses_written: HashSet<u64>,
}

impl MemoryPatternAnalysis {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    const REGION_GRANULARITY: u64 = 4096;

    const fn region_base(addr: u64) -> u64 {
        addr & !(Self::REGION_GRANULARITY - 1)
    }

    /// Process all trace events to build the pattern analysis.
    #[must_use]
    pub fn build_from_events(events: &[TraceEvent]) -> Self {
        let mut analysis = Self::new();
        let mut last_read_addr: Option<u64> = None;
        let mut last_write_addr: Option<u64> = None;
        let mut read_stride_count: u64 = 0;
        let mut write_stride_count: u64 = 0;
        let mut last_read_stride: Option<u64> = None;
        let mut last_write_stride: Option<u64> = None;
        // Where the current run STARTED. The base was previously reported as
        // the last address of the run, not its first.
        let mut read_run_base: Option<u64> = None;
        let mut write_run_base: Option<u64> = None;

        for event in events {
            match &event.kind {
                EventKind::MemRead { addr, len } => {
                    analysis.total_reads += 1;
                    analysis.unique_addresses_read.insert(*addr);
                    let base = Self::region_base(*addr);
                    let region = analysis.regions.entry(base).or_insert_with(|| {
                        MemoryRegion::new(base, Self::REGION_GRANULARITY, event.position)
                    });
                    region.read_count += 1;
                    region.last_access = event.position;

                    // Stride detection
                    if let Some(prev) = last_read_addr {
                        let stride = addr.wrapping_sub(prev);
                        if let Some(last_s) = last_read_stride {
                            if stride == last_s {
                                read_stride_count += 1;
                            } else {
                                if read_stride_count >= 3 {
                                    analysis.strided_accesses.push(StridedAccess {
                                        base: read_run_base.unwrap_or(prev),
                                        stride: last_s,
                                        count: read_stride_count,
                                        is_write: false,
                                    });
                                }
                                read_stride_count = 1;
                                read_run_base = Some(prev);
                                last_read_stride = Some(stride);
                            }
                        } else {
                            last_read_stride = Some(stride);
                            read_stride_count = 1;
                            read_run_base = Some(prev);
                        }
                    }
                    last_read_addr = Some(*addr);
                    let _ = len;
                }
                EventKind::MemWrite { addr, data } => {
                    analysis.total_writes += 1;
                    analysis.unique_addresses_written.insert(*addr);
                    let base = Self::region_base(*addr);
                    let region = analysis.regions.entry(base).or_insert_with(|| {
                        MemoryRegion::new(base, Self::REGION_GRANULARITY, event.position)
                    });
                    region.write_count += 1;
                    region.last_access = event.position;

                    if let Some(prev) = last_write_addr {
                        let stride = addr.wrapping_sub(prev);
                        if let Some(last_s) = last_write_stride {
                            if stride == last_s {
                                write_stride_count += 1;
                            } else {
                                if write_stride_count >= 3 {
                                    analysis.strided_accesses.push(StridedAccess {
                                        base: write_run_base.unwrap_or(prev),
                                        stride: last_s,
                                        count: write_stride_count,
                                        is_write: true,
                                    });
                                }
                                write_stride_count = 1;
                                write_run_base = Some(prev);
                                last_write_stride = Some(stride);
                            }
                        } else {
                            last_write_stride = Some(stride);
                            write_stride_count = 1;
                            write_run_base = Some(prev);
                        }
                    }
                    last_write_addr = Some(*addr);
                    let _ = data;
                }
                _ => {}
            }
        }

        // Flush the run still in progress. A run was only recorded when the
        // stride CHANGED, so one that continues to the last event — a loop
        // walking an array right up to where the trace stops, the common case —
        // was silently dropped.
        if let Some(stride) = last_read_stride
            && read_stride_count >= 3
        {
            analysis.strided_accesses.push(StridedAccess {
                base: read_run_base.or(last_read_addr).unwrap_or(0),
                stride,
                count: read_stride_count,
                is_write: false,
            });
        }
        if let Some(stride) = last_write_stride
            && write_stride_count >= 3
        {
            analysis.strided_accesses.push(StridedAccess {
                base: write_run_base.or(last_write_addr).unwrap_or(0),
                stride,
                count: write_stride_count,
                is_write: true,
            });
        }

        analysis
    }

    /// Return the hottest memory regions (by total access count).
    #[must_use]
    pub fn hot_regions(&self, threshold: u64) -> Vec<&MemoryRegion> {
        self.regions
            .values()
            .filter(|r| r.is_hot(threshold))
            .collect()
    }

    /// Return cold (never-written) regions.
    #[must_use]
    pub fn cold_regions(&self) -> Vec<&MemoryRegion> {
        self.regions
            .values()
            .filter(|r| r.write_count == 0)
            .collect()
    }

    /// Total unique addresses touched.
    #[must_use]
    pub fn total_unique_addresses(&self) -> usize {
        let mut all = self.unique_addresses_read.clone();
        all.extend(&self.unique_addresses_written);
        all.len()
    }

    /// Working set size in bytes (granularity: page).
    #[must_use]
    pub fn working_set_bytes(&self) -> u64 {
        self.regions.len() as u64 * Self::REGION_GRANULARITY
    }
}

impl fmt::Display for MemoryPatternAnalysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MemoryPatternAnalysis {{ regions={}, reads={}, writes={} }}",
            self.regions.len(),
            self.total_reads,
            self.total_writes
        )
    }
}

// ─── ReplayInsights ──────────────────────────────────────────────────────────

/// Severity level for an insight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum InsightSeverity {
    Info,
    Warning,
    Critical,
}

impl fmt::Display for InsightSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARN"),
            Self::Critical => write!(f, "CRIT"),
        }
    }
}

/// A single textual insight derived from replay analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Insight {
    pub severity: InsightSeverity,
    pub category: String,
    pub message: String,
    pub position: Option<TracePosition>,
}

impl Insight {
    pub fn info(category: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: InsightSeverity::Info,
            category: category.into(),
            message: message.into(),
            position: None,
        }
    }

    pub fn warning(category: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: InsightSeverity::Warning,
            category: category.into(),
            message: message.into(),
            position: None,
        }
    }

    pub fn critical(category: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: InsightSeverity::Critical,
            category: category.into(),
            message: message.into(),
            position: None,
        }
    }

    #[must_use]
    pub const fn at(mut self, pos: TracePosition) -> Self {
        self.position = Some(pos);
        self
    }
}

impl fmt::Display for Insight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} — {}",
            self.severity, self.category, self.message
        )
    }
}

/// Aggregated insights from a full replay analysis pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReplayInsights {
    pub insights: Vec<Insight>,
    pub instruction_frequency: InstructionFrequency,
    pub call_chain: CallChainAnalysis,
    pub exception_chain: ExceptionChain,
    pub memory_patterns: MemoryPatternAnalysis,
    pub total_events: u64,
    pub trace_duration_seq: u64,
}

impl ReplayInsights {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push an insight.
    pub fn add(&mut self, insight: Insight) {
        self.insights.push(insight);
    }

    /// Return insights of the given severity.
    #[must_use]
    pub fn by_severity(&self, sev: InsightSeverity) -> Vec<&Insight> {
        self.insights.iter().filter(|i| i.severity == sev).collect()
    }

    /// Return insights in the given category.
    #[must_use]
    pub fn by_category(&self, cat: &str) -> Vec<&Insight> {
        self.insights.iter().filter(|i| i.category == cat).collect()
    }

    /// True if any critical insight exists.
    #[must_use]
    pub fn has_critical(&self) -> bool {
        self.insights
            .iter()
            .any(|i| i.severity == InsightSeverity::Critical)
    }

    /// Summary line.
    #[must_use]
    pub fn summary_line(&self) -> String {
        let crits = self.by_severity(InsightSeverity::Critical).len();
        let warns = self.by_severity(InsightSeverity::Warning).len();
        format!(
            "ReplayInsights: {} events, {} criticals, {} warnings, {} exceptions",
            self.total_events,
            crits,
            warns,
            self.exception_chain.exceptions.len()
        )
    }
}

impl fmt::Display for ReplayInsights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary_line())
    }
}

// ─── ReplayAnalysis ───────────────────────────────────────────────────────────

/// Top-level driver that analyses a replay session and produces [`ReplayInsights`].
pub struct ReplayAnalysis {
    trace: std::sync::Arc<TtdTrace>,
}

impl ReplayAnalysis {
    pub const fn new(trace: std::sync::Arc<TtdTrace>) -> Self {
        Self { trace }
    }

    /// Run all analysis passes and return the insights.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// # Panics
    /// Panics if internal invariants are violated.
    pub fn analyze(&self) -> Result<ReplayInsights, AnalysisError> {
        let events = self.trace.all_events();
        if events.is_empty() {
            return Err(AnalysisError::EmptyTrace);
        }

        let mut insights = ReplayInsights::new();
        insights.total_events = events.len() as u64;

        // Trace duration
        if let (Some(first), Some(last)) = (events.first(), events.last()) {
            insights.trace_duration_seq = last
                .position
                .sequence
                .saturating_sub(first.position.sequence);
        }

        // Instruction frequency
        let mut freq = InstructionFrequency::new();
        for event in &events {
            match &event.kind {
                EventKind::Call { to, .. } | EventKind::Return { to, .. } => freq.record(*to),
                EventKind::Breakpoint { addr } => freq.record(*addr),
                _ => {}
            }
        }
        insights.instruction_frequency = freq;

        // Call chain
        insights.call_chain = CallChainAnalysis::build_from_events(&events);

        // Exception chain
        insights.exception_chain = ExceptionChain::build_from_events(&events);

        // Memory patterns
        insights.memory_patterns = MemoryPatternAnalysis::build_from_events(&events);

        // ─ derive insights ───────────────────────────────────────────────────

        // High call depth warning
        if insights.call_chain.max_depth > 200 {
            insights.add(Insight::warning(
                "call_chain",
                format!("Call depth reached {}", insights.call_chain.max_depth),
            ));
        }

        // Exception insight
        if insights.exception_chain.has_access_violation() {
            let rec = insights.exception_chain.first_access_violation().unwrap();
            insights.add(
                Insight::critical(
                    "exception",
                    format!("Access violation @ {:#x}", rec.address),
                )
                .at(rec.position),
            );
        }

        // Recursion detection
        let recursive = insights.call_chain.recursive_calls();
        if !recursive.is_empty() {
            insights.add(Insight::warning(
                "call_chain",
                format!("Recursive calls detected at {} sites", recursive.len()),
            ));
        }

        // Unmatched returns
        if insights.call_chain.unmatched_returns > 0 {
            insights.add(Insight::warning(
                "call_chain",
                format!(
                    "{} unmatched return events (possible CFI violation)",
                    insights.call_chain.unmatched_returns
                ),
            ));
        }

        // Hot memory
        let hot = insights.memory_patterns.hot_regions(1000);
        if !hot.is_empty() {
            insights.add(Insight::info(
                "memory",
                format!("{} hot memory pages (>1000 accesses)", hot.len()),
            ));
        }

        // Strided memory patterns
        if !insights.memory_patterns.strided_accesses.is_empty() {
            insights.add(Insight::info(
                "memory",
                format!(
                    "{} strided access patterns detected (likely loops/SIMD)",
                    insights.memory_patterns.strided_accesses.len()
                ),
            ));
        }

        // Hot instruction
        if let Some((addr, cnt)) = insights.instruction_frequency.hottest()
            && cnt > 1000
        {
            insights.add(Insight::info(
                "instruction_frequency",
                format!("Hottest address {addr:#x} hit {cnt} times"),
            ));
        }

        Ok(insights)
    }

    /// Analyse only a subset of events between two positions.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn analyze_range(
        &self,
        from: TracePosition,
        to: TracePosition,
    ) -> Result<ReplayInsights, AnalysisError> {
        let all_events = self.trace.all_events();
        let events: Vec<TraceEvent> = all_events
            .into_iter()
            .filter(|e| e.position >= from && e.position <= to)
            .collect();
        if events.is_empty() {
            return Err(AnalysisError::EmptyTrace);
        }
        let scoped = ScopedTrace { events };
        let inner = Self::new(std::sync::Arc::new(scoped.into_trace()));
        inner.analyze()
    }
}

// Helper: build a minimal TtdTrace from a subset of events
struct ScopedTrace {
    events: Vec<TraceEvent>,
}

impl ScopedTrace {
    fn into_trace(self) -> TtdTrace {
        let _last_pos = self
            .events
            .last()
            .map_or_else(TracePosition::start, |e| e.position);
        let t = TtdTrace::new(rustre_ttd::TraceMetadata {
            pid: 0,
            process_name: "scoped".into(),
            ..rustre_ttd::TraceMetadata::default()
        });
        for ev in self.events {
            t.add_event(ev);
        }
        t
    }
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_ttd::{EventKind, TraceEvent, TraceMetadata, TracePosition, TtdTrace};
    use std::sync::Arc;

    fn pos(seq: u64) -> TracePosition {
        TracePosition {
            sequence: seq,
            step: 0,
        }
    }

    fn make_call(from: u64, to: u64, seq: u64) -> TraceEvent {
        TraceEvent {
            position: pos(seq),
            thread_id: 1,
            kind: EventKind::Call { from, to },
        }
    }

    fn make_return(from: u64, to: u64, seq: u64) -> TraceEvent {
        TraceEvent {
            position: pos(seq),
            thread_id: 1,
            kind: EventKind::Return { from, to },
        }
    }

    fn make_mem_write(addr: u64, data: Vec<u8>, seq: u64) -> TraceEvent {
        TraceEvent {
            position: pos(seq),
            thread_id: 1,
            kind: EventKind::MemWrite { addr, data },
        }
    }

    fn make_mem_read(addr: u64, len: usize, seq: u64) -> TraceEvent {
        TraceEvent {
            position: pos(seq),
            thread_id: 1,
            kind: EventKind::MemRead { addr, len },
        }
    }

    fn make_exception(code: u32, address: u64, seq: u64) -> TraceEvent {
        TraceEvent {
            position: pos(seq),
            thread_id: 1,
            kind: EventKind::Exception { code, addr: address },
        }
    }

    fn build_trace(events: Vec<TraceEvent>) -> Arc<TtdTrace> {
        let _ = events
            .last().map_or_else(TracePosition::start, |e| e.position);
        let t = TtdTrace::new(TraceMetadata {
            pid: 1,
            process_name: "test".into(),
            thread_count: 1,
            ..TraceMetadata::default()
        });
        for ev in events {
            t.add_event(ev);
        }
        Arc::new(t)
    }

    // ── InstructionFrequency ─────────────────────────────────────────────────

    #[test]
    fn test_freq_record_and_hottest() {
        let mut f = InstructionFrequency::new();
        f.record(0x1000);
        f.record(0x1000);
        f.record(0x2000);
        assert_eq!(f.hottest(), Some((0x1000, 2)));
    }

    #[test]
    fn test_freq_top_n() {
        let mut f = InstructionFrequency::new();
        for i in 0..10u64 {
            for _ in 0..=i {
                f.record(i * 0x100);
            }
        }
        let top = f.top_n(3);
        assert_eq!(top.len(), 3);
        assert!(top[0].1 >= top[1].1);
    }

    #[test]
    fn test_freq_cold_addresses() {
        let mut f = InstructionFrequency::new();
        f.record(0x1000);
        f.record(0x1000);
        f.record(0x2000);
        let cold = f.cold_addresses();
        assert!(cold.contains(&0x2000));
        assert!(!cold.contains(&0x1000));
    }

    #[test]
    fn test_freq_average_hits() {
        let mut f = InstructionFrequency::new();
        f.record(0x1000);
        f.record(0x1000);
        f.record(0x2000);
        // 3/2 = 1.5
        assert!((f.average_hits() - 1.5).abs() < 1e-9);
    }

    #[test]
    fn test_freq_merge() {
        let mut a = InstructionFrequency::new();
        a.record(0x1000);
        let mut b = InstructionFrequency::new();
        b.record(0x1000);
        b.record(0x2000);
        a.merge(&b);
        assert_eq!(*a.counts.get(&0x1000).unwrap(), 2);
        assert_eq!(*a.counts.get(&0x2000).unwrap(), 1);
    }

    #[test]
    fn test_freq_unique_addresses() {
        let mut f = InstructionFrequency::new();
        f.record(0xA);
        f.record(0xA);
        f.record(0xB);
        assert_eq!(f.unique_addresses(), 2);
    }

    #[test]
    fn test_freq_empty() {
        let f = InstructionFrequency::new();
        assert_eq!(f.hottest(), None);
        assert!((f.average_hits() - 0.0).abs() < f64::EPSILON);
    }

    // ── CallChainAnalysis ────────────────────────────────────────────────────

    #[test]
    fn test_call_chain_basic() {
        let events = vec![
            make_call(0x1000, 0x2000, 1),
            make_call(0x2000, 0x3000, 2),
            make_return(0x3000, 0x2004, 3),
            make_return(0x2000, 0x1004, 4),
        ];
        let chain = CallChainAnalysis::build_from_events(&events);
        assert_eq!(chain.total_calls, 2);
        assert_eq!(chain.total_returns, 2);
        assert_eq!(chain.max_depth, 2);
        assert_eq!(chain.unmatched_returns, 0);
    }

    #[test]
    fn test_call_chain_unmatched_return() {
        let events = vec![make_return(0x3000, 0x1000, 1)];
        let chain = CallChainAnalysis::build_from_events(&events);
        assert_eq!(chain.unmatched_returns, 1);
    }

    #[test]
    fn test_call_chain_callers_of() {
        let events = vec![make_call(0x1000, 0x2000, 1), make_call(0x3000, 0x2000, 2)];
        let chain = CallChainAnalysis::build_from_events(&events);
        let callers = chain.callers_of(0x2000);
        assert_eq!(callers.len(), 2);
    }

    #[test]
    fn test_call_chain_recursive() {
        let events = vec![
            make_call(0x1000, 0x2000, 1),
            make_call(0x2000, 0x2000, 2), // self-call
        ];
        let chain = CallChainAnalysis::build_from_events(&events);
        let rec = chain.recursive_calls();
        assert!(rec.contains(&0x2000));
    }

    #[test]
    fn test_call_chain_frames_at_depth() {
        let events = vec![make_call(0x1000, 0x2000, 1), make_call(0x2000, 0x3000, 2)];
        let chain = CallChainAnalysis::build_from_events(&events);
        assert_eq!(chain.frames_at_depth(0).len(), 1);
        assert_eq!(chain.frames_at_depth(1).len(), 1);
    }

    #[test]
    fn test_call_chain_unique_callees() {
        let events = vec![
            make_call(0x1000, 0x2000, 1),
            make_call(0x1000, 0x2000, 2),
            make_call(0x1000, 0x3000, 3),
        ];
        let chain = CallChainAnalysis::build_from_events(&events);
        assert_eq!(chain.unique_callees().len(), 2);
    }

    #[test]
    fn test_call_chain_exit_position() {
        let events = vec![make_call(0x1000, 0x2000, 1), make_return(0x2000, 0x1004, 5)];
        let chain = CallChainAnalysis::build_from_events(&events);
        assert!(chain.frames[0].exit_position.is_some());
    }

    // ── ExceptionChain ───────────────────────────────────────────────────────

    #[test]
    fn test_exception_chain_build() {
        let events = vec![
            make_exception(0xC000_0005, 0xDEAD, 10),
            make_exception(0xC000_001D, 0xBEEF, 20),
        ];
        let chain = ExceptionChain::build_from_events(&events);
        assert_eq!(chain.exceptions.len(), 2);
    }

    #[test]
    fn test_exception_chain_has_av() {
        let events = vec![make_exception(0xC000_0005, 0x1000, 1)];
        let chain = ExceptionChain::build_from_events(&events);
        assert!(chain.has_access_violation());
    }

    #[test]
    fn test_exception_chain_by_code() {
        let events = vec![
            make_exception(0xC000_0005, 0x1000, 1),
            make_exception(0xC000_0005, 0x2000, 2),
            make_exception(0xC000_001D, 0x3000, 3),
        ];
        let chain = ExceptionChain::build_from_events(&events);
        assert_eq!(chain.by_code(0xC000_0005).len(), 2);
    }

    #[test]
    fn test_exception_chain_unique_codes() {
        let events = vec![
            make_exception(0xC000_0005, 0x1000, 1),
            make_exception(0xC000_0005, 0x2000, 2),
            make_exception(0xC000_001D, 0x3000, 3),
        ];
        let chain = ExceptionChain::build_from_events(&events);
        assert_eq!(chain.unique_codes().len(), 2);
    }

    #[test]
    fn test_exception_no_av() {
        let events = vec![make_exception(0xC000_001D, 0x1000, 1)];
        let chain = ExceptionChain::build_from_events(&events);
        assert!(!chain.has_access_violation());
        assert!(chain.first_access_violation().is_none());
    }

    #[test]
    fn test_exception_describe_code() {
        let rec = ExceptionRecord::new(pos(1), 0xC000_0005, 0x1000, 1, true);
        assert!(rec.description.contains("Access Violation"));
    }

    // ── MemoryPatternAnalysis ────────────────────────────────────────────────

    #[test]
    fn test_mem_pattern_reads() {
        let events = vec![make_mem_read(0x1000, 8, 1), make_mem_read(0x2000, 8, 2)];
        let mp = MemoryPatternAnalysis::build_from_events(&events);
        assert_eq!(mp.total_reads, 2);
        assert_eq!(mp.total_writes, 0);
    }

    #[test]
    fn test_mem_pattern_writes() {
        let events = vec![
            make_mem_write(0x1000, vec![1, 2], 1),
            make_mem_write(0x1008, vec![3, 4], 2),
        ];
        let mp = MemoryPatternAnalysis::build_from_events(&events);
        assert_eq!(mp.total_writes, 2);
    }

    #[test]
    fn test_mem_pattern_hot_regions() {
        let mut events = Vec::new();
        for i in 0..2000u64 {
            events.push(make_mem_read(0x1000 + (i % 4096), 1, i));
        }
        let mp = MemoryPatternAnalysis::build_from_events(&events);
        let hot = mp.hot_regions(1000);
        assert!(!hot.is_empty());
    }

    #[test]
    fn test_mem_pattern_cold_regions() {
        let events = vec![make_mem_read(0x1000, 4, 1)];
        let mp = MemoryPatternAnalysis::build_from_events(&events);
        let cold = mp.cold_regions();
        assert_eq!(cold.len(), 1);
    }

    #[test]
    fn test_mem_pattern_unique_addresses() {
        let events = vec![
            make_mem_read(0x1000, 1, 1),
            make_mem_write(0x2000, vec![0], 2),
        ];
        let mp = MemoryPatternAnalysis::build_from_events(&events);
        assert_eq!(mp.total_unique_addresses(), 2);
    }

    #[test]
    fn test_mem_pattern_working_set() {
        let events = vec![make_mem_read(0x0000, 1, 1), make_mem_read(0x1000, 1, 2)];
        let mp = MemoryPatternAnalysis::build_from_events(&events);
        assert_eq!(mp.working_set_bytes(), 2 * 4096);
    }

    // ── ReplayInsights ───────────────────────────────────────────────────────

    #[test]
    fn test_insights_add_and_by_severity() {
        let mut ins = ReplayInsights::new();
        ins.add(Insight::info("cat", "msg"));
        ins.add(Insight::critical("cat2", "crit"));
        assert_eq!(ins.by_severity(InsightSeverity::Info).len(), 1);
        assert_eq!(ins.by_severity(InsightSeverity::Critical).len(), 1);
        assert!(ins.has_critical());
    }

    #[test]
    fn test_insights_by_category() {
        let mut ins = ReplayInsights::new();
        ins.add(Insight::info("alpha", "x"));
        ins.add(Insight::info("alpha", "y"));
        ins.add(Insight::info("beta", "z"));
        assert_eq!(ins.by_category("alpha").len(), 2);
        assert_eq!(ins.by_category("beta").len(), 1);
    }

    #[test]
    fn test_insights_summary_line() {
        let mut ins = ReplayInsights::new();
        ins.total_events = 500;
        ins.add(Insight::critical("x", "bad"));
        let s = ins.summary_line();
        assert!(s.contains("500"));
        assert!(s.contains("1 criticals"));
    }

    // ── ReplayAnalysis end-to-end ────────────────────────────────────────────

    #[test]
    fn test_replay_analysis_empty_trace_error() {
        let t = TtdTrace::new(TraceMetadata {
            pid: 1,
            process_name: "test".into(),
            thread_count: 0,
            ..TraceMetadata::default()
        });
        let analysis = ReplayAnalysis::new(Arc::new(t));
        assert!(matches!(analysis.analyze(), Err(AnalysisError::EmptyTrace)));
    }

    #[test]
    fn test_replay_analysis_with_av() {
        let trace = build_trace(vec![
            make_call(0x1000, 0x2000, 1),
            make_exception(0xC000_0005, 0x9000, 10),
        ]);
        let analysis = ReplayAnalysis::new(trace);
        let ins = analysis.analyze().unwrap();
        assert!(ins.has_critical());
    }

    #[test]
    fn test_replay_analysis_counts() {
        let trace = build_trace(vec![
            make_call(0x1000, 0x2000, 1),
            make_return(0x2000, 0x1004, 2),
        ]);
        let analysis = ReplayAnalysis::new(trace);
        let ins = analysis.analyze().unwrap();
        assert_eq!(ins.total_events, 2);
    }

    #[test]
    fn test_replay_analysis_memory_events() {
        let trace = build_trace(vec![
            make_mem_write(0x5000, vec![0xAA; 8], 1),
            make_mem_read(0x5000, 8, 2),
        ]);
        let analysis = ReplayAnalysis::new(trace);
        let ins = analysis.analyze().unwrap();
        assert_eq!(ins.memory_patterns.total_writes, 1);
        assert_eq!(ins.memory_patterns.total_reads, 1);
    }

    #[test]
    fn test_replay_analysis_trace_duration() {
        let trace = build_trace(vec![
            make_call(0x1000, 0x2000, 10),
            make_return(0x2000, 0x1004, 20),
        ]);
        let analysis = ReplayAnalysis::new(trace);
        let ins = analysis.analyze().unwrap();
        assert_eq!(ins.trace_duration_seq, 10);
    }

    #[test]
    fn test_insight_severity_ordering() {
        assert!(InsightSeverity::Critical > InsightSeverity::Warning);
        assert!(InsightSeverity::Warning > InsightSeverity::Info);
    }

    #[test]
    fn test_insight_at_position() {
        let i = Insight::info("test", "msg").at(pos(42));
        assert_eq!(i.position.unwrap().sequence, 42);
    }

    #[test]
    fn test_call_frame_duration() {
        let mut frame = CallFrame::new(0x1000, 0x2000, 0, pos(5), 0);
        frame.exit_position = Some(pos(15));
        assert_eq!(frame.duration_seq(), Some(10));
    }

    #[test]
    fn test_exception_record_fatal() {
        let rec = ExceptionRecord::new(pos(1), 0xC000_0005, 0x1000, 1, false);
        assert!(rec.is_fatal());
        let rec2 = ExceptionRecord::new(pos(2), 0xC000_0005, 0x1000, 1, true);
        assert!(!rec2.is_fatal());
    }

    #[test]
    fn test_mem_region_write_ratio() {
        let mut r = MemoryRegion::new(0x1000, 4096, pos(1));
        r.read_count = 3;
        r.write_count = 1;
        assert!((r.write_ratio() - 0.25).abs() < 1e-9);
    }

    #[test]
    fn test_exception_by_thread() {
        let mut chain = ExceptionChain::new();
        chain
            .exceptions
            .push(ExceptionRecord::new(pos(1), 0xC000_0005, 0x1000, 1, true));
        chain
            .exceptions
            .push(ExceptionRecord::new(pos(2), 0xC000_0005, 0x2000, 2, true));
        assert_eq!(chain.by_thread(1).len(), 1);
        assert_eq!(chain.by_thread(2).len(), 1);
    }

    #[test]
    fn test_strided_access_display() {
        let sa = StridedAccess {
            base: 0x1000,
            stride: 4,
            count: 10,
            is_write: false,
        };
        let s = format!("{sa}");
        assert!(s.contains("stride=4"));
    }
}
