//! `differential_replay` — Compare two TTD replay sessions for divergence.
//!
//! Provides:
//! * [`DifferentialReplay`]  — driver that compares two traces event-by-event
//! * [`ReplayDiff`]          — single point-of-divergence record
//! * [`RegisterDivergence`]  — register file difference at a position
//! * [`MemoryDivergence`]    — memory content difference at a position
//! * [`ExecutionPath`]       — ordered sequence of control-flow addresses
//! * [`DivergenceReport`]    — full report combining all divergences

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use rustre_ttd::{EventKind, TraceEvent, TracePosition, TtdTrace};

// ─── errors ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum DiffError {
    EmptyTrace(usize),
    AlignmentFailure(String),
    Custom(String),
}

impl fmt::Display for DiffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTrace(n) => write!(f, "trace {n} is empty"),
            Self::AlignmentFailure(s) => write!(f, "alignment failure: {s}"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for DiffError {}

// ─── RegisterDivergence ──────────────────────────────────────────────────────

/// Register file difference at a trace position between two sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterDivergence {
    pub position_a: TracePosition,
    pub position_b: TracePosition,
    pub thread_id: u32,
    /// register name → (`value_in_a`, `value_in_b`)
    pub differences: HashMap<String, (u64, u64)>,
}

impl RegisterDivergence {
    #[must_use] 
    pub fn new(
        position_a: TracePosition,
        position_b: TracePosition,
        thread_id: u32,
    ) -> Self {
        Self { position_a, position_b, thread_id, differences: HashMap::new() }
    }

    pub fn add(&mut self, reg: impl Into<String>, val_a: u64, val_b: u64) {
        self.differences.insert(reg.into(), (val_a, val_b));
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.differences.is_empty()
    }

    #[must_use] 
    pub fn changed_registers(&self) -> Vec<&String> {
        self.differences.keys().collect()
    }
}

impl fmt::Display for RegisterDivergence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RegisterDivergence {{ tid={}, diffs={} }}",
            self.thread_id,
            self.differences.len()
        )
    }
}

// ─── MemoryDivergence ────────────────────────────────────────────────────────

/// Memory content difference between two sessions at a position.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDivergence {
    pub position_a: TracePosition,
    pub position_b: TracePosition,
    /// address → (`bytes_in_a`, `bytes_in_b`)
    pub regions: Vec<(u64, Vec<u8>, Vec<u8>)>,
}

impl MemoryDivergence {
    #[must_use] 
    pub const fn new(position_a: TracePosition, position_b: TracePosition) -> Self {
        Self { position_a, position_b, regions: Vec::new() }
    }

    pub fn add_region(&mut self, addr: u64, a: Vec<u8>, b: Vec<u8>) {
        self.regions.push((addr, a, b));
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    #[must_use] 
    pub fn diverged_addresses(&self) -> Vec<u64> {
        self.regions.iter().map(|(a, _, _)| *a).collect()
    }

    /// Total bytes that differ.
    #[must_use] 
    pub fn total_differing_bytes(&self) -> usize {
        self.regions
            .iter()
            .map(|(_, a, b)| {
                a.iter()
                    .zip(b.iter())
                    .filter(|(x, y)| x != y)
                    .count()
            })
            .sum()
    }
}

impl fmt::Display for MemoryDivergence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MemoryDivergence {{ regions={}, total_diff_bytes={} }}",
            self.regions.len(),
            self.total_differing_bytes()
        )
    }
}

// ─── DivergenceKind ──────────────────────────────────────────────────────────

/// What kind of divergence was observed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DivergenceKind {
    ControlFlow,
    RegisterValue,
    MemoryContent,
    EventTypeMismatch,
    TraceLengthMismatch,
    ThreadIdMismatch,
}

impl fmt::Display for DivergenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ControlFlow => write!(f, "ControlFlow"),
            Self::RegisterValue => write!(f, "RegisterValue"),
            Self::MemoryContent => write!(f, "MemoryContent"),
            Self::EventTypeMismatch => write!(f, "EventTypeMismatch"),
            Self::TraceLengthMismatch => write!(f, "TraceLengthMismatch"),
            Self::ThreadIdMismatch => write!(f, "ThreadIdMismatch"),
        }
    }
}

// ─── ReplayDiff ──────────────────────────────────────────────────────────────

/// A single point of divergence between two replay sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayDiff {
    pub event_index: usize,
    pub kind: DivergenceKind,
    pub position_a: TracePosition,
    pub position_b: TracePosition,
    pub description: String,
    pub register_divergence: Option<RegisterDivergence>,
    pub memory_divergence: Option<MemoryDivergence>,
}

impl ReplayDiff {
    pub fn new(
        event_index: usize,
        kind: DivergenceKind,
        position_a: TracePosition,
        position_b: TracePosition,
        description: impl Into<String>,
    ) -> Self {
        Self {
            event_index,
            kind,
            position_a,
            position_b,
            description: description.into(),
            register_divergence: None,
            memory_divergence: None,
        }
    }

    #[must_use] 
    pub fn with_register_divergence(mut self, rd: RegisterDivergence) -> Self {
        self.register_divergence = Some(rd);
        self
    }

    #[must_use] 
    pub fn with_memory_divergence(mut self, md: MemoryDivergence) -> Self {
        self.memory_divergence = Some(md);
        self
    }

    #[must_use] 
    pub fn is_control_flow(&self) -> bool {
        self.kind == DivergenceKind::ControlFlow
    }
}

impl fmt::Display for ReplayDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ReplayDiff[{}] {:?} @ idx={}: {}",
            self.event_index, self.kind, self.event_index, self.description
        )
    }
}

// ─── ExecutionPath ───────────────────────────────────────────────────────────

/// Ordered sequence of control-flow addresses from a trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutionPath {
    pub addresses: Vec<u64>,
    pub positions: Vec<TracePosition>,
    pub name: String,
}

impl ExecutionPath {
    pub fn new(name: impl Into<String>) -> Self {
        Self { addresses: Vec::new(), positions: Vec::new(), name: name.into() }
    }

    pub fn push(&mut self, addr: u64, pos: TracePosition) {
        self.addresses.push(addr);
        self.positions.push(pos);
    }

    /// Build from a slice of trace events.
    pub fn build_from_events(events: &[TraceEvent], name: impl Into<String>) -> Self {
        let mut path = Self::new(name);
        path.addresses.reserve(events.len());
        path.positions.reserve(events.len());
        for ev in events {
            match &ev.kind {
                EventKind::Call { to, .. } | EventKind::Return { to, .. } => {
                    path.push(*to, ev.position);
                }
                EventKind::Breakpoint { addr } => {
                    path.push(*addr, ev.position);
                }
                _ => {}
            }
        }
        path
    }

    /// Length of common prefix with another path.
    #[must_use] 
    pub fn common_prefix_len(&self, other: &Self) -> usize {
        self.addresses
            .iter()
            .zip(other.addresses.iter())
            .take_while(|(a, b)| a == b)
            .count()
    }

    /// First address where the two paths diverge, plus the index.
    #[must_use] 
    pub fn first_divergence(&self, other: &Self) -> Option<(usize, u64, u64)> {
        let common = self.common_prefix_len(other);
        let a = self.addresses.get(common)?;
        let b = other.addresses.get(common)?;
        Some((common, *a, *b))
    }

    /// Unique addresses in this path.
    #[must_use] 
    pub fn unique_addresses(&self) -> HashSet<u64> {
        self.addresses.iter().copied().collect()
    }

    /// Addresses in `other` but not in `self`.
    #[must_use] 
    pub fn addresses_only_in_other(&self, other: &Self) -> Vec<u64> {
        let mine: HashSet<u64> = self.unique_addresses();
        other.addresses.iter().filter(|a| !mine.contains(*a)).copied().collect()
    }

    #[must_use] 
    pub const fn len(&self) -> usize {
        self.addresses.len()
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }
}

impl fmt::Display for ExecutionPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExecutionPath({}) len={}", self.name, self.addresses.len())
    }
}

// ─── DivergenceReport ────────────────────────────────────────────────────────

/// Severity of the overall divergence report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DivergenceSeverity {
    None,
    Minor,
    Moderate,
    Severe,
}

impl fmt::Display for DivergenceSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "NONE"),
            Self::Minor => write!(f, "MINOR"),
            Self::Moderate => write!(f, "MODERATE"),
            Self::Severe => write!(f, "SEVERE"),
        }
    }
}

/// Full differential analysis report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DivergenceReport {
    pub diffs: Vec<ReplayDiff>,
    pub path_a: ExecutionPath,
    pub path_b: ExecutionPath,
    pub events_compared: usize,
    pub first_divergence_index: Option<usize>,
    pub severity: DivergenceSeverity,
    pub summary: String,
}

impl DivergenceReport {
    #[must_use] 
    pub const fn new(path_a: ExecutionPath, path_b: ExecutionPath) -> Self {
        Self {
            diffs: Vec::new(),
            path_a,
            path_b,
            events_compared: 0,
            first_divergence_index: None,
            severity: DivergenceSeverity::None,
            summary: String::new(),
        }
    }

    pub fn push_diff(&mut self, diff: ReplayDiff) {
        if self.first_divergence_index.is_none() {
            self.first_divergence_index = Some(diff.event_index);
        }
        self.diffs.push(diff);
    }

    #[must_use] 
    pub fn diffs_of_kind(&self, kind: &DivergenceKind) -> Vec<&ReplayDiff> {
        self.diffs.iter().filter(|d| &d.kind == kind).collect()
    }

    #[must_use] 
    pub fn control_flow_divergences(&self) -> Vec<&ReplayDiff> {
        self.diffs_of_kind(&DivergenceKind::ControlFlow)
    }

    #[must_use] 
    pub const fn is_identical(&self) -> bool {
        self.diffs.is_empty()
    }

    pub fn compute_severity(&mut self) {
        let cf = self.diffs_of_kind(&DivergenceKind::ControlFlow).len();
        let reg = self.diffs_of_kind(&DivergenceKind::RegisterValue).len();
        let mem = self.diffs_of_kind(&DivergenceKind::MemoryContent).len();
        self.severity = match cf + reg + mem {
            0 => DivergenceSeverity::None,
            1..=5 => DivergenceSeverity::Minor,
            6..=20 => DivergenceSeverity::Moderate,
            _ => DivergenceSeverity::Severe,
        };
    }

    pub fn build_summary(&mut self) {
        self.summary = format!(
            "Compared {events} events. Divergences: {total} (CF={cf}, Reg={reg}, Mem={mem}). Severity: {sev}.",
            events = self.events_compared,
            total = self.diffs.len(),
            cf = self.diffs_of_kind(&DivergenceKind::ControlFlow).len(),
            reg = self.diffs_of_kind(&DivergenceKind::RegisterValue).len(),
            mem = self.diffs_of_kind(&DivergenceKind::MemoryContent).len(),
            sev = self.severity,
        );
    }
}

impl fmt::Display for DivergenceReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DivergenceReport {{ {} }}", self.summary)
    }
}

// ─── DifferentialReplay ──────────────────────────────────────────────────────

/// Compares two TTD traces event-by-event and produces a [`DivergenceReport`].
pub struct DifferentialReplay {
    trace_a: std::sync::Arc<TtdTrace>,
    trace_b: std::sync::Arc<TtdTrace>,
    /// Maximum number of divergences to collect before stopping.
    pub max_diffs: usize,
    /// If true, stop at the first control-flow divergence.
    pub stop_at_first_cf: bool,
}

impl DifferentialReplay {
    pub const fn new(
        trace_a: std::sync::Arc<TtdTrace>,
        trace_b: std::sync::Arc<TtdTrace>,
    ) -> Self {
        Self { trace_a, trace_b, max_diffs: 100, stop_at_first_cf: false }
    }

    #[must_use] 
    pub const fn with_max_diffs(mut self, n: usize) -> Self {
        self.max_diffs = n;
        self
    }

    #[must_use] 
    pub const fn stop_at_first_control_flow(mut self) -> Self {
        self.stop_at_first_cf = true;
        self
    }

    fn event_summary(ev: &TraceEvent) -> String {
        match &ev.kind {
            EventKind::Call { from, to } => format!("Call {from:#x}->{to:#x}"),
            EventKind::Return { from, to } => format!("Ret {from:#x}->{to:#x}"),
            EventKind::MemWrite { addr, data } => {
                format!("MemWrite {:#x} len={}", addr, data.len())
            }
            EventKind::MemRead { addr, len } => format!("MemRead {addr:#x} len={len}"),
            EventKind::SyscallEnter { nr, .. } => format!("SyscallEnter nr={nr}"),
            EventKind::SyscallExit { ret, .. } => format!("SyscallExit ret={ret:#x}"),
            EventKind::Exception { code, addr } => {
                format!("Exception {code:#x}@{addr:#x}")
            }
            EventKind::ThreadCreate { tid } => format!("ThreadCreate {tid}"),
            EventKind::ThreadExit { tid, .. } => format!("ThreadExit {tid}"),
            EventKind::Breakpoint { addr } => format!("BP {addr:#x}"),
        }
    }

    fn same_kind(a: &EventKind, b: &EventKind) -> bool {
        std::mem::discriminant(a) == std::mem::discriminant(b)
    }

    fn compare_call_events(
        &self,
        idx: usize,
        ea: &TraceEvent,
        eb: &TraceEvent,
        diffs: &mut Vec<ReplayDiff>,
    ) {
        if let (EventKind::Call { to: to_a, .. }, EventKind::Call { to: to_b, .. }) =
            (&ea.kind, &eb.kind)
            && to_a != to_b {
                diffs.push(ReplayDiff::new(
                    idx,
                    DivergenceKind::ControlFlow,
                    ea.position,
                    eb.position,
                    format!("Call target diverged: {to_a:#x} vs {to_b:#x}"),
                ));
            }
    }

    fn compare_memory_write(
        &self,
        idx: usize,
        ea: &TraceEvent,
        eb: &TraceEvent,
        diffs: &mut Vec<ReplayDiff>,
    ) {
        if let (
            EventKind::MemWrite { addr: addr_a, data: data_a },
            EventKind::MemWrite { addr: addr_b, data: data_b },
        ) = (&ea.kind, &eb.kind)
            && (addr_a != addr_b || data_a != data_b) {
                let mut md = MemoryDivergence::new(ea.position, eb.position);
                let base = (*addr_a).min(*addr_b);
                md.add_region(base, data_a.clone(), data_b.clone());
                diffs.push(
                    ReplayDiff::new(
                        idx,
                        DivergenceKind::MemoryContent,
                        ea.position,
                        eb.position,
                        format!("MemWrite diverged: addr {addr_a:#x} vs {addr_b:#x}"),
                    )
                    .with_memory_divergence(md),
                );
            }
    }

    /// Run the differential comparison and produce a [`DivergenceReport`].
    pub fn compare(&self) -> Result<DivergenceReport, DiffError> {
        let events_a = self.trace_a.all_events();
        let events_b = self.trace_b.all_events();

        if events_a.is_empty() {
            return Err(DiffError::EmptyTrace(0));
        }
        if events_b.is_empty() {
            return Err(DiffError::EmptyTrace(1));
        }

        let path_a = ExecutionPath::build_from_events(&events_a, "trace_a");
        let path_b = ExecutionPath::build_from_events(&events_b, "trace_b");
        let mut report = DivergenceReport::new(path_a, path_b);

        let common_len = events_a.len().min(events_b.len());
        report.events_compared = common_len;

        let mut local_diffs: Vec<ReplayDiff> = Vec::with_capacity(self.max_diffs.min(common_len));
        let mut saw_control_flow = false;

        for idx in 0..common_len {
            if local_diffs.len() >= self.max_diffs {
                break;
            }
            let prev_len = local_diffs.len();
            let ea = &events_a[idx];
            let eb = &events_b[idx];

            // Thread mismatch
            if ea.thread_id != eb.thread_id {
                local_diffs.push(ReplayDiff::new(
                    idx,
                    DivergenceKind::ThreadIdMismatch,
                    ea.position,
                    eb.position,
                    format!("Thread ID {} vs {}", ea.thread_id, eb.thread_id),
                ));
                continue;
            }

            // Event kind mismatch
            if !Self::same_kind(&ea.kind, &eb.kind) {
                let diff = ReplayDiff::new(
                    idx,
                    DivergenceKind::EventTypeMismatch,
                    ea.position,
                    eb.position,
                    format!(
                        "Event type mismatch: {} vs {}",
                        Self::event_summary(ea),
                        Self::event_summary(eb)
                    ),
                );
                local_diffs.push(diff);
                if self.stop_at_first_cf {
                    break;
                }
                continue;
            }

            self.compare_call_events(idx, ea, eb, &mut local_diffs);
            self.compare_memory_write(idx, ea, eb, &mut local_diffs);

            if self.stop_at_first_cf && !saw_control_flow {
                saw_control_flow = local_diffs[prev_len..]
                    .iter()
                    .any(|d| d.kind == DivergenceKind::ControlFlow);
                if saw_control_flow {
                    break;
                }
            }
        }

        // Trace length mismatch
        if events_a.len() != events_b.len() {
            local_diffs.push(ReplayDiff::new(
                common_len,
                DivergenceKind::TraceLengthMismatch,
                events_a
                    .last().map_or_else(TracePosition::start, |e| e.position),
                events_b
                    .last().map_or_else(TracePosition::start, |e| e.position),
                format!(
                    "Trace length mismatch: {} vs {} events",
                    events_a.len(),
                    events_b.len()
                ),
            ));
        }

        for d in local_diffs {
            report.push_diff(d);
        }

        report.compute_severity();
        report.build_summary();
        Ok(report)
    }
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_ttd::{EventKind, TraceEvent, TraceMetadata, TracePosition, TtdTrace};
    use std::sync::Arc;

    fn pos(seq: u64) -> TracePosition {
        TracePosition { sequence: seq, step: 0 }
    }

    fn ev_call(from: u64, to: u64, seq: u64) -> TraceEvent {
        TraceEvent { position: pos(seq), thread_id: 1, kind: EventKind::Call { from, to } }
    }

    fn ev_ret(from: u64, to: u64, seq: u64) -> TraceEvent {
        TraceEvent { position: pos(seq), thread_id: 1, kind: EventKind::Return { from, to } }
    }

    fn ev_write(addr: u64, data: Vec<u8>, seq: u64) -> TraceEvent {
        TraceEvent { position: pos(seq), thread_id: 1, kind: EventKind::MemWrite { addr, data } }
    }

    fn ev_read(addr: u64, len: usize, seq: u64) -> TraceEvent {
        TraceEvent { position: pos(seq), thread_id: 1, kind: EventKind::MemRead { addr, len } }
    }

    fn build_trace(events: Vec<TraceEvent>) -> Arc<TtdTrace> {
        let last = events.last().map_or_else(TracePosition::start, |e| e.position);
        let mut t = TtdTrace::new(TraceMetadata {
            pid: 1,
            process_name: "test".into(),
            start_position: TracePosition::start(),
            end_position: last,
            thread_count: 1,
            ..Default::default()
        });
        for ev in events { t.push_event(ev); }
        Arc::new(t)
    }

    // ── RegisterDivergence ───────────────────────────────────────────────────

    #[test]
    fn test_register_divergence_add() {
        let mut rd = RegisterDivergence::new(pos(1), pos(1), 1);
        rd.add("rax", 10, 20);
        assert_eq!(rd.differences.len(), 1);
        assert!(!rd.is_empty());
    }

    #[test]
    fn test_register_divergence_empty() {
        let rd = RegisterDivergence::new(pos(1), pos(1), 1);
        assert!(rd.is_empty());
    }

    #[test]
    fn test_register_divergence_changed_registers() {
        let mut rd = RegisterDivergence::new(pos(1), pos(1), 1);
        rd.add("rax", 1, 2);
        rd.add("rbx", 3, 4);
        let changed = rd.changed_registers();
        assert_eq!(changed.len(), 2);
    }

    // ── MemoryDivergence ─────────────────────────────────────────────────────

    #[test]
    fn test_memory_divergence_total_differing_bytes() {
        let mut md = MemoryDivergence::new(pos(1), pos(1));
        md.add_region(0x1000, vec![0, 1, 2, 3], vec![0, 9, 2, 9]);
        assert_eq!(md.total_differing_bytes(), 2);
    }

    #[test]
    fn test_memory_divergence_empty() {
        let md = MemoryDivergence::new(pos(1), pos(2));
        assert!(md.is_empty());
        assert_eq!(md.total_differing_bytes(), 0);
    }

    #[test]
    fn test_memory_divergence_diverged_addresses() {
        let mut md = MemoryDivergence::new(pos(1), pos(1));
        md.add_region(0x1000, vec![1], vec![2]);
        md.add_region(0x2000, vec![3], vec![4]);
        assert_eq!(md.diverged_addresses().len(), 2);
    }

    // ── ExecutionPath ────────────────────────────────────────────────────────

    #[test]
    fn test_execution_path_build() {
        let events = vec![ev_call(0x1000, 0x2000, 1), ev_ret(0x2000, 0x1004, 2)];
        let path = ExecutionPath::build_from_events(&events, "a");
        assert_eq!(path.len(), 2);
    }

    #[test]
    fn test_execution_path_common_prefix() {
        let mut a = ExecutionPath::new("a");
        let mut b = ExecutionPath::new("b");
        a.push(0x1000, pos(1));
        a.push(0x2000, pos(2));
        a.push(0x3000, pos(3));
        b.push(0x1000, pos(1));
        b.push(0x2000, pos(2));
        b.push(0x4000, pos(3));
        assert_eq!(a.common_prefix_len(&b), 2);
    }

    #[test]
    fn test_execution_path_first_divergence() {
        let mut a = ExecutionPath::new("a");
        let mut b = ExecutionPath::new("b");
        a.push(0x1000, pos(1));
        a.push(0x9000, pos(2));
        b.push(0x1000, pos(1));
        b.push(0x8000, pos(2));
        let (idx, va, vb) = a.first_divergence(&b).unwrap();
        assert_eq!(idx, 1);
        assert_eq!(va, 0x9000);
        assert_eq!(vb, 0x8000);
    }

    #[test]
    fn test_execution_path_no_divergence() {
        let mut a = ExecutionPath::new("a");
        let mut b = ExecutionPath::new("b");
        a.push(0x1000, pos(1));
        b.push(0x1000, pos(1));
        assert!(a.first_divergence(&b).is_none());
    }

    #[test]
    fn test_execution_path_unique_addresses() {
        let mut p = ExecutionPath::new("p");
        p.push(0x1000, pos(1));
        p.push(0x1000, pos(2));
        p.push(0x2000, pos(3));
        assert_eq!(p.unique_addresses().len(), 2);
    }

    #[test]
    fn test_execution_path_only_in_other() {
        let mut a = ExecutionPath::new("a");
        let mut b = ExecutionPath::new("b");
        a.push(0x1000, pos(1));
        b.push(0x1000, pos(1));
        b.push(0x9999, pos(2));
        let only = a.addresses_only_in_other(&b);
        assert_eq!(only, vec![0x9999u64]);
    }

    // ── DivergenceReport ─────────────────────────────────────────────────────

    #[test]
    fn test_report_is_identical() {
        let r = DivergenceReport::new(ExecutionPath::new("a"), ExecutionPath::new("b"));
        assert!(r.is_identical());
    }

    #[test]
    fn test_report_compute_severity_none() {
        let mut r = DivergenceReport::new(ExecutionPath::new("a"), ExecutionPath::new("b"));
        r.compute_severity();
        assert_eq!(r.severity, DivergenceSeverity::None);
    }

    #[test]
    fn test_report_compute_severity_severe() {
        let mut r = DivergenceReport::new(ExecutionPath::new("a"), ExecutionPath::new("b"));
        for i in 0..25 {
            r.push_diff(ReplayDiff::new(i, DivergenceKind::ControlFlow, pos(i as u64), pos(i as u64), ""));
        }
        r.compute_severity();
        assert_eq!(r.severity, DivergenceSeverity::Severe);
    }

    #[test]
    fn test_report_first_divergence_index() {
        let mut r = DivergenceReport::new(ExecutionPath::new("a"), ExecutionPath::new("b"));
        r.push_diff(ReplayDiff::new(5, DivergenceKind::ControlFlow, pos(5), pos(5), "x"));
        assert_eq!(r.first_divergence_index, Some(5));
    }

    #[test]
    fn test_report_diffs_of_kind() {
        let mut r = DivergenceReport::new(ExecutionPath::new("a"), ExecutionPath::new("b"));
        r.push_diff(ReplayDiff::new(0, DivergenceKind::ControlFlow, pos(0), pos(0), "cf"));
        r.push_diff(ReplayDiff::new(1, DivergenceKind::MemoryContent, pos(1), pos(1), "mem"));
        assert_eq!(r.diffs_of_kind(&DivergenceKind::ControlFlow).len(), 1);
        assert_eq!(r.diffs_of_kind(&DivergenceKind::MemoryContent).len(), 1);
    }

    // ── DifferentialReplay end-to-end ─────────────────────────────────────────

    #[test]
    fn test_identical_traces_no_diffs() {
        let events = vec![ev_call(0x1000, 0x2000, 1), ev_ret(0x2000, 0x1004, 2)];
        let a = build_trace(events.clone());
        let b = build_trace(events);
        let dr = DifferentialReplay::new(a, b);
        let report = dr.compare().unwrap();
        assert!(report.is_identical());
        assert_eq!(report.severity, DivergenceSeverity::None);
    }

    #[test]
    fn test_different_call_targets() {
        let a = build_trace(vec![ev_call(0x1000, 0x2000, 1)]);
        let b = build_trace(vec![ev_call(0x1000, 0x3000, 1)]);
        let report = DifferentialReplay::new(a, b).compare().unwrap();
        assert!(!report.is_identical());
        assert!(!report.control_flow_divergences().is_empty());
    }

    #[test]
    fn test_event_type_mismatch() {
        let a = build_trace(vec![ev_call(0x1000, 0x2000, 1)]);
        let b = build_trace(vec![ev_ret(0x2000, 0x1004, 1)]);
        let report = DifferentialReplay::new(a, b).compare().unwrap();
        assert!(!report.is_identical());
        assert!(!report.diffs_of_kind(&DivergenceKind::EventTypeMismatch).is_empty());
    }

    #[test]
    fn test_trace_length_mismatch() {
        let a = build_trace(vec![ev_call(0x1000, 0x2000, 1), ev_ret(0x2000, 0x1004, 2)]);
        let b = build_trace(vec![ev_call(0x1000, 0x2000, 1)]);
        let report = DifferentialReplay::new(a, b).compare().unwrap();
        assert!(!report.diffs_of_kind(&DivergenceKind::TraceLengthMismatch).is_empty());
    }

    #[test]
    fn test_empty_trace_error() {
        let a = build_trace(vec![ev_call(0x1000, 0x2000, 1)]);
        let b_trace = TtdTrace::new(TraceMetadata {
            pid: 2,
            process_name: "empty".into(),
            start_position: TracePosition::start(),
            end_position: TracePosition::start(),
            thread_count: 0,
            ..Default::default()
        });
        let b = Arc::new(b_trace);
        let result = DifferentialReplay::new(a, b).compare();
        assert!(matches!(result, Err(DiffError::EmptyTrace(1))));
    }

    #[test]
    fn test_memory_write_divergence() {
        let a = build_trace(vec![ev_write(0x1000, vec![1, 2, 3], 1)]);
        let b = build_trace(vec![ev_write(0x1000, vec![4, 5, 6], 1)]);
        let report = DifferentialReplay::new(a, b).compare().unwrap();
        assert!(!report.diffs_of_kind(&DivergenceKind::MemoryContent).is_empty());
    }

    #[test]
    fn test_stop_at_first_cf() {
        let a = build_trace(vec![
            ev_call(0x1000, 0x2000, 1),
            ev_call(0x2000, 0x3000, 2),
            ev_call(0x3000, 0x4000, 3),
        ]);
        let b = build_trace(vec![
            ev_call(0x1000, 0x9999, 1),
            ev_call(0x2000, 0x3000, 2),
            ev_call(0x3000, 0x4000, 3),
        ]);
        let dr = DifferentialReplay::new(a, b).stop_at_first_control_flow();
        let report = dr.compare().unwrap();
        assert_eq!(report.diffs_of_kind(&DivergenceKind::ControlFlow).len(), 1);
    }

    #[test]
    fn test_max_diffs_limit() {
        let events_a: Vec<TraceEvent> =
            (0..50).map(|i| ev_call(0x1000, 0x2000 + i, i)).collect();
        let events_b: Vec<TraceEvent> =
            (0..50).map(|i| ev_call(0x1000, 0x9000 + i, i)).collect();
        let a = build_trace(events_a);
        let b = build_trace(events_b);
        let dr = DifferentialReplay::new(a, b).with_max_diffs(5);
        let report = dr.compare().unwrap();
        assert!(report.diffs.len() <= 5);
    }

    #[test]
    fn test_replay_diff_is_control_flow() {
        let d = ReplayDiff::new(0, DivergenceKind::ControlFlow, pos(0), pos(0), "x");
        assert!(d.is_control_flow());
    }

    #[test]
    fn test_replay_diff_with_register_divergence() {
        let mut rd = RegisterDivergence::new(pos(1), pos(1), 1);
        rd.add("rax", 1, 2);
        let diff = ReplayDiff::new(0, DivergenceKind::RegisterValue, pos(0), pos(0), "x")
            .with_register_divergence(rd);
        assert!(diff.register_divergence.is_some());
    }

    #[test]
    fn test_divergence_severity_ordering() {
        assert!(DivergenceSeverity::Severe > DivergenceSeverity::None);
    }

    #[test]
    fn test_report_build_summary() {
        let mut r = DivergenceReport::new(ExecutionPath::new("a"), ExecutionPath::new("b"));
        r.events_compared = 100;
        r.compute_severity();
        r.build_summary();
        assert!(r.summary.contains("100"));
    }

    #[test]
    fn test_read_events_not_compared_for_cf() {
        let a = build_trace(vec![ev_read(0x1000, 4, 1)]);
        let b = build_trace(vec![ev_read(0x2000, 4, 1)]);
        // MemRead events don't produce ControlFlow diffs
        let report = DifferentialReplay::new(a, b).compare().unwrap();
        assert!(report.diffs_of_kind(&DivergenceKind::ControlFlow).is_empty());
    }

    #[test]
    fn test_execution_path_is_empty() {
        let p = ExecutionPath::new("empty");
        assert!(p.is_empty());
        assert_eq!(p.len(), 0);
    }

    #[test]
    fn test_execution_path_build_from_empty() {
        let path = ExecutionPath::build_from_events(&[], "empty");
        assert!(path.is_empty());
    }

    #[test]
    fn test_register_divergence_display() {
        let mut rd = RegisterDivergence::new(pos(1), pos(2), 1);
        rd.add("rax", 0, 1);
        let s = format!("{rd}");
        assert!(s.contains("tid=1"));
        assert!(s.contains("diffs=1"));
    }

    #[test]
    fn test_memory_divergence_display() {
        let mut md = MemoryDivergence::new(pos(1), pos(2));
        md.add_region(0x1000, vec![1], vec![2]);
        let s = format!("{md}");
        assert!(s.contains("regions=1"));
    }

    #[test]
    fn test_replay_diff_display() {
        let d = ReplayDiff::new(3, DivergenceKind::ControlFlow, pos(1), pos(2), "diverged");
        let s = format!("{d}");
        assert!(s.contains("ReplayDiff"));
    }

    #[test]
    fn test_divergence_report_no_cf() {
        let r = DivergenceReport::new(ExecutionPath::new("a"), ExecutionPath::new("b"));
        assert!(r.control_flow_divergences().is_empty());
    }

    #[test]
    fn test_divergence_kind_display() {
        let s = format!("{}", DivergenceKind::ControlFlow);
        assert_eq!(s, "ControlFlow");
    }

    #[test]
    fn test_severity_moderate() {
        let mut r = DivergenceReport::new(ExecutionPath::new("a"), ExecutionPath::new("b"));
        for i in 0..10 {
            r.push_diff(ReplayDiff::new(i, DivergenceKind::ControlFlow, pos(i as u64), pos(i as u64), ""));
        }
        r.compute_severity();
        assert_eq!(r.severity, DivergenceSeverity::Moderate);
    }

    #[test]
    fn test_memory_divergence_identical_bytes() {
        let mut md = MemoryDivergence::new(pos(1), pos(1));
        md.add_region(0x1000, vec![1, 2, 3], vec![1, 2, 3]);
        assert_eq!(md.total_differing_bytes(), 0);
    }

    #[test]
    fn test_differential_replay_builder() {
        let a = build_trace(vec![ev_call(0, 0, 1)]);
        let b = build_trace(vec![ev_call(0, 0, 1)]);
        let dr = DifferentialReplay::new(a, b).with_max_diffs(10).stop_at_first_control_flow();
        assert_eq!(dr.max_diffs, 10);
        assert!(dr.stop_at_first_cf);
    }
}
