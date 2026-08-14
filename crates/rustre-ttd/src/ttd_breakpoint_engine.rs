//! Breakpoint engine for TTD traces: code breakpoints, memory watchpoints,
//! data breakpoints, hit-count conditions, and breakpoint matching over a
//! recorded event stream.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{EventKind, TraceEvent};
use crate::ttd_position::TtdPosition;

// ─── BreakpointKind ───────────────────────────────────────────────────────────

/// What kind of event a breakpoint matches.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BreakpointKind {
    /// Match any `Call` event to `address`.
    Code {
        /// Target instruction address.
        address: u64,
    },
    /// Match any memory-read that overlaps `[address, address + size)`.
    MemoryRead {
        /// Start of the watched region.
        address: u64,
        /// Size in bytes.
        size: u64,
    },
    /// Match any memory-write that overlaps `[address, address + size)`.
    MemoryWrite {
        /// Start of the watched region.
        address: u64,
        /// Size in bytes.
        size: u64,
    },
    /// Match either a read or write that overlaps `[address, address + size)`.
    MemoryAccess {
        /// Start of the watched region.
        address: u64,
        /// Size in bytes.
        size: u64,
    },
    /// Match a `SyscallEnter` event with the given syscall number.
    Syscall {
        /// Syscall number.
        nr: u32,
    },
    /// Match any `Exception` event with the given exception code, or any code
    /// if `code` is `None`.
    Exception {
        /// Optional specific exception code.
        code: Option<u32>,
    },
    /// Match a call **from** any address **to** `callee`.
    CallTo {
        /// Callee address.
        callee: u64,
    },
    /// Match a return **from** `address`.
    ReturnFrom {
        /// The function address from which the return originates.
        address: u64,
    },
    /// Match a thread-creation event for a specific TID (or any if `None`).
    ThreadCreate {
        /// Optional specific thread identifier.
        tid: Option<u32>,
    },
}

impl fmt::Display for BreakpointKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Code { address } => write!(f, "Code({address:#x})"),
            Self::MemoryRead { address, size } => write!(f, "MemRead({address:#x}+{size})"),
            Self::MemoryWrite { address, size } => write!(f, "MemWrite({address:#x}+{size})"),
            Self::MemoryAccess { address, size } => write!(f, "MemAccess({address:#x}+{size})"),
            Self::Syscall { nr } => write!(f, "Syscall(nr={nr})"),
            Self::Exception { code: None } => write!(f, "Exception(any)"),
            Self::Exception { code: Some(c) } => write!(f, "Exception({c:#x})"),
            Self::CallTo { callee } => write!(f, "CallTo({callee:#x})"),
            Self::ReturnFrom { address } => write!(f, "ReturnFrom({address:#x})"),
            Self::ThreadCreate { tid: None } => write!(f, "ThreadCreate(any)"),
            Self::ThreadCreate { tid: Some(t) } => write!(f, "ThreadCreate(tid={t})"),
        }
    }
}

// ─── HitCondition ────────────────────────────────────────────────────────────

/// Additional condition that must be satisfied for a breakpoint to fire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum HitCondition {
    /// Fire on every hit (default).
    #[default]
    Always,
    /// Fire only on the N-th hit (1-based).
    NthHit(u64),
    /// Fire only after `n` previous hits have been skipped.
    AfterSkip(u64),
    /// Fire on every N-th hit (mod condition).
    EveryN(u64),
    /// Fire only when the position falls in `[start, end)`.
    InRange(TtdPosition, TtdPosition),
    /// Fire only on hits with thread ID matching `tid`.
    Thread(u32),
}

impl HitCondition {
    /// Evaluate whether the condition allows the breakpoint to fire.
    ///
    /// `hit_count` is the 1-based count of this specific hit (incremented
    /// before this call).
    #[must_use] 
    pub fn allows_fire(&self, hit_count: u64, position: TtdPosition, thread_id: u32) -> bool {
        match self {
            Self::Always => true,
            Self::NthHit(n) => hit_count == *n,
            Self::AfterSkip(n) => hit_count > *n,
            Self::EveryN(n) => *n > 0 && hit_count.is_multiple_of(*n),
            Self::InRange(start, end) => position.in_range(start, end),
            Self::Thread(tid) => thread_id == *tid,
        }
    }
}


impl fmt::Display for HitCondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Always => write!(f, "always"),
            Self::NthHit(n) => write!(f, "nth_hit({n})"),
            Self::AfterSkip(n) => write!(f, "after_skip({n})"),
            Self::EveryN(n) => write!(f, "every_{n}"),
            Self::InRange(s, e) => write!(f, "in_range({s}, {e})"),
            Self::Thread(t) => write!(f, "thread({t})"),
        }
    }
}

// ─── TtdBreakpoint ────────────────────────────────────────────────────────────

/// A single breakpoint registered with the [`TtdBreakpointEngine`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtdBreakpoint {
    /// Unique identifier assigned at registration.
    pub id: u32,
    /// What kind of event triggers this breakpoint.
    pub kind: BreakpointKind,
    /// Additional firing condition.
    pub condition: HitCondition,
    /// Optional human-readable label.
    pub label: Option<String>,
    /// Whether this breakpoint is active.
    pub enabled: bool,
    /// Total number of times this breakpoint has been matched (including
    /// hits suppressed by `condition`).
    pub total_hits: u64,
    /// Number of times this breakpoint actually fired (condition passed).
    pub fired_count: u64,
}

impl TtdBreakpoint {
    const fn new(id: u32, kind: BreakpointKind) -> Self {
        Self {
            id,
            kind,
            condition: HitCondition::Always,
            label: None,
            enabled: true,
            total_hits: 0,
            fired_count: 0,
        }
    }

    /// Attach a label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Set the hit condition.
    #[must_use] 
    pub const fn with_condition(mut self, cond: HitCondition) -> Self {
        self.condition = cond;
        self
    }

    /// Return `true` if `event` matches the breakpoint kind.
    fn matches_event(&self, event: &TraceEvent) -> bool {
        match &self.kind {
            BreakpointKind::Code { address } => {
                matches!(&event.kind, EventKind::Call { to, .. } if to == address)
                    || matches!(&event.kind, EventKind::Breakpoint { addr } if addr == address)
            }
            BreakpointKind::MemoryRead { address, size } => {
                if let EventKind::MemRead { addr, len } = &event.kind {
                    ranges_overlap(*addr, *len as u64, *address, *size)
                } else {
                    false
                }
            }
            BreakpointKind::MemoryWrite { address, size } => {
                if let EventKind::MemWrite { addr, data } = &event.kind {
                    ranges_overlap(*addr, data.len() as u64, *address, *size)
                } else {
                    false
                }
            }
            BreakpointKind::MemoryAccess { address, size } => {
                match &event.kind {
                    EventKind::MemRead { addr, len } => {
                        ranges_overlap(*addr, *len as u64, *address, *size)
                    }
                    EventKind::MemWrite { addr, data } => {
                        ranges_overlap(*addr, data.len() as u64, *address, *size)
                    }
                    _ => false,
                }
            }
            BreakpointKind::Syscall { nr } => {
                matches!(&event.kind, EventKind::SyscallEnter { nr: n, .. } if n == nr)
            }
            BreakpointKind::Exception { code: None } => {
                matches!(&event.kind, EventKind::Exception { .. })
            }
            BreakpointKind::Exception { code: Some(c) } => {
                matches!(&event.kind, EventKind::Exception { code, .. } if code == c)
            }
            BreakpointKind::CallTo { callee } => {
                matches!(&event.kind, EventKind::Call { to, .. } if to == callee)
            }
            BreakpointKind::ReturnFrom { address } => {
                matches!(&event.kind, EventKind::Return { from, .. } if from == address)
            }
            BreakpointKind::ThreadCreate { tid: None } => {
                matches!(&event.kind, EventKind::ThreadCreate { .. })
            }
            BreakpointKind::ThreadCreate { tid: Some(t) } => {
                matches!(&event.kind, EventKind::ThreadCreate { tid } if tid == t)
            }
        }
    }
}

impl fmt::Display for TtdBreakpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = self.label.as_deref().unwrap_or("(no label)");
        let en = if self.enabled { "on" } else { "off" };
        write!(
            f,
            "BP[{}] {} kind={} cond={} hits={}/{} {}",
            self.id, label, self.kind, self.condition,
            self.fired_count, self.total_hits, en
        )
    }
}

// ─── BreakpointHit ────────────────────────────────────────────────────────────

/// A record of one breakpoint firing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointHit {
    /// Breakpoint ID that fired.
    pub bp_id: u32,
    /// The TTD position at which the hit occurred.
    pub position: TtdPosition,
    /// Thread that generated the triggering event.
    pub thread_id: u32,
    /// Hit number (1-based) for this specific breakpoint.
    pub hit_number: u64,
}

impl fmt::Display for BreakpointHit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Hit {{ bp={}, pos={}, tid={}, hit# {} }}",
            self.bp_id, self.position, self.thread_id, self.hit_number
        )
    }
}

// ─── TtdBreakpointEngine ──────────────────────────────────────────────────────

/// Manages a set of breakpoints and matches them against a TTD event stream.
#[derive(Debug, Default)]
pub struct TtdBreakpointEngine {
    breakpoints: HashMap<u32, TtdBreakpoint>,
    next_id: u32,
    hits: Vec<BreakpointHit>,
}

impl TtdBreakpointEngine {
    /// Create an empty breakpoint engine.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new breakpoint and return its ID.
    pub fn add(&mut self, kind: BreakpointKind) -> u32 {
        self.next_id += 1;
        let id = self.next_id;
        self.breakpoints.insert(id, TtdBreakpoint::new(id, kind));
        id
    }

    /// Register a breakpoint with a label.
    pub fn add_labeled(&mut self, kind: BreakpointKind, label: impl Into<String>) -> u32 {
        let id = self.add(kind);
        if let Some(bp) = self.breakpoints.get_mut(&id) {
            bp.label = Some(label.into());
        }
        id
    }

    /// Set the hit condition on an existing breakpoint.
    pub fn set_condition(&mut self, id: u32, cond: HitCondition) -> bool {
        if let Some(bp) = self.breakpoints.get_mut(&id) {
            bp.condition = cond;
            true
        } else {
            false
        }
    }

    /// Enable or disable a breakpoint.
    pub fn set_enabled(&mut self, id: u32, enabled: bool) -> bool {
        if let Some(bp) = self.breakpoints.get_mut(&id) {
            bp.enabled = enabled;
            true
        } else {
            false
        }
    }

    /// Remove a breakpoint by ID.
    pub fn remove(&mut self, id: u32) -> bool {
        self.breakpoints.remove(&id).is_some()
    }

    /// Return a reference to breakpoint `id`, or `None`.
    #[must_use] 
    pub fn get(&self, id: u32) -> Option<&TtdBreakpoint> {
        self.breakpoints.get(&id)
    }

    /// Return all registered breakpoints (sorted by id).
    #[must_use] 
    pub fn all_breakpoints(&self) -> Vec<&TtdBreakpoint> {
        let mut v: Vec<&TtdBreakpoint> = self.breakpoints.values().collect();
        v.sort_by_key(|bp| bp.id);
        v
    }

    /// Process a single event, updating hit counts and recording any fires.
    pub fn process_event(&mut self, event: &TraceEvent) {
        let bp_ids: Vec<u32> = self.breakpoints.keys().copied().collect();
        for id in bp_ids {
            let bp = match self.breakpoints.get_mut(&id) {
                Some(bp) if bp.enabled => bp,
                _ => continue,
            };
            if !bp.matches_event(event) {
                continue;
            }
            bp.total_hits += 1;
            let fires = bp.condition.allows_fire(
                bp.total_hits,
                TtdPosition::new(event.position.sequence, u32::try_from(event.position.step).unwrap_or(u32::MAX)),
                event.thread_id,
            );
            if fires {
                bp.fired_count += 1;
                self.hits.push(BreakpointHit {
                    bp_id: id,
                    position: TtdPosition::new(event.position.sequence, u32::try_from(event.position.step).unwrap_or(u32::MAX)),
                    thread_id: event.thread_id,
                    hit_number: bp.fired_count,
                });
            }
        }
    }

    /// Process a slice of events in order.
    pub fn process_events(&mut self, events: &[TraceEvent]) {
        for event in events {
            self.process_event(event);
        }
    }

    /// Return all recorded hits, in the order they were fired.
    #[must_use] 
    pub fn hits(&self) -> &[BreakpointHit] {
        &self.hits
    }

    /// Return all hits for a specific breakpoint ID.
    #[must_use] 
    pub fn hits_for_bp(&self, id: u32) -> Vec<&BreakpointHit> {
        self.hits.iter().filter(|h| h.bp_id == id).collect()
    }

    /// Return all hits at a specific TTD position.
    #[must_use] 
    pub fn hits_at_position(&self, pos: TtdPosition) -> Vec<&BreakpointHit> {
        self.hits.iter().filter(|h| h.position == pos).collect()
    }

    /// Return the first hit for breakpoint `id`, or `None`.
    #[must_use] 
    pub fn first_hit(&self, id: u32) -> Option<&BreakpointHit> {
        self.hits.iter().find(|h| h.bp_id == id)
    }

    /// Clear all recorded hits.
    pub fn clear_hits(&mut self) {
        self.hits.clear();
        for bp in self.breakpoints.values_mut() {
            bp.total_hits = 0;
            bp.fired_count = 0;
        }
    }

    /// Remove all breakpoints.
    pub fn clear_breakpoints(&mut self) {
        self.breakpoints.clear();
        self.next_id = 0;
    }

    /// Return a summary: `(bp_id, kind_str, fired_count)` for every breakpoint.
    #[must_use] 
    pub fn summary(&self) -> Vec<(u32, String, u64)> {
        let mut v: Vec<(u32, String, u64)> = self
            .breakpoints
            .values()
            .map(|bp| (bp.id, bp.kind.to_string(), bp.fired_count))
            .collect();
        v.sort_by_key(|(id, _, _)| *id);
        v
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Return `true` if `[a, a+a_len)` overlaps with `[b, b+b_len)`.
const fn ranges_overlap(a: u64, a_len: u64, b: u64, b_len: u64) -> bool {
    a < b + b_len && a + a_len > b
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn call_event(from: u64, to: u64) -> TraceEvent {
        TraceEvent::new(
            crate::TracePosition::new(1, 0),
            1,
            EventKind::Call { from, to },
        )
    }

    fn mem_write_event(addr: u64, data: Vec<u8>) -> TraceEvent {
        TraceEvent::new(
            crate::TracePosition::new(2, 0),
            1,
            EventKind::MemWrite { addr, data },
        )
    }

    fn syscall_enter_event(nr: u32) -> TraceEvent {
        TraceEvent::new(
            crate::TracePosition::new(3, 0),
            1,
            EventKind::SyscallEnter { nr, args: [0; 6] },
        )
    }

    #[test]
    fn test_code_bp_fires_on_call() {
        let mut engine = TtdBreakpointEngine::new();
        let id = engine.add(BreakpointKind::Code { address: 0x0040_1000 });
        engine.process_event(&call_event(0x0040_0ff0, 0x0040_1000));
        assert_eq!(engine.hits_for_bp(id).len(), 1);
    }

    #[test]
    fn test_code_bp_no_fire_wrong_address() {
        let mut engine = TtdBreakpointEngine::new();
        let id = engine.add(BreakpointKind::Code { address: 0x0040_2000 });
        engine.process_event(&call_event(0x0040_0ff0, 0x0040_1000));
        assert!(engine.hits_for_bp(id).is_empty());
    }

    #[test]
    fn test_mem_write_bp_overlapping() {
        let mut engine = TtdBreakpointEngine::new();
        let id = engine.add(BreakpointKind::MemoryWrite { address: 0x1000, size: 8 });
        // Write at 0x1004 for 4 bytes overlaps [0x1000, 0x1008).
        engine.process_event(&mem_write_event(0x1004, vec![1, 2, 3, 4]));
        assert_eq!(engine.hits_for_bp(id).len(), 1);
    }

    #[test]
    fn test_mem_write_bp_non_overlapping() {
        let mut engine = TtdBreakpointEngine::new();
        let id = engine.add(BreakpointKind::MemoryWrite { address: 0x1000, size: 8 });
        engine.process_event(&mem_write_event(0x2000, vec![0; 4]));
        assert!(engine.hits_for_bp(id).is_empty());
    }

    #[test]
    fn test_syscall_bp() {
        let mut engine = TtdBreakpointEngine::new();
        let id = engine.add(BreakpointKind::Syscall { nr: 60 });
        engine.process_event(&syscall_enter_event(60));
        engine.process_event(&syscall_enter_event(1));
        assert_eq!(engine.hits_for_bp(id).len(), 1);
    }

    #[test]
    fn test_hit_condition_nth_hit() {
        let mut engine = TtdBreakpointEngine::new();
        let id = engine.add(BreakpointKind::CallTo { callee: 0x5000 });
        engine.set_condition(id, HitCondition::NthHit(3));
        for _ in 0..5 {
            engine.process_event(&call_event(0x1000, 0x5000));
        }
        assert_eq!(engine.hits_for_bp(id).len(), 1);
        assert_eq!(engine.hits_for_bp(id)[0].hit_number, 1);
    }

    #[test]
    fn test_disabled_bp_does_not_fire() {
        let mut engine = TtdBreakpointEngine::new();
        let id = engine.add(BreakpointKind::Code { address: 0x0040_1000 });
        engine.set_enabled(id, false);
        engine.process_event(&call_event(0x0040_0ff0, 0x0040_1000));
        assert!(engine.hits_for_bp(id).is_empty());
    }

    #[test]
    fn test_remove_bp() {
        let mut engine = TtdBreakpointEngine::new();
        let id = engine.add(BreakpointKind::Code { address: 0x0040_1000 });
        assert!(engine.remove(id));
        assert!(engine.get(id).is_none());
    }

    #[test]
    fn test_clear_hits_resets_counts() {
        let mut engine = TtdBreakpointEngine::new();
        let id = engine.add(BreakpointKind::Code { address: 0x0040_1000 });
        engine.process_event(&call_event(0, 0x0040_1000));
        engine.clear_hits();
        assert!(engine.hits().is_empty());
        assert_eq!(engine.get(id).unwrap().total_hits, 0);
    }
}
