//! `ttd_breakpoint_manager` — Breakpoint management for TTD replay sessions.
//!
//! Provides [`TtdBreakpointManager`] which manages a collection of
//! [`TtdBreakpoint`] objects, evaluates them against the current replay
//! position, and records hit history.

use std::collections::HashMap;

use rustre_ttd::TracePosition;
use serde::{Deserialize, Serialize};

use crate::{BreakpointCondition, MemoryState};

/// Context passed to breakpoint evaluation, grouping the state inputs.
pub struct BreakpointEvalContext<'a> {
    pub pc: u64,
    pub position: TracePosition,
    pub registers: &'a HashMap<String, u64>,
    pub memory: &'a MemoryState,
    pub event_kind: Option<&'a str>,
    pub module_name: Option<&'a str>,
    pub thread_id: Option<u32>,
}

// ─────────────────────────────────────────────────────────────────────────────
// BreakpointKind
// ─────────────────────────────────────────────────────────────────────────────

/// Distinguishes the type of event a breakpoint is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BreakpointKind {
    /// Fires when the instruction pointer reaches a specific address.
    Code { address: u64 },
    /// Fires when an event of a given kind occurs at an address.
    Event { address: u64, event_kind: String },
    /// Fires at a given trace position (sequence:step).
    Position { position: TracePosition },
    /// Fires when a named module is loaded.
    ModuleLoad { module_name: String },
    /// Fires when a thread with the given ID is created.
    ThreadCreate { thread_id: u32 },
}

impl std::fmt::Display for BreakpointKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Code { address } => write!(f, "Code({address:#x})"),
            Self::Event { address, event_kind } => {
                write!(f, "Event({event_kind} @ {address:#x})")
            }
            Self::Position { position } => write!(f, "Position({position})"),
            Self::ModuleLoad { module_name } => write!(f, "ModuleLoad({module_name})"),
            Self::ThreadCreate { thread_id } => write!(f, "ThreadCreate(tid={thread_id})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TtdBreakpoint
// ─────────────────────────────────────────────────────────────────────────────

/// A single breakpoint registered in the TTD replay manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtdBreakpoint {
    /// Unique identifier assigned by the manager.
    pub id: u32,
    /// What triggers this breakpoint.
    pub kind: BreakpointKind,
    /// Optional condition for conditional breakpoints.
    pub condition: Option<BreakpointCondition>,
    /// Whether the breakpoint is currently active.
    pub enabled: bool,
    /// Number of times this breakpoint has fired.
    pub hit_count: u64,
    /// Optional user label for this breakpoint.
    pub label: Option<String>,
    /// Optional one-shot mode — disables itself after the first hit.
    pub one_shot: bool,
    /// History of positions at which this BP fired.
    pub hit_positions: Vec<TracePosition>,
}

impl TtdBreakpoint {
    #[must_use]
    pub const fn new(id: u32, kind: BreakpointKind) -> Self {
        Self {
            id,
            kind,
            condition: None,
            enabled: true,
            hit_count: 0,
            label: None,
            one_shot: false,
            hit_positions: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_condition(mut self, cond: BreakpointCondition) -> Self {
        self.condition = Some(cond);
        self
    }

    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    #[must_use]
    pub const fn one_shot(mut self) -> Self {
        self.one_shot = true;
        self
    }

    /// Return the address if this breakpoint is a `Code` or `Event` breakpoint.
    #[must_use]
    pub const fn address(&self) -> Option<u64> {
        match &self.kind {
            BreakpointKind::Code { address } | BreakpointKind::Event { address, .. } => Some(*address),
            _ => None,
        }
    }

    /// Check whether this breakpoint fires given the current state.
    ///
    /// `pc` — current instruction pointer.
    /// `position` — current trace position.
    /// `registers` — current register values.
    /// `memory` — current memory state.
    /// `event_kind` — optional event kind string (for Event BPs).
    /// `module_name` — optional just-loaded module name.
    /// `thread_id` — optional newly created thread id.
    #[must_use]
    pub fn hit_at_position(
        &self,
        ctx: &BreakpointEvalContext<'_>,
    ) -> bool {
        if !self.enabled {
            return false;
        }

        // Check the kind-specific trigger condition
        let kind_fires = match &self.kind {
            BreakpointKind::Code { address } => ctx.pc == *address,
            BreakpointKind::Event { address, event_kind: ek } => {
                ctx.pc == *address && ctx.event_kind.is_some_and(|ev| ev == ek)
            }
            BreakpointKind::Position { position: target } => ctx.position == *target,
            BreakpointKind::ModuleLoad { module_name: m } => {
                ctx.module_name.is_some_and(|n| n == m)
            }
            BreakpointKind::ThreadCreate { thread_id: tid } => {
                ctx.thread_id == Some(*tid)
            }
        };

        if !kind_fires {
            return false;
        }

        // Evaluate any attached condition
        match &self.condition {
            None | Some(BreakpointCondition::Always) => true,
            Some(BreakpointCondition::RegisterEquals { reg, value }) => {
                ctx.registers.get(reg).copied() == Some(*value)
            }
            Some(BreakpointCondition::MemoryEquals { addr, value }) => {
                ctx.memory.read(*addr, value.len()).as_deref() == Some(value.as_slice())
            }
            Some(BreakpointCondition::HitCountMultiple(n)) => {
                *n > 0 && (self.hit_count + 1).is_multiple_of(*n)
            }
        }
    }
}

impl std::fmt::Display for TtdBreakpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = self.label.as_deref().unwrap_or("-");
        write!(
            f,
            "BP#{} [{}] enabled={} hits={} label={}",
            self.id, self.kind, self.enabled, self.hit_count, label
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BreakpointHit
// ─────────────────────────────────────────────────────────────────────────────

/// Record of a breakpoint firing at a specific position.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointHit {
    pub bp_id: u32,
    pub position: TracePosition,
    pub pc: u64,
    pub hit_number: u64,
}

impl std::fmt::Display for BreakpointHit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Hit BP#{} @ pos={} pc={:#x} (hit #{})",
            self.bp_id, self.position, self.pc, self.hit_number
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TtdBreakpointManager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages a set of [`TtdBreakpoint`] objects for a TTD replay session.
pub struct TtdBreakpointManager {
    breakpoints: Vec<TtdBreakpoint>,
    next_id: u32,
    /// Global hit log across all breakpoints.
    hit_log: Vec<BreakpointHit>,
}

impl TtdBreakpointManager {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            breakpoints: Vec::new(),
            next_id: 1,
            hit_log: Vec::new(),
        }
    }

    /// Add a code breakpoint at `address`.  Returns the assigned ID.
    pub fn add_code_bp(&mut self, address: u64) -> u32 {
        self.add(TtdBreakpoint::new(
            self.next_id,
            BreakpointKind::Code { address },
        ))
    }

    /// Add a code breakpoint with a condition.  Returns the assigned ID.
    pub fn add_conditional_code_bp(&mut self, address: u64, cond: BreakpointCondition) -> u32 {
        self.add(
            TtdBreakpoint::new(self.next_id, BreakpointKind::Code { address })
                .with_condition(cond),
        )
    }

    /// Add a position breakpoint.  Returns the assigned ID.
    pub fn add_position_bp(&mut self, position: TracePosition) -> u32 {
        self.add(TtdBreakpoint::new(
            self.next_id,
            BreakpointKind::Position { position },
        ))
    }

    /// Add a module-load breakpoint.  Returns the assigned ID.
    pub fn add_module_load_bp(&mut self, module_name: impl Into<String>) -> u32 {
        self.add(TtdBreakpoint::new(
            self.next_id,
            BreakpointKind::ModuleLoad { module_name: module_name.into() },
        ))
    }

    /// Add a thread-create breakpoint.  Returns the assigned ID.
    pub fn add_thread_create_bp(&mut self, thread_id: u32) -> u32 {
        self.add(TtdBreakpoint::new(
            self.next_id,
            BreakpointKind::ThreadCreate { thread_id },
        ))
    }

    /// Register a fully-constructed breakpoint.  Returns the assigned ID.
    pub fn add(&mut self, mut bp: TtdBreakpoint) -> u32 {
        let id = self.next_id;
        bp.id = id;
        self.next_id += 1;
        self.breakpoints.push(bp);
        id
    }

    /// Remove the breakpoint with the given ID.  Returns `true` if found.
    pub fn remove(&mut self, bp_id: u32) -> bool {
        let before = self.breakpoints.len();
        self.breakpoints.retain(|bp| bp.id != bp_id);
        self.breakpoints.len() < before
    }

    pub fn enable(&mut self, bp_id: u32) -> bool {
        if let Some(bp) = self.breakpoints.iter_mut().find(|b| b.id == bp_id) {
            bp.enabled = true;
            return true;
        }
        false
    }

    pub fn disable(&mut self, bp_id: u32) -> bool {
        if let Some(bp) = self.breakpoints.iter_mut().find(|b| b.id == bp_id) {
            bp.enabled = false;
            return true;
        }
        false
    }

    /// Evaluate all breakpoints against the current state.  Returns IDs of
    /// all breakpoints that fired.
    pub fn evaluate(
        &mut self,
        ctx: &BreakpointEvalContext<'_>,
    ) -> Vec<u32> {
        let mut fired = Vec::new();
        for bp in &mut self.breakpoints {
            if bp.hit_at_position(ctx) {
                bp.hit_count += 1;
                bp.hit_positions.push(ctx.position);
                fired.push(bp.id);
                self.hit_log.push(BreakpointHit {
                    bp_id: bp.id,
                    position: ctx.position,
                    pc: ctx.pc,
                    hit_number: bp.hit_count,
                });
                if bp.one_shot {
                    bp.enabled = false;
                }
            }
        }
        fired
    }

    // ── query methods ─────────────────────────────────────────────────────────

    #[must_use]
    pub const fn count(&self) -> usize {
        self.breakpoints.len()
    }

    #[must_use]
    pub fn enabled_count(&self) -> usize {
        self.breakpoints.iter().filter(|b| b.enabled).count()
    }

    #[must_use]
    pub fn find(&self, bp_id: u32) -> Option<&TtdBreakpoint> {
        self.breakpoints.iter().find(|b| b.id == bp_id)
    }

    #[must_use]
    pub fn all(&self) -> &[TtdBreakpoint] {
        &self.breakpoints
    }

    #[must_use]
    pub fn by_address(&self, address: u64) -> Vec<&TtdBreakpoint> {
        self.breakpoints
            .iter()
            .filter(|b| b.address() == Some(address))
            .collect()
    }

    #[must_use]
    pub fn hit_log(&self) -> &[BreakpointHit] {
        &self.hit_log
    }

    #[must_use]
    pub fn total_hits(&self) -> u64 {
        self.breakpoints.iter().map(|b| b.hit_count).sum()
    }

    pub fn clear_hit_log(&mut self) {
        self.hit_log.clear();
    }

    pub fn clear_all(&mut self) {
        self.breakpoints.clear();
        self.hit_log.clear();
    }
}

impl Default for TtdBreakpointManager {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn mgr() -> TtdBreakpointManager {
        TtdBreakpointManager::new()
    }

    fn pos() -> TracePosition {
        TracePosition::default()
    }

    fn regs() -> HashMap<String, u64> {
        HashMap::new()
    }

    fn mem() -> MemoryState {
        MemoryState::new()
    }

    #[test]
    fn test_add_code_bp() {
        let mut m = mgr();
        let id = m.add_code_bp(0x1000);
        assert_eq!(m.count(), 1);
        assert!(m.find(id).is_some());
    }

    #[test]
    fn test_remove_bp() {
        let mut m = mgr();
        let id = m.add_code_bp(0x2000);
        assert!(m.remove(id));
        assert_eq!(m.count(), 0);
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut m = mgr();
        assert!(!m.remove(999));
    }

    #[test]
    fn test_enable_disable() {
        let mut m = mgr();
        let id = m.add_code_bp(0x3000);
        assert!(m.disable(id));
        assert!(!m.find(id).unwrap().enabled);
        assert!(m.enable(id));
        assert!(m.find(id).unwrap().enabled);
    }

    #[test]
    fn test_evaluate_code_bp_fires() {
        let mut m = mgr();
        m.add_code_bp(0x400);
        let fired = m.evaluate(&BreakpointEvalContext { pc: 0x400, position: pos(), registers: &regs(), memory: &mem(), event_kind: None, module_name: None, thread_id: None });
        assert_eq!(fired.len(), 1);
    }

    #[test]
    fn test_evaluate_code_bp_no_match() {
        let mut m = mgr();
        m.add_code_bp(0x400);
        let fired = m.evaluate(&BreakpointEvalContext { pc: 0x800, position: pos(), registers: &regs(), memory: &mem(), event_kind: None, module_name: None, thread_id: None });
        assert!(fired.is_empty());
    }

    #[test]
    fn test_hit_count_increments() {
        let mut m = mgr();
        let id = m.add_code_bp(0x100);
        m.evaluate(&BreakpointEvalContext { pc: 0x100, position: pos(), registers: &regs(), memory: &mem(), event_kind: None, module_name: None, thread_id: None });
        m.evaluate(&BreakpointEvalContext { pc: 0x100, position: pos(), registers: &regs(), memory: &mem(), event_kind: None, module_name: None, thread_id: None });
        assert_eq!(m.find(id).unwrap().hit_count, 2);
    }

    #[test]
    fn test_hit_log() {
        let mut m = mgr();
        m.add_code_bp(0x100);
        m.evaluate(&BreakpointEvalContext { pc: 0x100, position: pos(), registers: &regs(), memory: &mem(), event_kind: None, module_name: None, thread_id: None });
        assert_eq!(m.hit_log().len(), 1);
    }

    #[test]
    fn test_total_hits() {
        let mut m = mgr();
        m.add_code_bp(0x100);
        m.add_code_bp(0x200);
        m.evaluate(&BreakpointEvalContext { pc: 0x100, position: pos(), registers: &regs(), memory: &mem(), event_kind: None, module_name: None, thread_id: None });
        m.evaluate(&BreakpointEvalContext { pc: 0x200, position: pos(), registers: &regs(), memory: &mem(), event_kind: None, module_name: None, thread_id: None });
        assert_eq!(m.total_hits(), 2);
    }

    #[test]
    fn test_one_shot_disables_after_hit() {
        let mut m = mgr();
        let bp = TtdBreakpoint::new(1, BreakpointKind::Code { address: 0x100 }).one_shot();
        m.add(bp);
        m.evaluate(&BreakpointEvalContext { pc: 0x100, position: pos(), registers: &regs(), memory: &mem(), event_kind: None, module_name: None, thread_id: None });
        let fired2 = m.evaluate(&BreakpointEvalContext { pc: 0x100, position: pos(), registers: &regs(), memory: &mem(), event_kind: None, module_name: None, thread_id: None });
        assert!(fired2.is_empty());
    }

    #[test]
    fn test_conditional_register_bp() {
        let mut m = mgr();
        let cond = BreakpointCondition::RegisterEquals {
            reg: "rax".into(),
            value: 42,
        };
        m.add_conditional_code_bp(0x100, cond);
        let mut r = regs();
        r.insert("rax".into(), 42);
        let fired = m.evaluate(&BreakpointEvalContext { pc: 0x100, position: pos(), registers: &r, memory: &mem(), event_kind: None, module_name: None, thread_id: None });
        assert_eq!(fired.len(), 1);
    }

    #[test]
    fn test_conditional_register_bp_no_match() {
        let mut m = mgr();
        let cond = BreakpointCondition::RegisterEquals {
            reg: "rax".into(),
            value: 42,
        };
        m.add_conditional_code_bp(0x100, cond);
        let mut r = regs();
        r.insert("rax".into(), 0);
        let fired = m.evaluate(&BreakpointEvalContext { pc: 0x100, position: pos(), registers: &r, memory: &mem(), event_kind: None, module_name: None, thread_id: None });
        assert!(fired.is_empty());
    }

    #[test]
    fn test_position_bp() {
        let mut m = mgr();
        let target = pos();
        m.add_position_bp(target);
        let fired = m.evaluate(&BreakpointEvalContext { pc: 0, position: target, registers: &regs(), memory: &mem(), event_kind: None, module_name: None, thread_id: None });
        assert_eq!(fired.len(), 1);
    }

    #[test]
    fn test_module_load_bp() {
        let mut m = mgr();
        m.add_module_load_bp("ntdll.dll");
        let fired = m.evaluate(&BreakpointEvalContext { pc: 0, position: pos(), registers: &regs(), memory: &mem(), event_kind: None, module_name: Some("ntdll.dll"), thread_id: None });
        assert_eq!(fired.len(), 1);
    }

    #[test]
    fn test_thread_create_bp() {
        let mut m = mgr();
        m.add_thread_create_bp(4);
        let fired = m.evaluate(&BreakpointEvalContext { pc: 0, position: pos(), registers: &regs(), memory: &mem(), event_kind: None, module_name: None, thread_id: Some(4) });
        assert_eq!(fired.len(), 1);
    }

    #[test]
    fn test_by_address() {
        let mut m = mgr();
        m.add_code_bp(0xabc);
        m.add_code_bp(0xabc);
        m.add_code_bp(0x111);
        let matching = m.by_address(0xabc);
        assert_eq!(matching.len(), 2);
    }

    #[test]
    fn test_enabled_count() {
        let mut m = mgr();
        let id1 = m.add_code_bp(0x1);
        m.add_code_bp(0x2);
        m.disable(id1);
        assert_eq!(m.enabled_count(), 1);
    }

    #[test]
    fn test_clear_all() {
        let mut m = mgr();
        m.add_code_bp(0x1);
        m.evaluate(&BreakpointEvalContext { pc: 0x1, position: pos(), registers: &regs(), memory: &mem(), event_kind: None, module_name: None, thread_id: None });
        m.clear_all();
        assert_eq!(m.count(), 0);
        assert!(m.hit_log().is_empty());
    }

    #[test]
    fn test_clear_hit_log() {
        let mut m = mgr();
        m.add_code_bp(0x1);
        m.evaluate(&BreakpointEvalContext { pc: 0x1, position: pos(), registers: &regs(), memory: &mem(), event_kind: None, module_name: None, thread_id: None });
        m.clear_hit_log();
        assert!(m.hit_log().is_empty());
    }

    #[test]
    fn test_breakpoint_display() {
        let bp = TtdBreakpoint::new(1, BreakpointKind::Code { address: 0x1234 })
            .with_label("entry");
        let s = bp.to_string();
        assert!(s.contains("BP#1"));
        assert!(s.contains("entry"));
    }

    #[test]
    fn test_breakpoint_kind_display() {
        let k = BreakpointKind::Code { address: 0x4000 };
        assert!(k.to_string().contains("0x4000"));
    }

    #[test]
    fn test_hit_display() {
        let h = BreakpointHit {
            bp_id: 7,
            position: pos(),
            pc: 0x1234,
            hit_number: 3,
        };
        let s = h.to_string();
        assert!(s.contains("BP#7"));
        assert!(s.contains("hit #3"));
    }
}
