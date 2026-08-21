//! Multi-target debugger for `rustre-debug`.
//!
//! Allows a single session to control multiple debug targets simultaneously,
//! broadcast commands, correlate events across targets, and produce unified
//! reports.

use std::collections::{HashMap, VecDeque};
use std::fmt;
/// Re-exports of [`std::sync::Arc`] and [`std::sync::Mutex`] so external
/// orchestrators can build shared multi-target debugger handles without
/// importing `std::sync` directly.
pub use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Target identification
// ─────────────────────────────────────────────────────────────────────────────

/// Unique identifier for a debug target within a multi-target session.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TargetId(pub u32);

impl fmt::Display for TargetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "target#{}", self.0)
    }
}

/// Describes how to connect to or launch a single debug target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TargetSpec {
    /// An already-running local process.
    LocalPid(u32),
    /// A remote GDB/RSP server.
    GdbServer { host: String, port: u16 },
    /// A local binary to launch.
    Executable { path: String, args: Vec<String> },
    /// A kernel debugging endpoint.
    KernelGdb { device: String },
}

/// Runtime state of a target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetState {
    /// Not yet attached.
    Disconnected,
    /// Attached and running.
    Running,
    /// Stopped at a breakpoint or signal.
    Stopped { reason: String },
    /// The target process exited.
    Exited { code: i32 },
    /// The target encountered an error.
    Error { message: String },
}

impl TargetState {
    /// The variant's own name, with no payload: `disconnected`, `running`,
    /// `stopped`, `exited`, `error`.
    ///
    /// Selecting targets by state used to be done with
    /// `format!("{:?}", state).contains(name)`, which matches the PAYLOAD as
    /// well as the variant. `Stopped { reason }` renders the reason string —
    /// text that comes from the target — so a target stopped with the reason
    /// "error while reading memory" answered to a selection for the `Error`
    /// state, and one stopped "waiting for running thread" answered to
    /// `Running`. An empty name matched everything, turning a filter into a
    /// silent broadcast. In a multi-target session the command then reaches
    /// processes the caller did not select, and the results look exactly like
    /// a correct run.
    #[must_use]
    pub const fn variant_name(&self) -> &'static str {
        match self {
            Self::Disconnected => "disconnected",
            Self::Running => "running",
            Self::Stopped { .. } => "stopped",
            Self::Exited { .. } => "exited",
            Self::Error { .. } => "error",
        }
    }

    /// Whether `name` names this variant, ignoring case and any payload.
    #[must_use]
    pub fn is_named(&self, name: &str) -> bool {
        self.variant_name().eq_ignore_ascii_case(name.trim())
    }

    /// Every state name this crate accepts, for validating a caller's input.
    pub const ALL_NAMES: &'static [&'static str] =
        &["disconnected", "running", "stopped", "exited", "error"];
}

/// A single registered debug target.
#[derive(Debug)]
pub struct DebugTarget {
    pub id: TargetId,
    pub spec: TargetSpec,
    pub state: TargetState,
    pub name: String,
}

impl DebugTarget {
    pub fn new(id: u32, spec: TargetSpec, name: impl Into<String>) -> Self {
        Self {
            id: TargetId(id),
            spec,
            state: TargetState::Disconnected,
            name: name.into(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DebugTargetList
// ─────────────────────────────────────────────────────────────────────────────

/// A collection of registered debug targets.
#[derive(Debug, Default)]
pub struct DebugTargetList {
    targets: HashMap<TargetId, DebugTarget>,
    next_id: u32,
}

impl DebugTargetList {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new target and return its assigned id.
    pub fn add(&mut self, spec: TargetSpec, name: impl Into<String>) -> TargetId {
        let id = TargetId(self.next_id);
        self.next_id += 1;
        self.targets
            .insert(id.clone(), DebugTarget::new(id.0, spec, name));
        id
    }

    /// Remove a target by id.
    pub fn remove(&mut self, id: &TargetId) -> Option<DebugTarget> {
        self.targets.remove(id)
    }

    /// Get a reference to a target.
    #[must_use]
    pub fn get(&self, id: &TargetId) -> Option<&DebugTarget> {
        self.targets.get(id)
    }

    /// Get a mutable reference.
    pub fn get_mut(&mut self, id: &TargetId) -> Option<&mut DebugTarget> {
        self.targets.get_mut(id)
    }

    /// Return all target ids.
    #[must_use]
    pub fn ids(&self) -> Vec<TargetId> {
        self.targets.keys().cloned().collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.targets.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    /// Return all targets whose state is NAMED `name`, ignoring any payload.
    ///
    /// `None` when `name` is not a state name at all. That distinction is the
    /// point: "no target is stopped" and "there is no such state as `stoped`"
    /// are different answers, and returning an empty list for both lets a typo
    /// read as a fact about the targets.
    ///
    /// Use this rather than [`Self::in_state`] when the caller supplied a
    /// string. `in_state` compares whole values, so asking it for "everything
    /// stopped" requires already knowing the exact reason text.
    #[must_use]
    pub fn in_state_named(&self, name: &str) -> Option<Vec<&DebugTarget>> {
        let wanted = name.trim();
        if !TargetState::ALL_NAMES
            .iter()
            .any(|n| n.eq_ignore_ascii_case(wanted))
        {
            return None;
        }
        Some(
            self.targets
                .values()
                .filter(|t| t.state.is_named(wanted))
                .collect(),
        )
    }

    /// Return all targets in a given state, compared as WHOLE values.
    ///
    /// Payload included: `Stopped { reason: "sigsegv" }` and
    /// `Stopped { reason: "breakpoint" }` are different states here. When the
    /// caller means "any stopped target", that is [`Self::in_state_named`].
    #[must_use]
    pub fn in_state(&self, state: &TargetState) -> Vec<&DebugTarget> {
        self.targets
            .values()
            .filter(|t| &t.state == state)
            .collect()
    }

    /// Set the state of a target.
    pub fn set_state(&mut self, id: &TargetId, state: TargetState) -> bool {
        if let Some(t) = self.targets.get_mut(id) {
            t.state = state;
            true
        } else {
            false
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SessionRouter — route commands to the right target
// ─────────────────────────────────────────────────────────────────────────────

/// Routes a debug command to a specific target or all targets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommandRoute {
    /// Send only to this target.
    Single(TargetId),
    /// Send to all connected targets.
    Broadcast,
    /// Send to all targets in the given state.
    ByState(String),
}

/// A debug command that can be routed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutedCommand {
    pub route: CommandRoute,
    pub command: DebugCommand,
}

/// A debugger command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DebugCommand {
    Continue,
    StepInto,
    StepOver,
    Break,
    SetBreakpoint { address: u64 },
    RemoveBreakpoint { address: u64 },
    ReadMemory { address: u64, size: usize },
    WriteMemory { address: u64, data: Vec<u8> },
    GetRegisters,
    Evaluate { expression: String },
    Detach,
}

/// The result of executing a command on one target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub target_id: TargetId,
    pub command: DebugCommand,
    pub success: bool,
    pub output: String,
    pub data: Vec<u8>,
}

/// Routes commands to targets and collects results.
#[derive(Default)]
pub struct SessionRouter {
    /// Simulated command queue per target.
    queues: HashMap<TargetId, VecDeque<RoutedCommand>>,
}

impl SessionRouter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enqueue a routed command, returning how many targets it was addressed
    /// to.
    ///
    /// The count is the only way a caller can tell a route that reached nobody
    /// — an unknown state name, an id that is not registered — from one that
    /// reached everybody it should. It used to return nothing at all.
    pub fn enqueue(&mut self, cmd: RoutedCommand, targets: &DebugTargetList) -> usize {
        match &cmd.route {
            CommandRoute::Single(id) => {
                // An id nobody registered still gets a queue, and the command
                // sits in it forever; counting it as zero addressed is what
                // says so.
                let known = targets.get(id).is_some();
                self.queues.entry(id.clone()).or_default().push_back(cmd);
                usize::from(known)
            }
            CommandRoute::Broadcast => {
                let ids = targets.ids();
                for id in &ids {
                    self.queues.entry(id.clone()).or_default().push_back(cmd.clone());
                }
                ids.len()
            }
            CommandRoute::ByState(state_name) => {
                // Match the state's NAME, never its Debug rendering: the
                // payload of `Stopped { reason }` is text from the target, and
                // matching it routed commands to processes the caller never
                // selected. An unrecognised name addresses nobody, and the
                // returned 0 is what tells the caller that.
                let matching: Vec<TargetId> = targets
                    .in_state_named(state_name)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|t| t.id.clone())
                    .collect();
                for id in &matching {
                    self.queues.entry(id.clone()).or_default().push_back(cmd.clone());
                }
                matching.len()
            }
        }
    }

    /// Dequeue the next command for `target` and report the outcome of trying
    /// to run it.
    ///
    /// # This router has no live transport
    ///
    /// [`SessionRouter`] is the *routing* half of the multi-target design: it
    /// decides which targets a command is addressed to and keeps the per-target
    /// queues. Actually running a command needs a live connection to the
    /// target, and no [`TargetSpec`] in this build is backed by one.
    ///
    /// It used to answer `success: true, output: "ok"` here regardless. That is
    /// the worst possible shape for the failure: `debug.multi_target_broadcast`
    /// serialises this straight to `{"ok": true}`, so "I detached every target"
    /// and "I did nothing at all" were the same JSON.
    ///
    /// The command is still dequeued — the queue accounting is real, and
    /// [`Self::pending`] must drop — but the result says it was not executed
    /// and names why.
    pub fn execute_next(&mut self, target: &TargetId) -> Option<CommandResult> {
        let cmd = self.queues.get_mut(target)?.pop_front()?;
        Some(CommandResult {
            target_id: target.clone(),
            command: cmd.command,
            success: false,
            output: format!(
                "not executed: SessionRouter dequeued and routed this command to \
                 target {} but has no live transport to run it on; attach a real \
                 backend (debug.attach / debug.launch) and drive it through the \
                 debug.* session tools instead",
                target.0
            ),
            data: vec![],
        })
    }

    /// Count pending commands for a target.
    #[must_use]
    pub fn pending(&self, target: &TargetId) -> usize {
        self.queues
            .get(target)
            .map_or(0, std::collections::VecDeque::len)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CommandBroadcaster
// ─────────────────────────────────────────────────────────────────────────────

/// Broadcasts a command to every connected target and collects all results.
pub struct CommandBroadcaster {
    pub router: SessionRouter,
}

impl Default for CommandBroadcaster {
    fn default() -> Self {
        Self {
            router: SessionRouter::new(),
        }
    }
}

impl CommandBroadcaster {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Send the same command to all targets and return all results.
    pub fn broadcast(
        &mut self,
        cmd: DebugCommand,
        targets: &DebugTargetList,
    ) -> Vec<CommandResult> {
        let routed = RoutedCommand {
            route: CommandRoute::Broadcast,
            command: cmd,
        };
        self.router.enqueue(routed, targets);
        let mut results = Vec::with_capacity(targets.len());
        for id in targets.ids() {
            while let Some(r) = self.router.execute_next(&id) {
                results.push(r);
            }
        }
        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SyncBreakpoint — a breakpoint that must be hit by all targets
// ─────────────────────────────────────────────────────────────────────────────

/// A synchronised breakpoint that is only considered "hit" once all registered
/// targets have reached it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncBreakpoint {
    pub address: u64,
    pub expected_targets: Vec<TargetId>,
    pub hit_by: Vec<TargetId>,
}

impl SyncBreakpoint {
    #[must_use]
    pub const fn new(address: u64, targets: Vec<TargetId>) -> Self {
        Self {
            address,
            expected_targets: targets,
            hit_by: Vec::new(),
        }
    }

    /// Record that `target` hit this breakpoint.
    pub fn record_hit(&mut self, target: TargetId) {
        if !self.hit_by.contains(&target) {
            self.hit_by.push(target);
        }
    }

    /// True when all expected targets have hit this breakpoint.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.expected_targets
            .iter()
            .all(|t| self.hit_by.contains(t))
    }

    /// Remaining targets that have not yet hit this breakpoint.
    #[must_use]
    pub fn pending_targets(&self) -> Vec<&TargetId> {
        self.expected_targets
            .iter()
            .filter(|t| !self.hit_by.contains(t))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CorrelatedTrace — a trace entry spanning multiple targets
// ─────────────────────────────────────────────────────────────────────────────

/// A correlated trace record from a multi-target execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedTrace {
    /// Wall-clock timestamp (milliseconds since session start).
    pub timestamp_ms: u64,
    /// Per-target program-counter values at the recorded moment.
    pub pcs: HashMap<String, u64>, // TargetId.0.to_string() → pc
    /// Optional annotation.
    pub annotation: Option<String>,
}

impl CorrelatedTrace {
    #[must_use]
    pub fn new(timestamp_ms: u64) -> Self {
        Self {
            timestamp_ms,
            pcs: HashMap::new(),
            annotation: None,
        }
    }

    pub fn add_pc(&mut self, target: &TargetId, pc: u64) {
        self.pcs.insert(target.0.to_string(), pc);
    }

    /// True if all given targets have a PC recorded.
    #[must_use]
    pub fn is_complete(&self, targets: &[TargetId]) -> bool {
        targets
            .iter()
            .all(|t| self.pcs.contains_key(&t.0.to_string()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MultiTargetReport
// ─────────────────────────────────────────────────────────────────────────────

/// Summary report produced at the end of a multi-target session.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MultiTargetReport {
    /// Number of targets that were registered.
    pub total_targets: usize,
    /// Number of targets that exited cleanly.
    pub clean_exits: usize,
    /// Number of targets that encountered errors.
    pub errors: usize,
    /// Number of sync breakpoints that were fully satisfied.
    pub sync_bps_completed: usize,
    /// Correlated trace entries collected during the session.
    pub trace_entries: Vec<CorrelatedTrace>,
    /// Arbitrary notes / observations.
    pub notes: Vec<String>,
}

impl MultiTargetReport {
    pub fn add_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }

    /// True if all targets exited cleanly and no errors occurred.
    #[must_use]
    pub const fn all_ok(&self) -> bool {
        self.errors == 0 && self.clean_exits == self.total_targets
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MultiTargetDebugger — top-level façade
// ─────────────────────────────────────────────────────────────────────────────

/// Manages multiple debug targets in parallel.
pub struct MultiTargetDebugger {
    pub targets: DebugTargetList,
    pub broadcaster: CommandBroadcaster,
    pub sync_breakpoints: Vec<SyncBreakpoint>,
    pub trace: Vec<CorrelatedTrace>,
    pub report: MultiTargetReport,
    /// Monotonic timer (simulated).
    clock_ms: u64,
}

impl MultiTargetDebugger {
    #[must_use]
    pub fn new() -> Self {
        Self {
            targets: DebugTargetList::new(),
            broadcaster: CommandBroadcaster::new(),
            sync_breakpoints: Vec::new(),
            trace: Vec::new(),
            report: MultiTargetReport::default(),
            clock_ms: 0,
        }
    }

    /// Register a new target.
    pub fn add_target(&mut self, spec: TargetSpec, name: impl Into<String>) -> TargetId {
        let id = self.targets.add(spec, name);
        self.report.total_targets += 1;
        id
    }

    /// Attempt to connect every registered target.
    ///
    /// # Errors
    ///
    /// Always fails, per target, in this build: there is no live transport
    /// behind [`TargetSpec`]. Each target is left in
    /// [`TargetState::Error`] naming that, and the returned `Err` lists the
    /// target ids that could not be connected.
    ///
    /// It used to set every target to [`TargetState::Running`] and return
    /// nothing, so `debug.multi_target_list` reported a fleet of running
    /// processes that were never contacted.
    pub fn connect_all(&mut self) -> Result<(), Vec<TargetId>> {
        let ids = self.targets.ids();
        if ids.is_empty() {
            return Ok(());
        }
        for id in &ids {
            let spec = self.targets.get(id).map(|t| format!("{:?}", t.spec));
            self.targets.set_state(
                id,
                TargetState::Error {
                    message: format!(
                        "no live transport: MultiTargetDebugger routes and \
                         correlates targets but does not implement attach for \
                         {}; use debug.attach / debug.launch for a live session",
                        spec.as_deref().unwrap_or("<unknown spec>")
                    ),
                },
            );
            self.report.errors += 1;
        }
        Err(ids)
    }

    /// Add a sync breakpoint at the given address for all current targets.
    pub fn add_sync_breakpoint(&mut self, address: u64) {
        let ids = self.targets.ids();
        self.sync_breakpoints
            .push(SyncBreakpoint::new(address, ids));
    }

    /// Simulate all targets hitting a sync breakpoint at `address`.
    pub fn trigger_sync_breakpoint(&mut self, address: u64) {
        let ids = self.targets.ids();
        for bp in &mut self.sync_breakpoints {
            if bp.address == address {
                for id in &ids {
                    bp.record_hit(id.clone());
                }
                if bp.is_complete() {
                    self.report.sync_bps_completed += 1;
                }
            }
        }
    }

    /// Record a correlated trace entry with the given PCs.
    pub fn record_trace(&mut self, pcs: Vec<(TargetId, u64)>) {
        self.clock_ms += 10;
        let mut entry = CorrelatedTrace::new(self.clock_ms);
        for (id, pc) in pcs {
            entry.add_pc(&id, pc);
        }
        self.trace.push(entry);
    }

    /// Broadcast a command to all targets.
    pub fn broadcast_command(&mut self, cmd: DebugCommand) -> Vec<CommandResult> {
        self.broadcaster.broadcast(cmd, &self.targets)
    }

    /// Mark a target as exited with the given exit code.
    pub fn target_exited(&mut self, id: &TargetId, code: i32) {
        self.targets.set_state(id, TargetState::Exited { code });
        if code == 0 {
            self.report.clean_exits += 1;
        } else {
            self.report.errors += 1;
        }
    }

    /// Finalise the report.
    pub fn finalise(&mut self) -> &MultiTargetReport {
        self.report.trace_entries = self.trace.clone();
        &self.report
    }
}

impl Default for MultiTargetDebugger {
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

    fn make_two_targets() -> (MultiTargetDebugger, TargetId, TargetId) {
        let mut dbg = MultiTargetDebugger::new();
        let t1 = dbg.add_target(TargetSpec::LocalPid(1000), "proc-a");
        let t2 = dbg.add_target(TargetSpec::LocalPid(2000), "proc-b");
        (dbg, t1, t2)
    }

    // ── DebugTargetList ───────────────────────────────────────────────────────

    #[test]
    fn list_add_increases_len() {
        let mut list = DebugTargetList::new();
        list.add(TargetSpec::LocalPid(1), "a");
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn list_remove() {
        let mut list = DebugTargetList::new();
        let id = list.add(TargetSpec::LocalPid(1), "a");
        assert!(list.remove(&id).is_some());
        assert!(list.is_empty());
    }

    #[test]
    fn list_get() {
        let mut list = DebugTargetList::new();
        let id = list.add(TargetSpec::LocalPid(1), "foo");
        let t = list.get(&id).unwrap();
        assert_eq!(t.name, "foo");
    }

    #[test]
    fn list_ids_count() {
        let mut list = DebugTargetList::new();
        list.add(TargetSpec::LocalPid(1), "a");
        list.add(TargetSpec::LocalPid(2), "b");
        assert_eq!(list.ids().len(), 2);
    }

    #[test]
    fn list_set_state() {
        let mut list = DebugTargetList::new();
        let id = list.add(TargetSpec::LocalPid(1), "x");
        list.set_state(&id, TargetState::Running);
        assert_eq!(list.get(&id).unwrap().state, TargetState::Running);
    }

    #[test]
    fn list_in_state_filter() {
        let mut list = DebugTargetList::new();
        let id = list.add(TargetSpec::LocalPid(1), "x");
        list.set_state(&id, TargetState::Running);
        let running = list.in_state(&TargetState::Running);
        assert_eq!(running.len(), 1);
    }

    // ── SessionRouter ─────────────────────────────────────────────────────────

    #[test]
    fn router_enqueue_broadcast() {
        let mut list = DebugTargetList::new();
        let id1 = list.add(TargetSpec::LocalPid(1), "a");
        let id2 = list.add(TargetSpec::LocalPid(2), "b");
        let mut router = SessionRouter::new();
        let cmd = RoutedCommand {
            route: CommandRoute::Broadcast,
            command: DebugCommand::Continue,
        };
        router.enqueue(cmd, &list);
        assert_eq!(router.pending(&id1), 1);
        assert_eq!(router.pending(&id2), 1);
    }

    #[test]
    fn router_execute_next() {
        let mut list = DebugTargetList::new();
        let id = list.add(TargetSpec::LocalPid(1), "a");
        let mut router = SessionRouter::new();
        let cmd = RoutedCommand {
            route: CommandRoute::Single(id.clone()),
            command: DebugCommand::Break,
        };
        router.enqueue(cmd, &list);
        let r = router.execute_next(&id);
        assert!(r.is_some());
        assert_eq!(router.pending(&id), 0);
    }

    #[test]
    fn router_execute_empty_returns_none() {
        let id = TargetId(42);
        let mut router = SessionRouter::new();
        assert!(router.execute_next(&id).is_none());
    }

    // ── CommandBroadcaster ───────────────────────────────────────────────────

    #[test]
    fn broadcaster_sends_to_all() {
        let (mut dbg, _t1, _t2) = make_two_targets();
        let results = dbg.broadcast_command(DebugCommand::Continue);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn broadcaster_reaches_every_target_but_claims_no_success() {
        // ADAPTED (was `broadcaster_results_all_succeed`): asserting `success`
        // pinned the fabrication in place. What is real here is the ROUTING —
        // one result per registered target — so that is what is asserted.
        let (mut dbg, _, _) = make_two_targets();
        let results = dbg.broadcast_command(DebugCommand::GetRegisters);
        assert_eq!(results.len(), 2);
        assert!(
            results.iter().all(|r| !r.success),
            "GetRegisters was never sent anywhere; it must not report success"
        );
    }

    // ── SyncBreakpoint ────────────────────────────────────────────────────────

    #[test]
    fn sync_bp_not_complete_initially() {
        let ids = vec![TargetId(0), TargetId(1)];
        let bp = SyncBreakpoint::new(0x1000, ids);
        assert!(!bp.is_complete());
    }

    #[test]
    fn sync_bp_complete_after_all_hit() {
        let ids = vec![TargetId(0), TargetId(1)];
        let mut bp = SyncBreakpoint::new(0x1000, ids);
        bp.record_hit(TargetId(0));
        bp.record_hit(TargetId(1));
        assert!(bp.is_complete());
    }

    #[test]
    fn sync_bp_pending_targets() {
        let ids = vec![TargetId(0), TargetId(1)];
        let mut bp = SyncBreakpoint::new(0x1000, ids);
        bp.record_hit(TargetId(0));
        let pending = bp.pending_targets();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, 1);
    }

    #[test]
    fn sync_bp_no_duplicates() {
        let ids = vec![TargetId(0)];
        let mut bp = SyncBreakpoint::new(0x1000, ids);
        bp.record_hit(TargetId(0));
        bp.record_hit(TargetId(0)); // duplicate
        assert_eq!(bp.hit_by.len(), 1);
    }

    // ── CorrelatedTrace ───────────────────────────────────────────────────────

    #[test]
    fn trace_add_pc() {
        let mut t = CorrelatedTrace::new(100);
        t.add_pc(&TargetId(0), 0xDEAD);
        assert_eq!(t.pcs.get("0"), Some(&0xDEAD));
    }

    #[test]
    fn trace_is_complete() {
        let ids = vec![TargetId(0), TargetId(1)];
        let mut t = CorrelatedTrace::new(100);
        t.add_pc(&TargetId(0), 0x1);
        t.add_pc(&TargetId(1), 0x2);
        assert!(t.is_complete(&ids));
    }

    #[test]
    fn trace_not_complete() {
        let ids = vec![TargetId(0), TargetId(1)];
        let mut t = CorrelatedTrace::new(100);
        t.add_pc(&TargetId(0), 0x1);
        assert!(!t.is_complete(&ids));
    }

    // ── MultiTargetDebugger ───────────────────────────────────────────────────

    #[test]
    fn debugger_add_target_count() {
        let (dbg, _, _) = make_two_targets();
        assert_eq!(dbg.targets.len(), 2);
        assert_eq!(dbg.report.total_targets, 2);
    }

    #[test]
    fn debugger_connect_all_refuses_and_says_why() {
        // ADAPTED: this used to assert `TargetState::Running` after a call that
        // contacted nothing.
        let (mut dbg, t1, _) = make_two_targets();
        let failed = dbg.connect_all().expect_err("no live transport exists");
        assert!(failed.contains(&t1), "the failure must name the targets: {failed:?}");
        match &dbg.targets.get(&t1).unwrap().state {
            TargetState::Error { message } => {
                assert!(
                    message.contains("no live transport"),
                    "state must name the reason, got {message:?}"
                );
            }
            other => panic!("expected Error state naming the reason, got {other:?}"),
        }
    }

    #[test]
    fn connect_all_with_no_targets_is_vacuously_ok() {
        let mut dbg = MultiTargetDebugger::new();
        assert!(dbg.connect_all().is_ok());
    }

    #[test]
    fn broadcast_results_are_not_fabricated_successes() {
        // The router dequeues and routes, but cannot run anything: it must not
        // report `ok`. `debug.multi_target_broadcast` maps `success` to "ok".
        let (mut dbg, t1, _) = make_two_targets();
        let results = dbg.broadcast_command(DebugCommand::Continue);
        assert_eq!(results.len(), 2, "both targets must be routed to");
        for r in &results {
            assert!(!r.success, "a command that never ran must not report success");
            assert!(
                r.output.contains("not executed") && r.output.contains("no live transport"),
                "the output must name why, got {:?}",
                r.output
            );
        }
        // Queue accounting is real: nothing is left pending.
        assert_eq!(dbg.broadcaster.router.pending(&t1), 0);
    }

    #[test]
    fn debugger_sync_bp_trigger() {
        let (mut dbg, _, _) = make_two_targets();
        dbg.add_sync_breakpoint(0x4000);
        dbg.trigger_sync_breakpoint(0x4000);
        assert_eq!(dbg.report.sync_bps_completed, 1);
    }

    #[test]
    fn debugger_record_trace() {
        let (mut dbg, t1, t2) = make_two_targets();
        dbg.record_trace(vec![(t1, 0x100), (t2, 0x200)]);
        assert_eq!(dbg.trace.len(), 1);
    }

    #[test]
    fn debugger_target_exited_clean() {
        let (mut dbg, t1, _) = make_two_targets();
        dbg.target_exited(&t1, 0);
        assert_eq!(dbg.report.clean_exits, 1);
        assert_eq!(dbg.report.errors, 0);
    }

    #[test]
    fn debugger_target_exited_error() {
        let (mut dbg, t1, _) = make_two_targets();
        dbg.target_exited(&t1, 1);
        assert_eq!(dbg.report.errors, 1);
    }

    #[test]
    fn debugger_finalise_includes_trace() {
        let (mut dbg, t1, t2) = make_two_targets();
        dbg.record_trace(vec![(t1, 0), (t2, 0)]);
        let report = dbg.finalise();
        assert_eq!(report.trace_entries.len(), 1);
    }

    #[test]
    fn debugger_all_ok() {
        let (mut dbg, t1, t2) = make_two_targets();
        dbg.target_exited(&t1, 0);
        dbg.target_exited(&t2, 0);
        assert!(dbg.report.all_ok());
    }

    #[test]
    fn target_id_display() {
        assert_eq!(TargetId(3).to_string(), "target#3");
    }

    #[test]
    fn report_add_note() {
        let mut r = MultiTargetReport::default();
        r.add_note("test note");
        assert_eq!(r.notes.len(), 1);
    }

    #[test]
    fn debugger_clock_advances() {
        let (mut dbg, t1, t2) = make_two_targets();
        dbg.record_trace(vec![(t1, 0)]);
        dbg.record_trace(vec![(t2, 0)]);
        assert!(dbg.trace[1].timestamp_ms > dbg.trace[0].timestamp_ms);
    }

    #[test]
    fn list_set_state_unknown_id_returns_false() {
        let mut list = DebugTargetList::new();
        let fake = TargetId(999);
        assert!(!list.set_state(&fake, TargetState::Running));
    }

    #[test]
    fn list_is_empty_initially() {
        let list = DebugTargetList::new();
        assert!(list.is_empty());
    }

    #[test]
    fn command_result_target_id() {
        let r = CommandResult {
            target_id: TargetId(7),
            command: DebugCommand::Continue,
            success: true,
            output: "ok".into(),
            data: vec![],
        };
        assert_eq!(r.target_id.0, 7);
    }

    #[test]
    fn sync_bp_address_stored() {
        let bp = SyncBreakpoint::new(0xCAFE, vec![]);
        assert_eq!(bp.address, 0xCAFE);
    }

    #[test]
    fn report_not_all_ok_with_errors() {
        let (mut dbg, t1, _) = make_two_targets();
        dbg.target_exited(&t1, 1);
        assert!(!dbg.report.all_ok());
    }

    #[test]
    fn debugger_default_constructs() {
        let _d = MultiTargetDebugger::default();
    }

    /// Routing by state name must match the STATE, not the text the target
    /// happened to put in the payload.
    ///
    /// The old filter was `format!("{:?}", state).contains(name)`. The reason
    /// string of `Stopped { reason }` comes from the target, so a process
    /// stopped with the reason "error while reading memory" answered to a
    /// selection for the Error state, and one stopped "waiting for running
    /// thread" answered to Running. In a multi-target session the command then
    /// reaches processes the caller never selected - and the run looks exactly
    /// like a correct one.
    #[test]
    fn routing_by_state_ignores_the_text_inside_the_state() {
        let mut list = DebugTargetList::new();
        let trap = list.add(TargetSpec::LocalPid(1), "stopped-but-says-error");
        let real_error = list.add(TargetSpec::LocalPid(2), "really-in-error");
        let runner = list.add(TargetSpec::LocalPid(3), "running");
        list.set_state(&trap, TargetState::Stopped { reason: "error while reading memory".to_string() });
        list.set_state(&real_error, TargetState::Error { message: "attach denied".to_string() });
        list.set_state(&runner, TargetState::Running);

        let mut router = SessionRouter::new();
        let addressed = router.enqueue(
            RoutedCommand { route: CommandRoute::ByState("error".to_string()), command: DebugCommand::Continue },
            &list,
        );
        assert_eq!(addressed, 1, "only the target actually in the Error state is addressed");
        assert_eq!(router.pending(&real_error), 1);
        assert_eq!(
            router.pending(&trap),
            0,
            "a stopped target whose reason text merely mentions an error is not in the Error state"
        );
        assert_eq!(router.pending(&runner), 0);
    }

    /// An empty or unknown state name addresses NOBODY, and says so.
    ///
    /// With a substring match an empty name matched every target: a filter that
    /// silently became a broadcast. A typo like "stoped" did the opposite and
    /// matched nothing, which read as "no target is stopped".
    #[test]
    fn an_unknown_state_name_addresses_nobody_and_reports_it() {
        let mut list = DebugTargetList::new();
        let a = list.add(TargetSpec::LocalPid(1), "a");
        let b = list.add(TargetSpec::LocalPid(2), "b");
        list.set_state(&a, TargetState::Running);
        list.set_state(&b, TargetState::Running);

        let mut router = SessionRouter::new();
        for name in ["", "stoped", "  "] {
            let addressed = router.enqueue(
                RoutedCommand { route: CommandRoute::ByState(name.to_string()), command: DebugCommand::Continue },
                &list,
            );
            assert_eq!(addressed, 0, "{name:?} is not a state name and must address nobody");
        }
        assert_eq!(router.pending(&a), 0, "an empty filter must not become a broadcast");
        assert_eq!(router.pending(&b), 0);

        // ...and the list itself distinguishes "no such state" from "none in it".
        assert!(list.in_state_named("stoped").is_none());
        assert_eq!(list.in_state_named("stopped").map(|v| v.len()), Some(0));
        assert_eq!(list.in_state_named("RUNNING").map(|v| v.len()), Some(2));
    }

}
