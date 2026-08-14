//! Replay scheduling: manage multiple concurrent replay sessions.
//!
//! Provides priority-based scheduling, resource allocation, replay checkpointing
//! for fast seek, parallel replay for differential analysis, and session
//! lifecycle management.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ReplayCheckpoint, ReplayError, ReplayState, TtdReplayer, TtdTrace,
};

// ─── SchedulerError ───────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum SchedulerError {
    #[error("session {0} not found")]
    SessionNotFound(SessionId),
    #[error("scheduler is at capacity ({0} sessions)")]
    AtCapacity(usize),
    #[error("resource limit exceeded: {0}")]
    ResourceLimit(String),
    #[error("replay error in session {0}: {1}")]
    ReplayError(SessionId, ReplayError),
    #[error("differential replay requires exactly two sessions")]
    DifferentialRequiresTwoSessions,
    #[error("checkpoint {0} not found in session {1}")]
    CheckpointNotFound(usize, SessionId),
    #[error("scheduler has been shut down")]
    ShutDown,
}

// ─── SessionId ────────────────────────────────────────────────────────────────

/// Unique identifier for a replay session managed by the scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct SessionId(pub u64);

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Session#{}", self.0)
    }
}

// ─── ReplayPriority ───────────────────────────────────────────────────────────

/// Priority level for a replay session.
///
/// Higher numeric value = higher priority (served first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ReplayPriority {
    /// Background / low-priority batch replay.
    Background = 0,
    /// Normal interactive replay.
    Normal = 1,
    /// High-priority replay (user is actively debugging).
    High = 2,
    /// Critical / real-time analysis that preempts all others.
    Critical = 3,
}

impl std::fmt::Display for ReplayPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Background => "Background",
            Self::Normal => "Normal",
            Self::High => "High",
            Self::Critical => "Critical",
        };
        write!(f, "{s}")
    }
}

// ─── SessionStatus ────────────────────────────────────────────────────────────

/// Current lifecycle status of a scheduled replay session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    /// Waiting in the run queue.
    Queued,
    /// Currently replaying (time-slice allocated).
    Running,
    /// Paused (waiting for user interaction or resource).
    Paused,
    /// Reached end of trace.
    Completed,
    /// Aborted due to error or explicit cancellation.
    Aborted,
}

impl std::fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Queued => "Queued",
            Self::Running => "Running",
            Self::Paused => "Paused",
            Self::Completed => "Completed",
            Self::Aborted => "Aborted",
        };
        write!(f, "{s}")
    }
}

// ─── CheckpointStrategy ───────────────────────────────────────────────────────

/// Strategy for automatically creating checkpoints during replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CheckpointStrategy {
    /// No automatic checkpoints.
    None,
    /// Create a checkpoint every N ticks.
    EveryNTicks(u64),
    /// Create a checkpoint every N events.
    EveryNEvents(u64),
    /// Create checkpoints at specific ticks.
    AtTicks(Vec<u64>),
    /// Create a checkpoint at the start and end only.
    StartAndEnd,
}

impl CheckpointStrategy {
    /// Returns true if a checkpoint should be created at the given tick/event.
    #[must_use] 
    pub fn should_checkpoint(&self, tick: u64, events_replayed: u64) -> bool {
        match self {
            Self::EveryNTicks(n) => tick.is_multiple_of(*n),
            Self::EveryNEvents(n) => events_replayed.is_multiple_of(*n),
            Self::AtTicks(ticks) => ticks.contains(&tick),
            Self::None | Self::StartAndEnd => false, // handled separately
        }
    }
}

// ─── ScheduledSession ─────────────────────────────────────────────────────────

/// Internal record for a session managed by the scheduler.
struct ScheduledSession {
    id: SessionId,
    replayer: TtdReplayer,
    priority: ReplayPriority,
    status: SessionStatus,
    checkpoints: Vec<ReplayCheckpoint>,
    checkpoint_strategy: CheckpointStrategy,
    events_replayed: u64,
    created_at: Instant,
    last_run_at: Option<Instant>,
    total_run_time: Duration,
    label: String,
    tick_budget: Option<u64>,
    ticks_consumed: u64,
}

impl ScheduledSession {
    fn new(
        id: SessionId,
        trace: TtdTrace,
        priority: ReplayPriority,
        label: impl Into<String>,
        strategy: CheckpointStrategy,
        tick_budget: Option<u64>,
    ) -> Self {
        let replayer = TtdReplayer::new(trace);
        Self {
            id,
            replayer,
            priority,
            status: SessionStatus::Queued,
            checkpoints: Vec::new(),
            checkpoint_strategy: strategy,
            events_replayed: 0,
            created_at: Instant::now(),
            last_run_at: None,
            total_run_time: Duration::ZERO,
            label: label.into(),
            tick_budget,
            ticks_consumed: 0,
        }
    }

    fn save_checkpoint(&mut self, label: impl Into<String>) -> usize {
        let cp = ReplayCheckpoint::save(&self.replayer, label);
        self.checkpoints.push(cp);
        self.checkpoints.len() - 1
    }

    fn restore_checkpoint(&mut self, idx: usize) -> bool {
        if let Some(cp) = self.checkpoints.get(idx).cloned() {
            cp.restore(&mut self.replayer);
            true
        } else {
            false
        }
    }

    fn is_budget_exhausted(&self) -> bool {
        self.tick_budget
            .is_some_and(|budget| self.ticks_consumed >= budget)
    }
}

// ─── SessionInfo ──────────────────────────────────────────────────────────────

/// Public-facing snapshot of a session's state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: SessionId,
    pub label: String,
    pub priority: ReplayPriority,
    pub status: SessionStatus,
    pub current_tick: u64,
    pub events_replayed: u64,
    pub checkpoint_count: usize,
    pub ticks_consumed: u64,
    pub tick_budget: Option<u64>,
    pub total_run_ms: u64,
    /// Wall-clock milliseconds since the session was spawned.
    pub age_ms: u64,
}

impl std::fmt::Display for SessionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} | {} | tick={} | priority={} | events={}",
            self.id,
            self.label,
            self.status,
            self.current_tick,
            self.priority,
            self.events_replayed
        )
    }
}

// ─── RunResult ────────────────────────────────────────────────────────────────

/// Result of running a session for one scheduling quantum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResult {
    pub session_id: SessionId,
    pub events_applied: u64,
    pub ticks_advanced: u64,
    pub new_status: SessionStatus,
    pub checkpoints_created: usize,
    pub elapsed_ms: u64,
}

// ─── DifferentialReplay ───────────────────────────────────────────────────────

/// Configuration for running two sessions in parallel for differential analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialReplay {
    /// ID of the "baseline" session.
    pub baseline_id: SessionId,
    /// ID of the "variant" session.
    pub variant_id: SessionId,
    /// Ticks at which to compare the two sessions' states.
    pub comparison_points: Vec<u64>,
    /// Whether to compare register state at each comparison point.
    pub compare_registers: bool,
    /// Whether to compare memory state at each comparison point.
    pub compare_memory: bool,
}

/// A state divergence found during differential replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DivergenceRecord {
    /// Tick at which divergence was detected.
    pub tick: u64,
    /// Registers that differed: name -> (`baseline_val`, `variant_val`).
    pub register_diffs: Vec<(String, u64, u64)>,
    /// Number of differing memory bytes at this tick.
    pub differing_memory_bytes: u64,
    /// Memory pages that differed (page-aligned addresses).
    pub differing_pages: Vec<u64>,
}

impl std::fmt::Display for DivergenceRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Divergence@{}: reg_diffs={} mem_diff_bytes={}",
            self.tick,
            self.register_diffs.len(),
            self.differing_memory_bytes
        )
    }
}

/// Result of a differential replay run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialResult {
    pub config: DifferentialReplay,
    pub divergences: Vec<DivergenceRecord>,
    pub first_divergence_tick: Option<u64>,
    pub total_divergences: u64,
}

impl DifferentialResult {
    #[must_use] 
    pub const fn is_identical(&self) -> bool {
        self.divergences.is_empty()
    }
}

impl std::fmt::Display for DifferentialResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_identical() {
            write!(f, "DifferentialResult: traces are identical")
        } else {
            write!(
                f,
                "DifferentialResult: {} divergences, first at tick {:?}",
                self.total_divergences, self.first_divergence_tick
            )
        }
    }
}

// ─── ResourceLimits ───────────────────────────────────────────────────────────

/// Resource limits enforced by the scheduler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum number of concurrent sessions.
    pub max_sessions: usize,
    /// Maximum total memory footprint of all replay states in bytes.
    pub max_total_memory_bytes: u64,
    /// Maximum events per scheduling quantum per session.
    pub quantum_events: u64,
    /// Maximum ticks per quantum per session.
    pub quantum_ticks: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_sessions: 16,
            max_total_memory_bytes: 512 * 1024 * 1024, // 512 MiB
            quantum_events: 10_000,
            quantum_ticks: 100_000,
        }
    }
}

// ─── ReplayScheduler ──────────────────────────────────────────────────────────

/// Manages multiple concurrent replay sessions with priority-based scheduling.
///
/// Sessions are processed in priority order; within the same priority level,
/// they are scheduled round-robin. Each call to [`ReplayScheduler::run_quantum`]
/// advances the highest-priority session by up to `quantum_events` events.
pub struct ReplayScheduler {
    sessions: HashMap<SessionId, ScheduledSession>,
    next_id: u64,
    limits: ResourceLimits,
    run_order: VecDeque<SessionId>,
    shut_down: bool,
    total_events_dispatched: u64,
}

impl ReplayScheduler {
    /// Create a new scheduler with the given resource limits.
    #[must_use] 
    pub fn new(limits: ResourceLimits) -> Self {
        Self {
            sessions: HashMap::new(),
            next_id: 1,
            limits,
            run_order: VecDeque::new(),
            shut_down: false,
            total_events_dispatched: 0,
        }
    }

    /// Create a scheduler with default limits.
    #[must_use] 
    pub fn default() -> Self {
        Self::new(ResourceLimits::default())
    }

    /// Spawn a new replay session.
    ///
    /// Returns the session ID that can be used to interact with the session.
    pub fn spawn_session(
        &mut self,
        trace: TtdTrace,
        priority: ReplayPriority,
        label: impl Into<String>,
        strategy: CheckpointStrategy,
        tick_budget: Option<u64>,
    ) -> Result<SessionId, SchedulerError> {
        if self.shut_down {
            return Err(SchedulerError::ShutDown);
        }
        if self.sessions.len() >= self.limits.max_sessions {
            return Err(SchedulerError::AtCapacity(self.limits.max_sessions));
        }

        let id = SessionId(self.next_id);
        self.next_id += 1;

        let session =
            ScheduledSession::new(id, trace, priority, label, strategy, tick_budget);
        self.sessions.insert(id, session);
        self.enqueue(id, priority);
        Ok(id)
    }

    /// Run one scheduling quantum for the highest-priority queued session.
    ///
    /// Returns the result of the quantum, or `None` if no sessions are ready.
    pub fn run_quantum(&mut self) -> Result<Option<RunResult>, SchedulerError> {
        if self.shut_down {
            return Err(SchedulerError::ShutDown);
        }

        // Find the highest-priority queued session.
        let session_id = self.pick_next_session();
        let id = match session_id {
            None => return Ok(None),
            Some(id) => id,
        };

        let t0 = Instant::now();
        let quantum_events = self.limits.quantum_events;
        let quantum_ticks = self.limits.quantum_ticks;

        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(SchedulerError::SessionNotFound(id))?;

        session.status = SessionStatus::Running;
        session.last_run_at = Some(Instant::now());

        let start_tick = session.replayer.current_tick;
        let mut events_applied = 0u64;
        let mut checkpoints_created = 0usize;

        loop {
            if events_applied >= quantum_events {
                break;
            }
            let current_tick = session.replayer.current_tick;
            if current_tick.saturating_sub(start_tick) >= quantum_ticks {
                break;
            }
            if session.is_budget_exhausted() {
                session.status = SessionStatus::Completed;
                break;
            }

            match session.replayer.step_forward() {
                Ok(ev) => {
                    let tick = ev.tick();
                    events_applied += 1;
                    session.events_replayed += 1;
                    session.ticks_consumed += 1;
                    self.total_events_dispatched += 1;

                    // Auto-checkpoint logic.
                    let should_cp = session
                        .checkpoint_strategy
                        .should_checkpoint(tick, session.events_replayed);
                    if should_cp {
                        let label = format!("auto@{tick}");
                        session.save_checkpoint(label);
                        checkpoints_created += 1;
                    }
                }
                Err(ReplayError::AtEnd) => {
                    session.status = SessionStatus::Completed;
                    // Save end checkpoint if strategy is StartAndEnd.
                    if matches!(session.checkpoint_strategy, CheckpointStrategy::StartAndEnd) {
                        session.save_checkpoint("end");
                        checkpoints_created += 1;
                    }
                    break;
                }
                Err(e) => {
                    session.status = SessionStatus::Aborted;
                    return Err(SchedulerError::ReplayError(id, e));
                }
            }
        }

        let elapsed = t0.elapsed();
        session.total_run_time += elapsed;

        let ticks_advanced = session
            .replayer
            .current_tick
            .saturating_sub(start_tick);

        // Re-queue if not finished.
        let new_status = session.status;
        let priority = session.priority;
        let should_enqueue = matches!(new_status, SessionStatus::Running);
        if should_enqueue {
            session.status = SessionStatus::Queued;
        }

        // We drop session reference now
        if should_enqueue {
            self.enqueue(id, priority);
        }

        Ok(Some(RunResult {
            session_id: id,
            events_applied,
            ticks_advanced,
            new_status,
            checkpoints_created,
            elapsed_ms: elapsed.as_millis() as u64,
        }))
    }

    /// Run all queued sessions to completion (blocks until all are done).
    pub fn drain_all(&mut self) -> Result<Vec<RunResult>, SchedulerError> {
        let mut results = Vec::new();
        loop {
            match self.run_quantum()? {
                None => break,
                Some(r) => results.push(r),
            }
        }
        Ok(results)
    }

    /// Seek a specific session to `tick`.
    pub fn seek_session(
        &mut self,
        id: SessionId,
        tick: u64,
    ) -> Result<(), SchedulerError> {
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(SchedulerError::SessionNotFound(id))?;
        session
            .replayer
            .goto(tick)
            .map_err(|e| SchedulerError::ReplayError(id, e))
    }

    /// Save a named checkpoint in a session, returning the checkpoint index.
    pub fn save_checkpoint(
        &mut self,
        id: SessionId,
        label: impl Into<String>,
    ) -> Result<usize, SchedulerError> {
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(SchedulerError::SessionNotFound(id))?;
        Ok(session.save_checkpoint(label))
    }

    /// Restore a checkpoint by index in a session.
    pub fn restore_checkpoint(
        &mut self,
        id: SessionId,
        checkpoint_idx: usize,
    ) -> Result<(), SchedulerError> {
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(SchedulerError::SessionNotFound(id))?;
        if session.restore_checkpoint(checkpoint_idx) {
            Ok(())
        } else {
            Err(SchedulerError::CheckpointNotFound(checkpoint_idx, id))
        }
    }

    /// Pause a session (remove from run queue, keep state).
    pub fn pause_session(&mut self, id: SessionId) -> Result<(), SchedulerError> {
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(SchedulerError::SessionNotFound(id))?;
        session.status = SessionStatus::Paused;
        self.run_order.retain(|&sid| sid != id);
        Ok(())
    }

    /// Resume a paused session.
    pub fn resume_session(&mut self, id: SessionId) -> Result<(), SchedulerError> {
        let (priority, status) = {
            let session = self
                .sessions
                .get_mut(&id)
                .ok_or(SchedulerError::SessionNotFound(id))?;
            if session.status == SessionStatus::Paused {
                session.status = SessionStatus::Queued;
            }
            (session.priority, session.status)
        };
        if status == SessionStatus::Queued {
            self.enqueue(id, priority);
        }
        Ok(())
    }

    /// Abort and remove a session.
    pub fn abort_session(&mut self, id: SessionId) -> Result<(), SchedulerError> {
        self.sessions
            .get_mut(&id)
            .ok_or(SchedulerError::SessionNotFound(id))?
            .status = SessionStatus::Aborted;
        self.run_order.retain(|&sid| sid != id);
        self.sessions.remove(&id);
        Ok(())
    }

    /// Change the priority of a session.
    pub fn set_priority(
        &mut self,
        id: SessionId,
        priority: ReplayPriority,
    ) -> Result<(), SchedulerError> {
        let session = self
            .sessions
            .get_mut(&id)
            .ok_or(SchedulerError::SessionNotFound(id))?;
        session.priority = priority;
        // Re-sort run order.
        let is_queued = session.status == SessionStatus::Queued;
        if is_queued {
            self.run_order.retain(|&sid| sid != id);
            self.enqueue(id, priority);
        }
        Ok(())
    }

    /// Return public info about all sessions.
    pub fn list_sessions(&self) -> Vec<SessionInfo> {
        self.sessions.values().map(session_to_info).collect()
    }

    /// Return info for a specific session.
    pub fn session_info(&self, id: SessionId) -> Option<SessionInfo> {
        self.sessions.get(&id).map(session_to_info)
    }

    /// Run differential analysis between two sessions.
    ///
    /// Both sessions are seeked to each comparison point and their states
    /// are compared. The sessions must already be registered with the scheduler.
    pub fn run_differential(
        &mut self,
        config: DifferentialReplay,
    ) -> Result<DifferentialResult, SchedulerError> {
        let baseline_id = config.baseline_id;
        let variant_id = config.variant_id;

        let mut divergences = Vec::new();

        for &tick in &config.comparison_points {
            // Seek baseline.
            self.seek_session(baseline_id, tick)?;
            // Seek variant.
            self.seek_session(variant_id, tick)?;

            let baseline_state = self
                .sessions
                .get(&baseline_id)
                .map(|s| s.replayer.state.clone())
                .ok_or(SchedulerError::SessionNotFound(baseline_id))?;
            let variant_state = self
                .sessions
                .get(&variant_id)
                .map(|s| s.replayer.state.clone())
                .ok_or(SchedulerError::SessionNotFound(variant_id))?;

            let mut register_diffs = Vec::new();
            if config.compare_registers {
                let all_regs: std::collections::HashSet<&str> = baseline_state
                    .regs
                    .keys()
                    .chain(variant_state.regs.keys())
                    .map(std::string::String::as_str)
                    .collect();
                for reg in all_regs {
                    let bval = baseline_state.reg(reg);
                    let vval = variant_state.reg(reg);
                    if bval != vval {
                        register_diffs.push((reg.to_string(), bval, vval));
                    }
                }
            }

            let mut differing_pages = Vec::new();
            let mut differing_memory_bytes = 0u64;
            if config.compare_memory {
                for (&page, baseline_data) in &baseline_state.mem {
                    match variant_state.mem.get(&page) {
                        None => {
                            differing_pages.push(page);
                            differing_memory_bytes += baseline_data.len() as u64;
                        }
                        Some(variant_data) => {
                            let diff_bytes = baseline_data
                                .iter()
                                .zip(variant_data.iter())
                                .filter(|(a, b)| a != b)
                                .count() as u64;
                            if diff_bytes > 0 {
                                differing_pages.push(page);
                                differing_memory_bytes += diff_bytes;
                            }
                        }
                    }
                }
                for &page in variant_state.mem.keys() {
                    if !baseline_state.mem.contains_key(&page) {
                        let size = variant_state.mem[&page].len() as u64;
                        differing_pages.push(page);
                        differing_memory_bytes += size;
                    }
                }
            }

            if !register_diffs.is_empty() || differing_memory_bytes > 0 {
                divergences.push(DivergenceRecord {
                    tick,
                    register_diffs,
                    differing_memory_bytes,
                    differing_pages,
                });
            }
        }

        let first_divergence_tick = divergences.first().map(|d| d.tick);
        let total_divergences = divergences.len() as u64;

        Ok(DifferentialResult {
            config,
            divergences,
            first_divergence_tick,
            total_divergences,
        })
    }

    /// Estimate total memory used by all active replay states.
    #[must_use] 
    pub fn estimated_memory_bytes(&self) -> u64 {
        self.sessions
            .values()
            .map(|s| s.replayer.state.footprint() as u64)
            .sum()
    }

    /// Total events dispatched across all sessions since creation.
    #[must_use] 
    pub const fn total_events_dispatched(&self) -> u64 {
        self.total_events_dispatched
    }

    /// Shut down the scheduler (no new sessions can be spawned).
    pub fn shutdown(&mut self) {
        self.shut_down = true;
        for session in self.sessions.values_mut() {
            if matches!(
                session.status,
                SessionStatus::Queued | SessionStatus::Running | SessionStatus::Paused
            ) {
                session.status = SessionStatus::Aborted;
            }
        }
        self.run_order.clear();
    }

    // ─── Private helpers ──────────────────────────────────────────────────────

    fn enqueue(&mut self, id: SessionId, priority: ReplayPriority) {
        // Insert in priority order (highest first) using linear scan.
        // For small queues this is fast enough.
        let insert_pos = self
            .run_order
            .iter()
            .position(|&sid| {
                self.sessions
                    .get(&sid)
                    .is_some_and(|s| s.priority < priority)
            })
            .unwrap_or(self.run_order.len());
        self.run_order.insert(insert_pos, id);
    }

    fn pick_next_session(&mut self) -> Option<SessionId> {
        while let Some(&id) = self.run_order.front() {
            let status = self.sessions.get(&id).map(|s| s.status);
            match status {
                Some(SessionStatus::Queued) => {
                    self.run_order.pop_front();
                    return Some(id);
                }
                _ => {
                    self.run_order.pop_front();
                }
            }
        }
        None
    }
}

fn session_to_info(session: &ScheduledSession) -> SessionInfo {
    SessionInfo {
        id: session.id,
        label: session.label.clone(),
        priority: session.priority,
        status: session.status,
        current_tick: session.replayer.current_tick,
        events_replayed: session.events_replayed,
        checkpoint_count: session.checkpoints.len(),
        ticks_consumed: session.ticks_consumed,
        tick_budget: session.tick_budget,
        total_run_ms: session.total_run_time.as_millis() as u64,
        age_ms: session.created_at.elapsed().as_millis() as u64,
    }
}

impl std::fmt::Debug for ReplayScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayScheduler")
            .field("sessions", &self.sessions.len())
            .field("queued", &self.run_order.len())
            .field("total_dispatched", &self.total_events_dispatched)
            .finish_non_exhaustive()
    }
}

// ─── ParallelBatch ────────────────────────────────────────────────────────────

/// A batch of sessions to be replayed to the same tick for comparison.
///
/// All sessions are seeked to `target_tick` and their states collected.
pub struct ParallelBatch {
    session_ids: Vec<SessionId>,
    target_tick: u64,
}

impl ParallelBatch {
    #[must_use] 
    pub const fn new(session_ids: Vec<SessionId>, target_tick: u64) -> Self {
        Self {
            session_ids,
            target_tick,
        }
    }

    /// Execute the batch: seek all sessions to `target_tick` and collect states.
    ///
    /// Returns a map of session ID -> replay state at the target tick.
    pub fn execute(
        &self,
        scheduler: &mut ReplayScheduler,
    ) -> Result<HashMap<SessionId, ReplayState>, SchedulerError> {
        let mut states = HashMap::new();
        for &id in &self.session_ids {
            scheduler.seek_session(id, self.target_tick)?;
            let state = scheduler
                .sessions
                .get(&id)
                .map(|s| s.replayer.state.clone())
                .ok_or(SchedulerError::SessionNotFound(id))?;
            states.insert(id, state);
        }
        Ok(states)
    }
}

// ─── SchedulerStats ───────────────────────────────────────────────────────────

/// Aggregate statistics from the scheduler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerStats {
    pub total_sessions_created: u64,
    pub active_sessions: usize,
    pub completed_sessions: usize,
    pub aborted_sessions: usize,
    pub total_events_dispatched: u64,
    pub estimated_memory_bytes: u64,
}

impl ReplayScheduler {
    #[must_use] 
    pub fn stats(&self) -> SchedulerStats {
        let completed = self
            .sessions
            .values()
            .filter(|s| s.status == SessionStatus::Completed)
            .count();
        let aborted = self
            .sessions
            .values()
            .filter(|s| s.status == SessionStatus::Aborted)
            .count();
        SchedulerStats {
            total_sessions_created: self.next_id - 1,
            active_sessions: self.sessions.len(),
            completed_sessions: completed,
            aborted_sessions: aborted,
            total_events_dispatched: self.total_events_dispatched,
            estimated_memory_bytes: self.estimated_memory_bytes(),
        }
    }
}

impl std::fmt::Display for SchedulerStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SchedulerStats {{ sessions={}, completed={}, aborted={}, dispatched={}, mem={}B }}",
            self.active_sessions,
            self.completed_sessions,
            self.aborted_sessions,
            self.total_events_dispatched,
            self.estimated_memory_bytes
        )
    }
}
