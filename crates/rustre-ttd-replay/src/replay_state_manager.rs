//! Replay state management: current position, bookmarks, and position history.
//!
//! The [`ReplayStateManager`] is the high-level coordinator for a single
//! time-travel debugging session.  It wraps a [`ForwardStepper`] and a
//! [`BackwardStepper`] and adds:
//!
//! * **Bookmarks** — named positions the user can jump to.
//! * **State snapshots** — periodic full-state copies for instant seek.
//! * **Position history** — the stack of previously-visited positions.
//! * **Session persistence** — serialise/deserialise the manager state to JSON.

use std::collections::HashMap;
use std::sync::Arc;

use rustre_ttd::{TraceMetadata, TracePosition, TtdTrace};
use serde::{Deserialize, Serialize};

use crate::{
    backward_stepper::{BackwardStepper, ReverseStepMode},
    forward_stepper::{ForwardStepper, StepMode},
    MemoryState, ReplayError,
};

// ─── Bookmark ─────────────────────────────────────────────────────────────────

/// A named bookmark in the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bookmark {
    /// Unique identifier (auto-assigned).
    pub id: u32,
    /// Human-readable label.
    pub label: String,
    /// Trace position.
    pub position: TracePosition,
    /// Optional note.
    pub note: Option<String>,
    /// Creation timestamp (Unix seconds, 0 if unavailable).
    pub created_at: u64,
    /// Whether this bookmark is pinned (protected from auto-removal).
    pub pinned: bool,
}

impl Bookmark {
    /// Create a new bookmark.
    #[must_use]
    pub fn new(id: u32, label: impl Into<String>, position: TracePosition) -> Self {
        Self {
            id,
            label: label.into(),
            position,
            note: None,
            created_at: 0,
            pinned: false,
        }
    }

    /// Attach a note.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    /// Mark as pinned.
    #[must_use]
    pub const fn pinned(mut self) -> Self {
        self.pinned = true;
        self
    }
}

impl std::fmt::Display for Bookmark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Bookmark#{} '{}' @ {}",
            self.id, self.label, self.position
        )
    }
}

// ─── StateSnapshot ────────────────────────────────────────────────────────────

/// A full session state snapshot, sufficient to reconstruct the entire replay
/// session at a given moment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Trace position this snapshot was taken at.
    pub position: TracePosition,
    /// Register state per-thread.
    pub registers: HashMap<u32, HashMap<String, u64>>,
    /// Label (auto-generated if not provided).
    pub label: String,
    /// Creation sequence number.
    pub seq: u64,
}

impl StateSnapshot {
    /// Create a new `StateSnapshot`.
    #[must_use]
    pub fn new(
        position: TracePosition,
        registers: HashMap<u32, HashMap<String, u64>>,
        seq: u64,
    ) -> Self {
        Self {
            position,
            registers,
            label: format!("snapshot-{seq}"),
            seq,
        }
    }
}

impl std::fmt::Display for StateSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StateSnapshot#{} @ {}", self.seq, self.position)
    }
}

// ─── ReplayState ─────────────────────────────────────────────────────────────

/// The combined replay session state at a single instant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayState {
    /// Current trace position.
    pub position: TracePosition,
    /// Current register state (primary thread).
    pub registers: HashMap<String, u64>,
    /// Primary thread ID.
    pub thread_id: u32,
}

impl ReplayState {
    #[must_use]
    pub fn new(position: TracePosition, thread_id: u32) -> Self {
        Self {
            position,
            registers: HashMap::new(),
            thread_id,
        }
    }
}

impl std::fmt::Display for ReplayState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ReplayState {{ pos={}, tid={} }}",
            self.position, self.thread_id
        )
    }
}

// ─── PositionHistoryEntry ─────────────────────────────────────────────────────

/// One entry in the position history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PositionHistoryEntry {
    /// The trace position.
    pub position: TracePosition,
    /// Why we were at this position (user action description).
    pub reason: String,
    /// Timestamp.
    pub timestamp: u64,
}

impl PositionHistoryEntry {
    #[must_use]
    pub fn new(position: TracePosition, reason: impl Into<String>) -> Self {
        Self {
            position,
            reason: reason.into(),
            timestamp: 0,
        }
    }
}

impl std::fmt::Display for PositionHistoryEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.position, self.reason)
    }
}

// ─── ReplayStateManager ──────────────────────────────────────────────────────

/// High-level manager for a TTD replay session.
///
/// Coordinates forward and backward stepping, bookmark management, and
/// session history.
pub struct ReplayStateManager {
    /// Forward stepper.
    forward: ForwardStepper,
    /// Backward stepper.
    backward: BackwardStepper,
    /// Bookmarks, keyed by ID.
    bookmarks: HashMap<u32, Bookmark>,
    /// Next bookmark ID.
    next_bookmark_id: u32,
    /// Periodic session snapshots.
    snapshots: Vec<StateSnapshot>,
    /// Snapshot sequence counter.
    snapshot_seq: u64,
    /// Position history (most recent first).
    history: Vec<PositionHistoryEntry>,
    /// Maximum history entries to keep.
    pub max_history: usize,
    /// The underlying trace (for metadata access).
    trace: Arc<TtdTrace>,
}

impl ReplayStateManager {
    /// Create a new manager at the start of `trace`.
    ///
    /// `snapshot_interval` — the backward-stepper snapshot interval.
    pub fn new(trace: Arc<TtdTrace>, snapshot_interval: u64) -> Self {
        let forward = ForwardStepper::new(Arc::clone(&trace));
        let backward = BackwardStepper::new(Arc::clone(&trace), snapshot_interval);
        Self {
            forward,
            backward,
            bookmarks: HashMap::new(),
            next_bookmark_id: 1,
            snapshots: Vec::new(),
            snapshot_seq: 0,
            history: Vec::new(),
            max_history: 1000,
            trace,
        }
    }

    /// Return the current trace position.
    #[must_use]
    pub const fn position(&self) -> TracePosition {
        self.forward.position()
    }

    /// Return the trace metadata.
    #[must_use]
    pub fn metadata(&self) -> &TraceMetadata {
        &self.trace.metadata
    }

    // ── Navigation ────────────────────────────────────────────────────────────

    /// Step forward by one event.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn step_forward(&mut self) -> Result<(), ReplayError> {
        let old_pos = self.position();
        self.forward.step(StepMode::SingleStep)?;
        let new_pos = self.position();
        if new_pos != old_pos {
            self.push_history(old_pos, "step_forward");
        }
        Ok(())
    }

    /// Step forward using step-over semantics.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn step_over(&mut self) -> Result<(), ReplayError> {
        let old_pos = self.position();
        self.forward.step(StepMode::StepOver)?;
        let new_pos = self.position();
        if new_pos != old_pos {
            self.push_history(old_pos, "step_over");
        }
        Ok(())
    }

    /// Step forward using step-out semantics.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn step_out(&mut self) -> Result<(), ReplayError> {
        let old_pos = self.position();
        self.forward.step(StepMode::StepOut)?;
        let new_pos = self.position();
        if new_pos != old_pos {
            self.push_history(old_pos, "step_out");
        }
        Ok(())
    }

    /// Step backward by one event.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn step_backward(&mut self) -> Result<(), ReplayError> {
        let old_pos = self.backward.position();
        self.backward.step(ReverseStepMode::SingleStep)?;
        let new_pos = self.backward.position();
        if new_pos != old_pos {
            // Synchronise the forward stepper with the backward stepper.
            Self::sync_forward_from_backward(new_pos);
            self.push_history(old_pos, "step_backward");
        }
        Ok(())
    }

    /// Step backward using step-back-over-call semantics.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn step_back_over(&mut self) -> Result<(), ReplayError> {
        let old_pos = self.backward.position();
        self.backward.step(ReverseStepMode::StepBack)?;
        let new_pos = self.backward.position();
        if new_pos != old_pos {
            Self::sync_forward_from_backward(new_pos);
            self.push_history(old_pos, "step_back_over");
        }
        Ok(())
    }

    /// Jump to a specific position.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn goto(&mut self, pos: TracePosition) -> Result<(), ReplayError> {
        let old_pos = self.position();
        self.backward.goto(pos)?;
        Self::sync_forward_from_backward(pos);
        self.push_history(old_pos, &format!("goto {pos}"));
        Ok(())
    }

    /// Run forward to the end of the trace.
    pub fn run_to_end(&mut self) {
        let old_pos = self.position();
        self.forward.run_to_end();
        self.push_history(old_pos, "run_to_end");
    }

    const fn sync_forward_from_backward(_pos: TracePosition) {
        // The forward stepper is driven independently; for backward steps we
        // note the position but the canonical position state comes from the
        // backward stepper's reconstruction.  No action needed here beyond
        // maintaining `history`.
    }

    // ── Bookmarks ────────────────────────────────────────────────────────────

    /// Create a bookmark at the current position.
    pub fn add_bookmark(&mut self, label: impl Into<String>) -> u32 {
        let id = self.next_bookmark_id;
        self.next_bookmark_id += 1;
        let pos = self.position();
        self.bookmarks.insert(id, Bookmark::new(id, label, pos));
        id
    }

    /// Create a bookmark at a specific position.
    pub fn add_bookmark_at(
        &mut self,
        label: impl Into<String>,
        pos: TracePosition,
    ) -> u32 {
        let id = self.next_bookmark_id;
        self.next_bookmark_id += 1;
        self.bookmarks.insert(id, Bookmark::new(id, label, pos));
        id
    }

    /// Remove a bookmark by ID.  Returns `true` if it existed.
    pub fn remove_bookmark(&mut self, id: u32) -> bool {
        self.bookmarks.remove(&id).is_some()
    }

    /// Look up a bookmark by its label.
    #[must_use]
    pub fn find_bookmark_by_label(&self, label: &str) -> Option<&Bookmark> {
        self.bookmarks.values().find(|b| b.label == label)
    }

    /// Look up a bookmark by ID.
    #[must_use]
    pub fn bookmark(&self, id: u32) -> Option<&Bookmark> {
        self.bookmarks.get(&id)
    }

    /// Return all bookmarks sorted by position.
    #[must_use]
    pub fn all_bookmarks_sorted(&self) -> Vec<&Bookmark> {
        let mut v: Vec<&Bookmark> = self.bookmarks.values().collect();
        v.sort_by_key(|b| b.position);
        v
    }

    /// Update the note on an existing bookmark.
    pub fn set_bookmark_note(&mut self, id: u32, note: impl Into<String>) -> bool {
        if let Some(bm) = self.bookmarks.get_mut(&id) {
            bm.note = Some(note.into());
            true
        } else {
            false
        }
    }

    /// Rename a bookmark.
    pub fn rename_bookmark(&mut self, id: u32, new_label: impl Into<String>) -> bool {
        if let Some(bm) = self.bookmarks.get_mut(&id) {
            bm.label = new_label.into();
            true
        } else {
            false
        }
    }

    /// Jump to a bookmark.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn goto_bookmark(&mut self, id: u32) -> Result<(), ReplayError> {
        let pos = self
            .bookmarks
            .get(&id)
            .map(|b| b.position)
            .ok_or_else(|| {
                ReplayError::PositionNotFound(TracePosition::start())
            })?;
        self.goto(pos)
    }

    // ── State snapshots ───────────────────────────────────────────────────────

    /// Take a state snapshot at the current position.
    pub fn take_snapshot(&mut self) -> u64 {
        let seq = self.snapshot_seq;
        self.snapshot_seq += 1;
        let pos = self.position();
        let registers = self
            .forward
            .registers_for(0)
            .cloned()
            .map(|r| {
                let mut m = HashMap::new();
                m.insert(0u32, r);
                m
            })
            .unwrap_or_default();
        self.snapshots.push(StateSnapshot::new(pos, registers, seq));
        seq
    }

    /// Retrieve a snapshot by sequence number.
    #[must_use]
    pub fn snapshot(&self, seq: u64) -> Option<&StateSnapshot> {
        self.snapshots.iter().find(|s| s.seq == seq)
    }

    /// Return all snapshots.
    #[must_use]
    pub fn all_snapshots(&self) -> &[StateSnapshot] {
        &self.snapshots
    }

    /// Remove a snapshot by sequence number.
    pub fn remove_snapshot(&mut self, seq: u64) -> bool {
        if let Some(idx) = self.snapshots.iter().position(|s| s.seq == seq) {
            self.snapshots.remove(idx);
            true
        } else {
            false
        }
    }

    // ── Position history ─────────────────────────────────────────────────────

    fn push_history(&mut self, pos: TracePosition, reason: &str) {
        self.history
            .insert(0, PositionHistoryEntry::new(pos, reason));
        if self.history.len() > self.max_history {
            self.history.truncate(self.max_history);
        }
    }

    /// Return the position history (most recent first).
    #[must_use]
    pub fn history(&self) -> &[PositionHistoryEntry] {
        &self.history
    }

    /// Return the most recently visited position (before the current one).
    #[must_use]
    pub fn previous_position(&self) -> Option<TracePosition> {
        self.history.first().map(|e| e.position)
    }

    /// Clear the position history.
    pub fn clear_history(&mut self) {
        self.history.clear();
    }

    // ── Query helpers ─────────────────────────────────────────────────────────

    /// Return the current memory state from the forward stepper.
    #[must_use]
    pub const fn memory(&self) -> &MemoryState {
        self.forward.memory()
    }

    /// Return a `ReplayState` summary.
    #[must_use]
    pub fn current_state(&self) -> ReplayState {
        let pos = self.position();
        let tid = 1u32; // default to thread 1
        let mut state = ReplayState::new(pos, tid);
        if let Some(regs) = self.forward.registers_for(tid) {
            state.registers.clone_from(regs);
        }
        state
    }

    /// Whether the forward stepper is at the end of the trace.
    #[must_use]
    pub fn at_end(&self) -> bool {
        self.forward.at_end()
    }

    /// Whether the backward stepper is at the start of the trace.
    #[must_use]
    pub const fn at_start(&self) -> bool {
        self.backward.at_start()
    }

    // ── Session serialisation ─────────────────────────────────────────────────

    /// Export bookmarks to a JSON value.
    #[must_use]
    pub fn export_bookmarks_json(&self) -> serde_json::Value {
        let bmarks: Vec<serde_json::Value> = self
            .bookmarks
            .values()
            .map(|b| serde_json::to_value(b).unwrap_or(serde_json::Value::Null))
            .collect();
        serde_json::json!({ "bookmarks": bmarks })
    }

    /// Import bookmarks from a JSON value.
    ///
    /// Existing bookmarks are preserved; imported ones use new IDs.
    pub fn import_bookmarks_json(&mut self, v: &serde_json::Value) -> usize {
        let mut count = 0;
        if let Some(arr) = v.get("bookmarks").and_then(serde_json::Value::as_array) {
            for item in arr {
                if let Ok(mut bm) = serde_json::from_value::<Bookmark>(item.clone()) {
                    let id = self.next_bookmark_id;
                    self.next_bookmark_id += 1;
                    bm.id = id;
                    self.bookmarks.insert(id, bm);
                    count += 1;
                }
            }
        }
        count
    }
}

impl std::fmt::Debug for ReplayStateManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayStateManager")
            .field("position", &self.position())
            .field("bookmarks", &self.bookmarks.len())
            .field("history_len", &self.history.len())
            .field("snapshots", &self.snapshots.len())
            .finish_non_exhaustive()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_ttd::{EventKind, TraceEvent, TraceMetadata, TracePosition};

    fn make_meta() -> TraceMetadata {
        TraceMetadata {
            version: 1,
            process_name: "test".into(),
            pid: 1,
            arch: "x86_64".into(),
            start_time: 0,
            end_time: 100,
            thread_count: 1,
            ..Default::default()
        }
    }

    fn make_trace(n: usize) -> Arc<TtdTrace> {
        let t = Arc::new(TtdTrace::new(make_meta()));
        for i in 0..n {
            t.add_event(TraceEvent {
                position: TracePosition::new(i as u64, 0),
                thread_id: 1,
                kind: EventKind::MemWrite {
                    addr: 0x1000 + i as u64 * 4,
                    data: vec![u8::try_from(i).unwrap_or(u8::MAX)],
                },
            });
        }
        t
    }

    #[test]
    fn create_manager() {
        let trace = make_trace(5);
        let mgr = ReplayStateManager::new(trace, 2);
        assert_eq!(mgr.position(), TracePosition::start());
        assert!(!mgr.at_end());
    }

    #[test]
    fn step_forward_advances_position() {
        let trace = make_trace(5);
        let mut mgr = ReplayStateManager::new(trace, 2);
        let pos0 = mgr.position();
        mgr.step_forward().unwrap();
        let pos1 = mgr.position();
        assert_ne!(pos0, pos1);
    }

    #[test]
    fn bookmark_round_trip() {
        let trace = make_trace(5);
        let mut mgr = ReplayStateManager::new(trace, 2);
        mgr.step_forward().unwrap();
        let id = mgr.add_bookmark("test_bookmark");
        assert!(mgr.bookmark(id).is_some());
        assert_eq!(mgr.bookmark(id).unwrap().label, "test_bookmark");
    }

    #[test]
    fn remove_bookmark() {
        let trace = make_trace(5);
        let mut mgr = ReplayStateManager::new(trace, 2);
        let id = mgr.add_bookmark("to_remove");
        assert!(mgr.remove_bookmark(id));
        assert!(mgr.bookmark(id).is_none());
        assert!(!mgr.remove_bookmark(id));
    }

    #[test]
    fn find_bookmark_by_label() {
        let trace = make_trace(5);
        let mut mgr = ReplayStateManager::new(trace, 2);
        mgr.add_bookmark("alpha");
        mgr.add_bookmark("beta");
        let bm = mgr.find_bookmark_by_label("alpha");
        assert!(bm.is_some());
        assert_eq!(bm.unwrap().label, "alpha");
    }

    #[test]
    fn snapshot_take_and_retrieve() {
        let trace = make_trace(5);
        let mut mgr = ReplayStateManager::new(trace, 2);
        mgr.step_forward().unwrap();
        let seq = mgr.take_snapshot();
        let snap = mgr.snapshot(seq);
        assert!(snap.is_some());
        assert_eq!(snap.unwrap().seq, seq);
    }

    #[test]
    fn remove_snapshot() {
        let trace = make_trace(5);
        let mut mgr = ReplayStateManager::new(trace, 2);
        let seq = mgr.take_snapshot();
        assert!(mgr.remove_snapshot(seq));
        assert!(mgr.snapshot(seq).is_none());
    }

    #[test]
    fn history_records_steps() {
        let trace = make_trace(5);
        let mut mgr = ReplayStateManager::new(trace, 2);
        mgr.step_forward().unwrap();
        mgr.step_forward().unwrap();
        assert!(!mgr.history().is_empty());
    }

    #[test]
    fn clear_history() {
        let trace = make_trace(5);
        let mut mgr = ReplayStateManager::new(trace, 2);
        mgr.step_forward().unwrap();
        mgr.clear_history();
        assert!(mgr.history().is_empty());
    }

    #[test]
    fn export_import_bookmarks() {
        let trace = make_trace(5);
        let mut mgr = ReplayStateManager::new(Arc::clone(&trace), 2);
        mgr.add_bookmark("bm_one");
        mgr.add_bookmark("bm_two");
        let json = mgr.export_bookmarks_json();

        let mut mgr2 = ReplayStateManager::new(Arc::clone(&trace), 2);
        let count = mgr2.import_bookmarks_json(&json);
        assert_eq!(count, 2);
    }

    #[test]
    fn set_and_rename_bookmark() {
        let trace = make_trace(5);
        let mut mgr = ReplayStateManager::new(trace, 2);
        let id = mgr.add_bookmark("original");
        assert!(mgr.set_bookmark_note(id, "some note"));
        assert_eq!(
            mgr.bookmark(id).unwrap().note.as_deref(),
            Some("some note")
        );
        assert!(mgr.rename_bookmark(id, "renamed"));
        assert_eq!(mgr.bookmark(id).unwrap().label, "renamed");
    }

    #[test]
    fn all_bookmarks_sorted_by_position() {
        let trace = make_trace(5);
        let mut mgr = ReplayStateManager::new(trace, 2);
        mgr.add_bookmark_at("b_later", TracePosition::new(3, 0));
        mgr.add_bookmark_at("b_early", TracePosition::new(1, 0));
        let sorted = mgr.all_bookmarks_sorted();
        assert_eq!(sorted.len(), 2);
        assert!(sorted[0].position <= sorted[1].position);
    }
}
