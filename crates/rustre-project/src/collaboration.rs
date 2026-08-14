//! `collaboration` — Real-time collaboration support.
//!
//! Provides `CollaborationSession`, `UserCursor`, `EditConflict`,
//! `CRDTComment`, `CollaborationLog`, `MergeStrategy`.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

/// Errors from the collaboration subsystem.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CollaborationError {
    #[error("user not found: '{0}'")]
    UserNotFound(String),
    #[error("user already in session: '{0}'")]
    UserAlreadyJoined(String),
    #[error("session is closed")]
    SessionClosed,
    #[error("conflict at address {0:#x}: {1}")]
    Conflict(u64, String),
    #[error("operation rejected: {0}")]
    Rejected(String),
    #[error("session ID mismatch")]
    SessionMismatch,
    #[error("merge failed: {0}")]
    MergeFailed(String),
}

// ─── VectorClock ──────────────────────────────────────────────────────────────

/// A simple vector clock for distributed event ordering.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorClock {
    /// Maps user_id → logical clock value.
    pub clocks: HashMap<String, u64>,
}

impl VectorClock {
    /// Create an empty clock.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Increment the clock for a user.
    pub fn tick(&mut self, user_id: &str) {
        let v = self.clocks.entry(user_id.to_string()).or_insert(0);
        *v = v.saturating_add(1);
    }

    /// Merge another vector clock (taking the component-wise max).
    pub fn merge(&mut self, other: &Self) {
        for (user, &val) in &other.clocks {
            let entry = self.clocks.entry(user.clone()).or_insert(0);
            *entry = (*entry).max(val);
        }
    }

    /// Return `true` if `self` happened-before `other`.
    #[must_use]
    pub fn happens_before(&self, other: &Self) -> bool {
        // self ≤ other component-wise and self ≠ other
        for (user, &val) in &self.clocks {
            let other_val = other.clocks.get(user).copied().unwrap_or(0);
            if val > other_val { return false; }
        }
        self.clocks != other.clocks
    }

    /// Return `true` if the clocks are concurrent (neither happens-before the other).
    #[must_use]
    pub fn concurrent(&self, other: &Self) -> bool {
        !self.happens_before(other) && !other.happens_before(self)
    }

    /// Return the clock value for `user_id`.
    #[must_use]
    pub fn get(&self, user_id: &str) -> u64 {
        self.clocks.get(user_id).copied().unwrap_or(0)
    }
}

// ─── UserCursor ───────────────────────────────────────────────────────────────

/// Position of a user's cursor in the disassembly / analysis view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserCursor {
    /// User identifier.
    pub user_id: String,
    /// Current virtual address.
    pub address: u64,
    /// Optional function name context.
    pub function: Option<String>,
    /// Optional binary ID.
    pub binary_id: Option<String>,
    /// Vector clock at time of update.
    pub clock: VectorClock,
    /// Unix timestamp of last update (ms).
    pub updated_at_ms: u64,
    /// Colour assigned to this user.
    pub color: String,
}

impl UserCursor {
    /// Create a new cursor.
    #[must_use]
    pub fn new(user_id: impl Into<String>, address: u64) -> Self {
        Self {
            user_id: user_id.into(), address, function: None,
            binary_id: None, clock: VectorClock::new(),
            updated_at_ms: 0, color: "#3498db".into(),
        }
    }

    /// Builder: set function context.
    #[must_use]
    pub fn in_function(mut self, func: impl Into<String>) -> Self {
        self.function = Some(func.into()); self
    }

    /// Builder: set colour.
    #[must_use]
    pub fn with_color(mut self, color: impl Into<String>) -> Self {
        self.color = color.into(); self
    }

    /// Move the cursor to a new address.
    pub fn move_to(&mut self, addr: u64) {
        self.address = addr;
        self.clock.tick(&self.user_id);
    }
}

impl fmt::Display for UserCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{:#x}", self.user_id, self.address)
    }
}

// ─── EditConflict ─────────────────────────────────────────────────────────────

/// Describes a conflict between two concurrent edits at the same address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditConflict {
    /// Virtual address where the conflict occurred.
    pub address: u64,
    /// Type of conflict.
    pub conflict_type: ConflictType,
    /// User who made the first edit.
    pub user_a: String,
    /// First edit description.
    pub edit_a: String,
    /// User who made the second edit.
    pub user_b: String,
    /// Second edit description.
    pub edit_b: String,
    /// Whether the conflict has been resolved.
    pub resolved: bool,
    /// Winning edit description.
    pub resolution: Option<String>,
}

/// Type of edit conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictType {
    /// Two users renamed the same function to different names.
    FunctionRename,
    /// Two users added different comments at the same address.
    CommentConflict,
    /// Two users defined different types.
    TypeConflict,
    /// General concurrent write conflict.
    ConcurrentWrite,
}

impl fmt::Display for ConflictType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::FunctionRename => "function_rename",
            Self::CommentConflict => "comment_conflict",
            Self::TypeConflict => "type_conflict",
            Self::ConcurrentWrite => "concurrent_write",
        };
        f.write_str(s)
    }
}

impl EditConflict {
    /// Create a new conflict.
    #[must_use]
    pub fn new(
        address: u64,
        conflict_type: ConflictType,
        user_a: impl Into<String>,
        edit_a: impl Into<String>,
        user_b: impl Into<String>,
        edit_b: impl Into<String>,
    ) -> Self {
        Self {
            address, conflict_type,
            user_a: user_a.into(), edit_a: edit_a.into(),
            user_b: user_b.into(), edit_b: edit_b.into(),
            resolved: false, resolution: None,
        }
    }

    /// Resolve the conflict by choosing one of the edits.
    pub fn resolve(&mut self, winning_edit: impl Into<String>) {
        self.resolved = true;
        self.resolution = Some(winning_edit.into());
    }
}

// ─── CRDTComment ─────────────────────────────────────────────────────────────

/// A conflict-free replicated comment using CRDT semantics (LWW element set).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CRDTComment {
    /// Unique comment ID.
    pub id: u64,
    /// Virtual address this comment is attached to.
    pub address: u64,
    /// Comment text.
    pub text: String,
    /// Author user ID.
    pub author: String,
    /// Vector clock at time of creation.
    pub created_clock: VectorClock,
    /// Unix timestamp (ms).
    pub created_at_ms: u64,
    /// Whether this comment has been tombstoned (deleted).
    pub tombstoned: bool,
    /// Tombstone clock (for LWW deletion).
    pub tombstone_clock: Option<VectorClock>,
    /// Last edit clock.
    pub last_edit_clock: VectorClock,
    /// Edit history (previous texts).
    pub edit_history: Vec<String>,
}

impl CRDTComment {
    /// Create a new comment.
    #[must_use]
    pub fn new(id: u64, address: u64, text: impl Into<String>, author: impl Into<String>) -> Self {
        let author_s: String = author.into();
        let mut clock = VectorClock::new();
        clock.tick(&author_s);
        Self {
            id, address, text: text.into(), author: author_s,
            created_clock: clock.clone(), created_at_ms: 0,
            tombstoned: false, tombstone_clock: None,
            last_edit_clock: clock, edit_history: vec![],
        }
    }

    /// Edit the comment.
    pub fn edit(&mut self, new_text: impl Into<String>) {
        self.edit_history.push(self.text.clone());
        self.text = new_text.into();
        self.last_edit_clock.tick(&self.author);
    }

    /// Delete the comment (tombstone).
    pub fn delete(&mut self) {
        let mut tc = self.last_edit_clock.clone();
        tc.tick(&self.author);
        self.tombstoned = true;
        self.tombstone_clock = Some(tc);
    }

    /// Merge another version of this comment using Last-Write-Wins.
    pub fn merge(&mut self, other: &Self) {
        if other.tombstoned {
            // Other version is deleted; apply tombstone if it's newer
            if let Some(ref other_tc) = other.tombstone_clock
                && self.last_edit_clock.happens_before(other_tc) {
                    self.tombstoned = true;
                    self.tombstone_clock = other.tombstone_clock.clone();
                }
        } else if self.last_edit_clock.happens_before(&other.last_edit_clock) {
            // Other version is newer text
            self.edit_history.push(self.text.clone());
            self.text = other.text.clone();
            self.last_edit_clock = other.last_edit_clock.clone();
        }
    }

    /// Return `true` if the comment is visible (not tombstoned).
    #[must_use]
    pub fn is_visible(&self) -> bool { !self.tombstoned }
}

// ─── CollaborationOperation ───────────────────────────────────────────────────

/// An operation submitted by a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborationOperation {
    pub op_id: u64,
    pub user_id: String,
    pub clock: VectorClock,
    pub op_type: OperationType,
    pub timestamp_ms: u64,
}

/// Type of collaboration operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationType {
    RenameFunction { address: u64, old_name: String, new_name: String },
    AddComment { address: u64, text: String },
    EditComment { comment_id: u64, new_text: String },
    DeleteComment { comment_id: u64 },
    MoveCursor { address: u64 },
    TypeDefinition { name: String, definition: String },
    Patch { address: u64, old_bytes: Vec<u8>, new_bytes: Vec<u8> },
}

// ─── CollaborationLog ────────────────────────────────────────────────────────

/// Vector-clock-ordered log of collaboration events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CollaborationLog {
    pub entries: Vec<CollaborationOperation>,
    pub current_clock: VectorClock,
}

impl CollaborationLog {
    /// Create an empty log.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Append an operation.
    pub fn append(&mut self, mut op: CollaborationOperation) {
        self.current_clock.merge(&op.clock);
        self.current_clock.tick(&op.user_id);
        op.clock = self.current_clock.clone();
        self.entries.push(op);
    }

    /// Return all operations by a specific user.
    #[must_use]
    pub fn by_user(&self, user_id: &str) -> Vec<&CollaborationOperation> {
        self.entries.iter().filter(|e| e.user_id == user_id).collect()
    }

    /// Return the last N operations.
    #[must_use]
    pub fn last_n(&self, n: usize) -> Vec<&CollaborationOperation> {
        self.entries.iter().rev().take(n).collect()
    }

    /// Return operations since a given clock.
    #[must_use]
    pub fn ops_since(&self, clock: &VectorClock) -> Vec<&CollaborationOperation> {
        self.entries.iter().filter(|e| clock.happens_before(&e.clock)).collect()
    }

    /// Total number of operations.
    #[must_use]
    pub fn len(&self) -> usize { self.entries.len() }

    /// Return `true` if the log is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}

// ─── MergeStrategy ────────────────────────────────────────────────────────────

/// Strategy used when merging concurrent edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MergeStrategy {
    /// Last writer wins (by timestamp).
    LastWriteWins,
    /// First writer wins (by clock order).
    FirstWriteWins,
    /// Merge both (e.g. concatenate comments).
    Union,
    /// Manual resolution required.
    Manual,
    /// Higher-priority user wins.
    PriorityBased,
}

impl fmt::Display for MergeStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::LastWriteWins => "last_write_wins",
            Self::FirstWriteWins => "first_write_wins",
            Self::Union => "union",
            Self::Manual => "manual",
            Self::PriorityBased => "priority_based",
        };
        f.write_str(s)
    }
}

// ─── CollaborationSession ────────────────────────────────────────────────────

/// A multi-user collaboration session on a project.
pub struct CollaborationSession {
    /// Session identifier.
    pub session_id: String,
    /// Whether the session is open.
    pub open: bool,
    /// Users currently in the session.
    users: HashMap<String, UserInfo>,
    /// User cursors.
    cursors: HashMap<String, UserCursor>,
    /// Collaboration log.
    pub log: CollaborationLog,
    /// Comments keyed by ID.
    comments: HashMap<u64, CRDTComment>,
    /// Detected conflicts.
    conflicts: Vec<EditConflict>,
    /// Merge strategy.
    pub merge_strategy: MergeStrategy,
    next_comment_id: u64,
    next_op_id: u64,
}

/// Information about a session participant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub user_id: String,
    pub display_name: String,
    pub trust_level: u8,
    pub joined_at_ms: u64,
    pub color: String,
}

impl CollaborationSession {
    /// Create a new session.
    #[must_use]
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            open: true,
            users: HashMap::new(),
            cursors: HashMap::new(),
            log: CollaborationLog::new(),
            comments: HashMap::new(),
            conflicts: Vec::new(),
            merge_strategy: MergeStrategy::LastWriteWins,
            next_comment_id: 1,
            next_op_id: 1,
        }
    }

    /// Join a user to the session.
    ///
    /// # Errors
    /// Returns `CollaborationError::UserAlreadyJoined` if already present,
    /// or `CollaborationError::SessionClosed` if the session is closed.
    pub fn join(&mut self, user_id: impl Into<String>, display_name: impl Into<String>) -> Result<(), CollaborationError> {
        if !self.open { return Err(CollaborationError::SessionClosed); }
        let uid: String = user_id.into();
        if self.users.contains_key(&uid) {
            return Err(CollaborationError::UserAlreadyJoined(uid));
        }
        let color = Self::assign_color(self.users.len());
        let cursor = UserCursor::new(uid.clone(), 0).with_color(color.clone());
        self.cursors.insert(uid.clone(), cursor);
        self.users.insert(uid.clone(), UserInfo {
            user_id: uid,
            display_name: display_name.into(),
            trust_level: 1,
            joined_at_ms: 0,
            color,
        });
        Ok(())
    }

    /// Leave the session.
    ///
    /// # Errors
    /// Returns `CollaborationError::UserNotFound` if the user is not in the session.
    pub fn leave(&mut self, user_id: &str) -> Result<(), CollaborationError> {
        if !self.users.remove(user_id).is_some() {
            return Err(CollaborationError::UserNotFound(user_id.to_string()));
        }
        self.cursors.remove(user_id);
        Ok(())
    }

    /// Move a user's cursor.
    ///
    /// # Errors
    /// Returns `CollaborationError::UserNotFound` if the user is not in the session.
    pub fn move_cursor(&mut self, user_id: &str, address: u64) -> Result<(), CollaborationError> {
        if !self.users.contains_key(user_id) {
            return Err(CollaborationError::UserNotFound(user_id.to_string()));
        }
        if let Some(cursor) = self.cursors.get_mut(user_id) {
            cursor.move_to(address);
        }
        let op = self.make_op(user_id, OperationType::MoveCursor { address });
        self.log.append(op);
        Ok(())
    }

    /// Rename a function, detecting conflicts.
    ///
    /// # Errors
    /// Returns `CollaborationError` on failure.
    pub fn rename_function(
        &mut self,
        user_id: &str,
        address: u64,
        old_name: impl Into<String>,
        new_name: impl Into<String>,
    ) -> Result<(), CollaborationError> {
        if !self.users.contains_key(user_id) {
            return Err(CollaborationError::UserNotFound(user_id.to_string()));
        }
        let old = old_name.into();
        let new = new_name.into();

        // Check for concurrent renames at the same address
        let recent_renames: Vec<_> = self.log.entries.iter().rev().take(10)
            .filter(|op| matches!(&op.op_type, OperationType::RenameFunction { address: a, .. } if *a == address))
            .collect();

        if let Some(other_op) = recent_renames.first() {
            if let OperationType::RenameFunction { new_name: other_new, .. } = &other_op.op_type {
                if *other_new != new && other_op.user_id != user_id {
                    self.conflicts.push(EditConflict::new(
                        address, ConflictType::FunctionRename,
                        &other_op.user_id, other_new.clone(),
                        user_id, new.clone(),
                    ));
                    if self.merge_strategy == MergeStrategy::Manual {
                        return Err(CollaborationError::Conflict(address, "concurrent rename".into()));
                    }
                }
            }
        }

        let op = self.make_op(user_id, OperationType::RenameFunction { address, old_name: old, new_name: new });
        self.log.append(op);
        Ok(())
    }

    /// Add a comment.
    ///
    /// # Errors
    /// Returns `CollaborationError::UserNotFound` if the user is not in the session.
    pub fn add_comment(&mut self, user_id: &str, address: u64, text: impl Into<String>) -> Result<u64, CollaborationError> {
        if !self.users.contains_key(user_id) {
            return Err(CollaborationError::UserNotFound(user_id.to_string()));
        }
        let id = self.next_comment_id;
        self.next_comment_id += 1;
        let text_s: String = text.into();
        let comment = CRDTComment::new(id, address, text_s.clone(), user_id);
        self.comments.insert(id, comment);
        let op = self.make_op(user_id, OperationType::AddComment { address, text: text_s });
        self.log.append(op);
        Ok(id)
    }

    /// Delete a comment.
    ///
    /// # Errors
    /// Returns `CollaborationError::UserNotFound` or a comment-not-found error.
    pub fn delete_comment(&mut self, user_id: &str, comment_id: u64) -> Result<(), CollaborationError> {
        if !self.users.contains_key(user_id) {
            return Err(CollaborationError::UserNotFound(user_id.to_string()));
        }
        if let Some(c) = self.comments.get_mut(&comment_id) {
            c.delete();
        }
        let op = self.make_op(user_id, OperationType::DeleteComment { comment_id });
        self.log.append(op);
        Ok(())
    }

    /// Return all visible comments.
    #[must_use]
    pub fn visible_comments(&self) -> Vec<&CRDTComment> {
        self.comments.values().filter(|c| c.is_visible()).collect()
    }

    /// Return all conflicts.
    #[must_use]
    pub fn conflicts(&self) -> &[EditConflict] { &self.conflicts }

    /// Return unresolved conflicts.
    #[must_use]
    pub fn unresolved_conflicts(&self) -> Vec<&EditConflict> {
        self.conflicts.iter().filter(|c| !c.resolved).collect()
    }

    /// Resolve a conflict by choosing a winning edit.
    ///
    /// # Errors
    /// Returns `CollaborationError::Rejected` if the conflict index is out of bounds.
    pub fn resolve_conflict(&mut self, index: usize, winning_edit: impl Into<String>) -> Result<(), CollaborationError> {
        let c = self.conflicts.get_mut(index)
            .ok_or_else(|| CollaborationError::Rejected(format!("conflict index {index} out of bounds")))?;
        c.resolve(winning_edit);
        Ok(())
    }

    /// Return cursors for all connected users.
    #[must_use]
    pub fn cursors(&self) -> Vec<&UserCursor> { self.cursors.values().collect() }

    /// Return the cursor for a specific user.
    #[must_use]
    pub fn cursor(&self, user_id: &str) -> Option<&UserCursor> { self.cursors.get(user_id) }

    /// Number of users in the session.
    #[must_use]
    pub fn user_count(&self) -> usize { self.users.len() }

    /// Close the session.
    pub fn close(&mut self) { self.open = false; }

    /// Return a list of user IDs in the session.
    #[must_use]
    pub fn user_ids(&self) -> Vec<&str> {
        self.users.keys().map(String::as_str).collect()
    }

    fn make_op(&mut self, user_id: &str, op_type: OperationType) -> CollaborationOperation {
        let id = self.next_op_id;
        self.next_op_id += 1;
        let mut clock = self.log.current_clock.clone();
        clock.tick(user_id);
        CollaborationOperation { op_id: id, user_id: user_id.to_string(), clock, op_type, timestamp_ms: 0 }
    }

    fn assign_color(index: usize) -> String {
        const COLORS: &[&str] = &[
            "#e74c3c", "#2ecc71", "#3498db", "#f39c12", "#9b59b6",
            "#1abc9c", "#e67e22", "#34495e", "#16a085", "#c0392b",
        ];
        COLORS[index % COLORS.len()].to_string()
    }
}

impl fmt::Debug for CollaborationSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CollaborationSession")
            .field("session_id", &self.session_id)
            .field("users", &self.users.len())
            .field("open", &self.open)
            .finish_non_exhaustive()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> CollaborationSession {
        let mut s = CollaborationSession::new("sess-001");
        s.join("alice", "Alice").unwrap();
        s.join("bob", "Bob").unwrap();
        s
    }

    // ── VectorClock ──────────────────────────────────────────────────────────

    #[test]
    fn test_clock_tick_and_get() {
        let mut c = VectorClock::new();
        c.tick("alice");
        c.tick("alice");
        assert_eq!(c.get("alice"), 2);
        assert_eq!(c.get("bob"), 0);
    }

    #[test]
    fn test_clock_merge_max() {
        let mut a = VectorClock::new();
        let mut b = VectorClock::new();
        a.tick("alice"); a.tick("alice");
        b.tick("alice"); b.tick("bob");
        a.merge(&b);
        assert_eq!(a.get("alice"), 2); // max(2, 1)
        assert_eq!(a.get("bob"), 1);
    }

    #[test]
    fn test_clock_happens_before() {
        let mut a = VectorClock::new();
        let mut b = VectorClock::new();
        a.tick("alice");
        b.tick("alice"); b.tick("alice");
        assert!(a.happens_before(&b));
        assert!(!b.happens_before(&a));
    }

    #[test]
    fn test_clock_concurrent() {
        let mut a = VectorClock::new();
        let mut b = VectorClock::new();
        a.tick("alice");
        b.tick("bob");
        assert!(a.concurrent(&b));
    }

    #[test]
    fn test_clock_equal_not_happens_before() {
        let c = VectorClock::new();
        assert!(!c.happens_before(&c));
    }

    // ── UserCursor ────────────────────────────────────────────────────────────

    #[test]
    fn test_cursor_new() {
        let c = UserCursor::new("alice", 0x1000);
        assert_eq!(c.address, 0x1000);
        assert_eq!(c.user_id, "alice");
    }

    #[test]
    fn test_cursor_move_to() {
        let mut c = UserCursor::new("alice", 0x1000);
        c.move_to(0x2000);
        assert_eq!(c.address, 0x2000);
        assert_eq!(c.clock.get("alice"), 1);
    }

    #[test]
    fn test_cursor_display() {
        let c = UserCursor::new("alice", 0x401000);
        assert!(c.to_string().contains("alice"));
    }

    // ── EditConflict ─────────────────────────────────────────────────────────

    #[test]
    fn test_conflict_new() {
        let c = EditConflict::new(0x1000, ConflictType::FunctionRename, "alice", "foo", "bob", "bar");
        assert!(!c.resolved);
        assert_eq!(c.conflict_type, ConflictType::FunctionRename);
    }

    #[test]
    fn test_conflict_resolve() {
        let mut c = EditConflict::new(0, ConflictType::FunctionRename, "a", "x", "b", "y");
        c.resolve("x");
        assert!(c.resolved);
        assert_eq!(c.resolution.as_deref(), Some("x"));
    }

    #[test]
    fn test_conflict_type_display() {
        assert_eq!(ConflictType::FunctionRename.to_string(), "function_rename");
    }

    // ── CRDTComment ───────────────────────────────────────────────────────────

    #[test]
    fn test_comment_new() {
        let c = CRDTComment::new(1, 0x1000, "hello", "alice");
        assert!(c.is_visible());
        assert_eq!(c.text, "hello");
    }

    #[test]
    fn test_comment_edit() {
        let mut c = CRDTComment::new(1, 0x1000, "old text", "alice");
        c.edit("new text");
        assert_eq!(c.text, "new text");
        assert_eq!(c.edit_history.len(), 1);
    }

    #[test]
    fn test_comment_delete() {
        let mut c = CRDTComment::new(1, 0x1000, "text", "alice");
        c.delete();
        assert!(!c.is_visible());
    }

    #[test]
    fn test_comment_merge_newer_wins() {
        let mut a = CRDTComment::new(1, 0, "old", "alice");
        let mut b = CRDTComment::new(1, 0, "new", "alice");
        b.last_edit_clock.tick("alice");
        a.merge(&b);
        assert_eq!(a.text, "new");
    }

    #[test]
    fn test_comment_merge_tombstone_propagates() {
        let mut a = CRDTComment::new(1, 0, "text", "alice");
        let mut b = CRDTComment::new(1, 0, "text", "alice");
        b.delete();
        a.merge(&b);
        assert!(!a.is_visible());
    }

    // ── CollaborationLog ──────────────────────────────────────────────────────

    #[test]
    fn test_log_append_and_len() {
        let mut s = session();
        s.move_cursor("alice", 0x1000).unwrap();
        assert_eq!(s.log.len(), 1);
    }

    #[test]
    fn test_log_by_user() {
        let mut s = session();
        s.move_cursor("alice", 0x1000).unwrap();
        s.move_cursor("bob", 0x2000).unwrap();
        s.move_cursor("alice", 0x3000).unwrap();
        assert_eq!(s.log.by_user("alice").len(), 2);
        assert_eq!(s.log.by_user("bob").len(), 1);
    }

    #[test]
    fn test_log_last_n() {
        let mut s = session();
        for addr in 0..5 { s.move_cursor("alice", addr).unwrap(); }
        assert_eq!(s.log.last_n(3).len(), 3);
    }

    #[test]
    fn test_log_empty() {
        let s = session();
        assert!(s.log.is_empty());
    }

    // ── CollaborationSession ──────────────────────────────────────────────────

    #[test]
    fn test_session_join() {
        let s = session();
        assert_eq!(s.user_count(), 2);
    }

    #[test]
    fn test_session_join_duplicate() {
        let mut s = session();
        let result = s.join("alice", "Alice");
        assert!(matches!(result, Err(CollaborationError::UserAlreadyJoined(_))));
    }

    #[test]
    fn test_session_leave() {
        let mut s = session();
        s.leave("alice").unwrap();
        assert_eq!(s.user_count(), 1);
    }

    #[test]
    fn test_session_leave_not_found() {
        let mut s = session();
        let result = s.leave("carol");
        assert!(matches!(result, Err(CollaborationError::UserNotFound(_))));
    }

    #[test]
    fn test_session_move_cursor() {
        let mut s = session();
        s.move_cursor("alice", 0x401000).unwrap();
        assert_eq!(s.cursor("alice").unwrap().address, 0x401000);
    }

    #[test]
    fn test_session_move_cursor_unknown_user() {
        let mut s = session();
        let result = s.move_cursor("carol", 0);
        assert!(matches!(result, Err(CollaborationError::UserNotFound(_))));
    }

    #[test]
    fn test_session_rename_function_no_conflict() {
        let mut s = session();
        s.rename_function("alice", 0x1000, "sub_1000", "decrypt").unwrap();
        assert!(s.unresolved_conflicts().is_empty());
    }

    #[test]
    fn test_session_rename_function_conflict_detected() {
        let mut s = session();
        s.rename_function("alice", 0x1000, "sub_1000", "foo").unwrap();
        s.rename_function("bob", 0x1000, "sub_1000", "bar").unwrap();
        assert!(!s.conflicts().is_empty());
    }

    #[test]
    fn test_session_add_comment() {
        let mut s = session();
        let id = s.add_comment("alice", 0x1000, "interesting code here").unwrap();
        assert_eq!(s.visible_comments().len(), 1);
        assert_eq!(id, 1);
    }

    #[test]
    fn test_session_delete_comment() {
        let mut s = session();
        let id = s.add_comment("alice", 0x1000, "temp note").unwrap();
        s.delete_comment("alice", id).unwrap();
        assert_eq!(s.visible_comments().len(), 0);
    }

    #[test]
    fn test_session_resolve_conflict() {
        let mut s = session();
        s.rename_function("alice", 0x1000, "old", "foo").unwrap();
        s.rename_function("bob", 0x1000, "old", "bar").unwrap();
        s.resolve_conflict(0, "foo").unwrap();
        assert!(s.conflicts()[0].resolved);
    }

    #[test]
    fn test_session_closed_join_fails() {
        let mut s = session();
        s.close();
        let result = s.join("carol", "Carol");
        assert!(matches!(result, Err(CollaborationError::SessionClosed)));
    }

    #[test]
    fn test_session_cursors_count() {
        let s = session();
        assert_eq!(s.cursors().len(), 2);
    }

    #[test]
    fn test_session_user_ids() {
        let s = session();
        let ids = s.user_ids();
        assert!(ids.contains(&"alice"));
        assert!(ids.contains(&"bob"));
    }

    #[test]
    fn test_merge_strategy_display() {
        assert_eq!(MergeStrategy::LastWriteWins.to_string(), "last_write_wins");
        assert_eq!(MergeStrategy::Manual.to_string(), "manual");
    }
}
