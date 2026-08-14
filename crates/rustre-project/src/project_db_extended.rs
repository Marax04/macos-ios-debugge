//! `project_db_extended` — Extended project database functionality.
//!
//! Provides [`ProjectDbExtended`] with annotation-level session management,
//! undo/redo stacks, collaboration change tracking, and multi-format export.
//!
//! # Layer distinction
//! This module owns the **annotation + undo/redo + collaboration-change**
//! layer; its [`AnalysisSession`] is a lightweight holder for per-address
//! annotations, bookmarks, and notes tied to a single binary path, and is
//! intentionally different from the similarly-named types in other modules:
//!
//! * [`crate::session::AnalysisSession`] — SQLite-persisted view/script
//!   state loaded across restarts.
//! * [`crate::session_management::ActiveSession`] — in-memory lifecycle
//!   session (state-machine, locking, snapshots).
//!
//! The three layers are complementary and should not be merged.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
pub use std::path::Path;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisSession
// ─────────────────────────────────────────────────────────────────────────────

/// An analysis session for a single binary view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSession {
    pub session_id: String,
    pub project_id: String,
    pub binary_path: String,
    pub created_at: u64,
    pub last_active_at: u64,
    pub arch: String,
    pub annotations: HashMap<u64, String>,
    pub bookmarks: Vec<Bookmark>,
    pub notes: Vec<SessionNote>,
    pub current_address: u64,
    pub zoom_level: f64,
}

/// A bookmark within a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bookmark {
    pub address: u64,
    pub label: String,
    pub color: String,
}

/// A text note attached to a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionNote {
    pub note_id: String,
    pub address: Option<u64>,
    pub content: String,
    pub author: String,
    pub created_at: u64,
}

impl AnalysisSession {
    /// Create a new analysis session.
    #[must_use]
    pub fn new(
        session_id: impl Into<String>,
        project_id: impl Into<String>,
        binary_path: impl Into<String>,
    ) -> Self {
        let now = now_secs();
        Self {
            session_id: session_id.into(),
            project_id: project_id.into(),
            binary_path: binary_path.into(),
            created_at: now,
            last_active_at: now,
            arch: "unknown".to_string(),
            annotations: HashMap::new(),
            bookmarks: Vec::new(),
            notes: Vec::new(),
            current_address: 0,
            zoom_level: 1.0,
        }
    }

    /// Add an annotation at an address.
    pub fn annotate(&mut self, address: u64, comment: impl Into<String>) {
        self.annotations.insert(address, comment.into());
        self.touch();
    }

    /// Add a bookmark.
    pub fn add_bookmark(&mut self, address: u64, label: impl Into<String>) {
        self.bookmarks.push(Bookmark {
            address,
            label: label.into(),
            color: "#4caf50".to_string(),
        });
        self.touch();
    }

    /// Add a note.
    pub fn add_note(
        &mut self,
        note_id: impl Into<String>,
        content: impl Into<String>,
        author: impl Into<String>,
    ) {
        self.notes.push(SessionNote {
            note_id: note_id.into(),
            address: None,
            content: content.into(),
            author: author.into(),
            created_at: now_secs(),
        });
        self.touch();
    }

    /// Update the last-active timestamp.
    pub fn touch(&mut self) {
        self.last_active_at = now_secs();
    }

    /// Return the annotation count.
    #[must_use]
    pub fn annotation_count(&self) -> usize {
        self.annotations.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisHistory
// ─────────────────────────────────────────────────────────────────────────────

/// A record of a past analysis activity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub entry_id: String,
    pub session_id: String,
    pub action: String,
    pub details: HashMap<String, String>,
    pub timestamp: u64,
    pub user: String,
}

impl HistoryEntry {
    /// Create a new history entry.
    #[must_use]
    pub fn new(
        entry_id: impl Into<String>,
        session_id: impl Into<String>,
        action: impl Into<String>,
        user: impl Into<String>,
    ) -> Self {
        Self {
            entry_id: entry_id.into(),
            session_id: session_id.into(),
            action: action.into(),
            details: HashMap::new(),
            timestamp: now_secs(),
            user: user.into(),
        }
    }

    /// Add a detail key-value pair.
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }
}

/// Chronological history of analysis activities.
#[derive(Debug, Default)]
pub struct AnalysisHistory {
    pub entries: VecDeque<HistoryEntry>,
    pub max_size: usize,
}

impl AnalysisHistory {
    /// Create a new history store.
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            max_size,
        }
    }

    /// Append a history entry.
    pub fn push(&mut self, entry: HistoryEntry) {
        if self.entries.len() >= self.max_size {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    /// Return entries for a specific session.
    #[must_use]
    pub fn for_session(&self, session_id: &str) -> Vec<&HistoryEntry> {
        self.entries
            .iter()
            .filter(|e| e.session_id == session_id)
            .collect()
    }

    /// Return the total entry count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return whether the history is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return the most recent entry.
    #[must_use]
    pub fn latest(&self) -> Option<&HistoryEntry> {
        self.entries.back()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UndoStack / RedoStack
// ─────────────────────────────────────────────────────────────────────────────

/// An undoable action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndoableAction {
    pub action_id: String,
    pub description: String,
    pub timestamp: u64,
    pub inverse: Option<Box<Self>>,
    pub address: Option<u64>,
}

impl UndoableAction {
    /// Create a new undoable action.
    #[must_use]
    pub fn new(action_id: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            action_id: action_id.into(),
            description: description.into(),
            timestamp: now_secs(),
            inverse: None,
            address: None,
        }
    }

    /// Attach an inverse (redo) action.
    #[must_use]
    pub fn with_inverse(mut self, inverse: Self) -> Self {
        self.inverse = Some(Box::new(inverse));
        self
    }

    /// Set the address this action applies to.
    #[must_use]
    pub fn at_address(mut self, address: u64) -> Self {
        self.address = Some(address);
        self
    }
}

/// Undo stack.
#[derive(Debug, Default)]
pub struct UndoStack {
    stack: Vec<UndoableAction>,
    max_depth: usize,
}

impl UndoStack {
    /// Create a new undo stack.
    #[must_use]
    pub fn new(max_depth: usize) -> Self {
        Self {
            stack: Vec::new(),
            max_depth,
        }
    }

    /// Push an action onto the undo stack.
    pub fn push(&mut self, action: UndoableAction) {
        if self.stack.len() >= self.max_depth {
            self.stack.remove(0);
        }
        self.stack.push(action);
    }

    /// Pop the top action (to undo).
    pub fn pop(&mut self) -> Option<UndoableAction> {
        self.stack.pop()
    }

    /// Peek at the top without removing.
    #[must_use]
    pub fn peek(&self) -> Option<&UndoableAction> {
        self.stack.last()
    }

    /// Return the stack depth.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.stack.len()
    }

    /// Return whether the stack is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    /// Clear the stack.
    pub fn clear(&mut self) {
        self.stack.clear();
    }
}

/// Redo stack (same structure as undo).
#[derive(Debug, Default)]
pub struct RedoStack {
    stack: Vec<UndoableAction>,
    max_depth: usize,
}

impl RedoStack {
    /// Create a new redo stack.
    #[must_use]
    pub fn new(max_depth: usize) -> Self {
        Self {
            stack: Vec::new(),
            max_depth,
        }
    }

    /// Push an action onto the redo stack.
    pub fn push(&mut self, action: UndoableAction) {
        if self.stack.len() >= self.max_depth {
            self.stack.remove(0);
        }
        self.stack.push(action);
    }

    /// Pop the top redo action.
    pub fn pop(&mut self) -> Option<UndoableAction> {
        self.stack.pop()
    }

    /// Return the redo depth.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.stack.len()
    }

    /// Return whether the stack is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    /// Clear the redo stack.
    pub fn clear(&mut self) {
        self.stack.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CollaborationSync
// ─────────────────────────────────────────────────────────────────────────────

/// A collaborative change from another user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollabChange {
    pub change_id: String,
    pub author: String,
    pub timestamp: u64,
    pub change_type: CollabChangeType,
    pub data: serde_json::Value,
}

/// The type of collaborative change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollabChangeType {
    Rename,
    Comment,
    TypeSet,
    Annotation,
    Bookmark,
    Custom(String),
}

/// Manages collaboration synchronization.
#[derive(Debug, Default)]
pub struct CollaborationSync {
    pub local_user: String,
    pub remote_changes: VecDeque<CollabChange>,
    pub outbound_changes: Vec<CollabChange>,
    pub applied_ids: std::collections::HashSet<String>,
    pub conflict_log: Vec<String>,
}

impl CollaborationSync {
    /// Create a new collaboration sync.
    #[must_use]
    pub fn new(local_user: impl Into<String>) -> Self {
        Self {
            local_user: local_user.into(),
            ..Default::default()
        }
    }

    /// Receive a remote change.
    pub fn receive(&mut self, change: CollabChange) {
        if !self.applied_ids.contains(&change.change_id) {
            self.remote_changes.push_back(change);
        }
    }

    /// Apply the next pending remote change.
    #[must_use]
    pub fn apply_next(&mut self) -> Option<CollabChange> {
        let change = self.remote_changes.pop_front()?;
        self.applied_ids.insert(change.change_id.clone());
        Some(change)
    }

    /// Record a local change for outbound sync.
    pub fn record_local(&mut self, change: CollabChange) {
        self.outbound_changes.push(change);
    }

    /// Drain all outbound changes (for sending to remote).
    #[must_use]
    pub fn drain_outbound(&mut self) -> Vec<CollabChange> {
        std::mem::take(&mut self.outbound_changes)
    }

    /// Return the number of pending remote changes.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.remote_changes.len()
    }

    /// Log a conflict.
    pub fn log_conflict(&mut self, description: impl Into<String>) {
        self.conflict_log.push(description.into());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProjectExporter
// ─────────────────────────────────────────────────────────────────────────────

/// Supported export formats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportFormat {
    Json,
    Xml,
    Csv,
    Html,
    Markdown,
    IdbCompat,
    BinjaCompat,
    Custom(String),
}

/// The result of an export operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportResult {
    pub format: ExportFormat,
    pub output_path: Option<PathBuf>,
    pub content: Option<String>,
    pub byte_count: usize,
    pub success: bool,
    pub error: Option<String>,
}

impl ExportResult {
    /// Create a successful export result.
    #[must_use]
    pub fn success_with_content(format: ExportFormat, content: String) -> Self {
        let bc = content.len();
        Self {
            format,
            output_path: None,
            content: Some(content),
            byte_count: bc,
            success: true,
            error: None,
        }
    }

    /// Create an error result.
    #[must_use]
    pub fn failure(format: ExportFormat, error: impl Into<String>) -> Self {
        Self {
            format,
            output_path: None,
            content: None,
            byte_count: 0,
            success: false,
            error: Some(error.into()),
        }
    }
}

/// Exports project data in multiple formats.
#[derive(Debug, Default)]
pub struct ProjectExporter {
    pub include_notes: bool,
    pub include_bookmarks: bool,
    pub include_history: bool,
}

impl ProjectExporter {
    /// Create a new exporter with all fields enabled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            include_notes: true,
            include_bookmarks: true,
            include_history: true,
        }
    }

    /// Export a session to the given format.
    #[must_use]
    pub fn export(&self, session: &AnalysisSession, format: ExportFormat) -> ExportResult {
        match &format {
            ExportFormat::Json => match serde_json::to_string_pretty(session) {
                Ok(json) => ExportResult::success_with_content(format, json),
                Err(e) => ExportResult::failure(format, e.to_string()),
            },
            ExportFormat::Csv => {
                let mut csv = "address,annotation\n".to_string();
                let mut pairs: Vec<_> = session.annotations.iter().collect();
                pairs.sort_by_key(|(a, _)| *a);
                for (addr, note) in pairs {
                    csv.push_str(&format!("{addr:#x},{}\n", note.replace(',', ";")));
                }
                ExportResult::success_with_content(format, csv)
            }
            ExportFormat::Markdown => {
                let mut md = format!("# Analysis: {}\n\n", session.binary_path);
                md.push_str(&format!("- Architecture: {}\n", session.arch));
                md.push_str(&format!("- Annotations: {}\n", session.annotation_count()));
                md.push_str(&format!("- Bookmarks: {}\n\n", session.bookmarks.len()));
                if !session.annotations.is_empty() {
                    md.push_str("## Annotations\n\n");
                    let mut annots: Vec<_> = session.annotations.iter().collect();
                    annots.sort_by_key(|(a, _)| *a);
                    for (addr, text) in annots {
                        md.push_str(&format!("- `{addr:#x}`: {text}\n"));
                    }
                }
                ExportResult::success_with_content(format, md)
            }
            ExportFormat::Html => {
                let html = format!(
                    "<html><body><h1>{}</h1><p>Arch: {}</p></body></html>",
                    session.binary_path, session.arch
                );
                ExportResult::success_with_content(format, html)
            }
            ExportFormat::Xml => {
                let xml = format!(
                    "<analysis><binary>{}</binary><arch>{}</arch></analysis>",
                    session.binary_path, session.arch
                );
                ExportResult::success_with_content(format, xml)
            }
            ExportFormat::IdbCompat => {
                let content = format!("// IDA-compatible export for {}\n", session.binary_path);
                ExportResult::success_with_content(format, content)
            }
            ExportFormat::BinjaCompat => {
                // `binary_path` is a filesystem path: on Windows every one of
                // them carries backslashes, each of which starts an escape
                // sequence inside a JSON string. Emitted raw, this export was
                // never valid JSON for a Windows session.
                let escape = |v: &str| {
                    v.replace('\\', "\\\\")
                        .replace('"', "\\\"")
                        .replace('\n', "\\n")
                        .replace('\r', "\\r")
                        .replace('\t', "\\t")
                };
                let content = format!(
                    "{{ \"file\": \"{}\", \"arch\": \"{}\" }}",
                    escape(&session.binary_path),
                    escape(&session.arch)
                );
                ExportResult::success_with_content(format, content)
            }
            ExportFormat::Custom(name) => ExportResult::failure(
                ExportFormat::Custom(name.clone()),
                format!("custom format '{name}' not implemented"),
            ),
        }
    }

    /// Export annotations as a sorted CSV string.
    #[must_use]
    pub fn annotations_csv(&self, session: &AnalysisSession) -> String {
        let result = self.export(session, ExportFormat::Csv);
        result.content.unwrap_or_default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProjectDbExtended — top-level extended database
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the extended project database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbConfig {
    pub max_undo_depth: usize,
    pub max_history_entries: usize,
    pub enable_collaboration: bool,
    pub auto_save_interval_secs: u64,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            max_undo_depth: 100,
            max_history_entries: 1000,
            enable_collaboration: true,
            auto_save_interval_secs: 300,
        }
    }
}

/// Extended project database with full CRUD, undo/redo, history, and export.
#[derive(Debug)]
pub struct ProjectDbExtended {
    pub config: DbConfig,
    pub sessions: HashMap<String, AnalysisSession>,
    pub history: AnalysisHistory,
    pub undo: UndoStack,
    pub redo: RedoStack,
    pub collaboration: CollaborationSync,
    pub exporter: ProjectExporter,
    pub local_user: String,
}

impl ProjectDbExtended {
    /// Create a new extended project database.
    #[must_use]
    pub fn new(local_user: impl Into<String>, config: DbConfig) -> Self {
        let user: String = local_user.into();
        Self {
            history: AnalysisHistory::new(config.max_history_entries),
            undo: UndoStack::new(config.max_undo_depth),
            redo: RedoStack::new(config.max_undo_depth),
            collaboration: CollaborationSync::new(user.clone()),
            exporter: ProjectExporter::new(),
            sessions: HashMap::new(),
            local_user: user,
            config,
        }
    }

    /// Create a new session and store it.
    pub fn create_session(
        &mut self,
        session_id: impl Into<String>,
        project_id: impl Into<String>,
        binary_path: impl Into<String>,
    ) -> &AnalysisSession {
        let session =
            AnalysisSession::new(session_id.into(), project_id.into(), binary_path.into());
        let id = session.session_id.clone();
        self.sessions.insert(id.clone(), session);
        // Log to history.
        self.history.push(HistoryEntry::new(
            format!("create_{id}"),
            id.clone(),
            "session_created",
            &self.local_user,
        ));
        self.sessions.get(&id).unwrap()
    }

    /// Get a session by ID.
    #[must_use]
    pub fn get_session(&self, session_id: &str) -> Option<&AnalysisSession> {
        self.sessions.get(session_id)
    }

    /// Get a mutable session by ID.
    #[must_use]
    pub fn get_session_mut(&mut self, session_id: &str) -> Option<&mut AnalysisSession> {
        self.sessions.get_mut(session_id)
    }

    /// Add an annotation with undo support.
    pub fn annotate(&mut self, session_id: &str, address: u64, comment: impl Into<String>) -> bool {
        let comment: String = comment.into();
        let Some(session) = self.sessions.get_mut(session_id) else {
            return false;
        };
        let old = session.annotations.get(&address).cloned();
        session.annotate(address, comment.clone());
        // Push undo action.
        let action = UndoableAction::new(
            format!("annotate_{address}"),
            format!("Annotate {address:#x} = {comment}"),
        )
        .at_address(address);
        self.undo.push(action);
        self.redo.clear();
        // History.
        let mut history_entry = HistoryEntry::new(
            format!("ann_{session_id}_{address}"),
            session_id,
            "annotation_added",
            &self.local_user,
        )
        .with_detail("address", format!("{address:#x}"))
        .with_detail("comment", comment.clone());
        if let Some(prev) = old {
            history_entry = history_entry.with_detail("previous_comment", prev);
        }
        self.history.push(history_entry);
        // Collaboration.
        self.collaboration.record_local(CollabChange {
            change_id: format!("ann_{session_id}_{address}_{}", now_secs()),
            author: self.local_user.clone(),
            timestamp: now_secs(),
            change_type: CollabChangeType::Annotation,
            data: serde_json::json!({ "address": address, "comment": comment }),
        });
        true
    }

    /// Undo the last action.
    pub fn undo(&mut self) -> Option<String> {
        let action = self.undo.pop()?;
        let desc = action.description.clone();
        self.redo.push(action);
        Some(desc)
    }

    /// Redo the last undone action.
    pub fn redo(&mut self) -> Option<String> {
        let action = self.redo.pop()?;
        let desc = action.description.clone();
        self.undo.push(action);
        Some(desc)
    }

    /// Export a session.
    #[must_use]
    pub fn export_session(&self, session_id: &str, format: ExportFormat) -> Option<ExportResult> {
        let session = self.sessions.get(session_id)?;
        Some(self.exporter.export(session, format))
    }

    /// Return the session count.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Delete a session.
    pub fn delete_session(&mut self, session_id: &str) -> bool {
        self.sessions.remove(session_id).is_some()
    }

    /// Return all session IDs.
    #[must_use]
    pub fn session_ids(&self) -> Vec<&str> {
        self.sessions.keys().map(String::as_str).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> ProjectDbExtended {
        ProjectDbExtended::new("alice", DbConfig::default())
    }

    fn session_with_annotations() -> AnalysisSession {
        let mut s = AnalysisSession::new("s1", "p1", "/bin/test");
        s.annotate(0x1000, "entry point");
        s.annotate(0x2000, "interesting function");
        s
    }

    // ── AnalysisSession ───────────────────────────────────────────────────────

    #[test]
    fn test_session_new() {
        let s = AnalysisSession::new("s1", "p1", "/bin/test");
        assert_eq!(s.session_id, "s1");
        assert_eq!(s.project_id, "p1");
        assert_eq!(s.annotation_count(), 0);
    }

    #[test]
    fn test_session_annotate() {
        let mut s = AnalysisSession::new("s1", "p1", "/bin/test");
        s.annotate(0x1000, "entry");
        assert_eq!(s.annotation_count(), 1);
        assert_eq!(
            s.annotations.get(&0x1000).map(String::as_str),
            Some("entry")
        );
    }

    #[test]
    fn test_session_bookmark() {
        let mut s = AnalysisSession::new("s1", "p1", "/bin/test");
        s.add_bookmark(0x4000, "interesting");
        assert_eq!(s.bookmarks.len(), 1);
        assert_eq!(s.bookmarks[0].address, 0x4000);
    }

    #[test]
    fn test_session_note() {
        let mut s = AnalysisSession::new("s1", "p1", "/bin/test");
        s.add_note("n1", "This is a note", "alice");
        assert_eq!(s.notes.len(), 1);
        assert_eq!(s.notes[0].author, "alice");
    }

    #[test]
    fn test_session_touch_updates_timestamp() {
        let mut s = AnalysisSession::new("s1", "p1", "/bin/test");
        let before = s.last_active_at;
        std::thread::sleep(std::time::Duration::from_millis(10));
        s.touch();
        assert!(s.last_active_at >= before);
    }

    // ── AnalysisHistory ───────────────────────────────────────────────────────

    #[test]
    fn test_history_push() {
        let mut h = AnalysisHistory::new(100);
        h.push(HistoryEntry::new("e1", "s1", "action", "alice"));
        assert_eq!(h.len(), 1);
        assert!(!h.is_empty());
    }

    #[test]
    fn test_history_max_size() {
        let mut h = AnalysisHistory::new(3);
        for i in 0..5 {
            h.push(HistoryEntry::new(format!("e{i}"), "s1", "action", "alice"));
        }
        assert_eq!(h.len(), 3);
    }

    #[test]
    fn test_history_for_session() {
        let mut h = AnalysisHistory::new(100);
        h.push(HistoryEntry::new("e1", "s1", "a", "alice"));
        h.push(HistoryEntry::new("e2", "s2", "b", "bob"));
        h.push(HistoryEntry::new("e3", "s1", "c", "alice"));
        assert_eq!(h.for_session("s1").len(), 2);
    }

    #[test]
    fn test_history_latest() {
        let mut h = AnalysisHistory::new(100);
        h.push(HistoryEntry::new("e1", "s1", "first", "alice"));
        h.push(HistoryEntry::new("e2", "s1", "last", "alice"));
        assert_eq!(h.latest().unwrap().action, "last");
    }

    // ── UndoStack ─────────────────────────────────────────────────────────────

    #[test]
    fn test_undo_stack_push_pop() {
        let mut s = UndoStack::new(10);
        s.push(UndoableAction::new("a1", "Add annotation"));
        assert_eq!(s.depth(), 1);
        let a = s.pop().unwrap();
        assert_eq!(a.description, "Add annotation");
        assert!(s.is_empty());
    }

    #[test]
    fn test_undo_stack_max_depth() {
        let mut s = UndoStack::new(3);
        for i in 0..5 {
            s.push(UndoableAction::new(format!("a{i}"), "action"));
        }
        assert_eq!(s.depth(), 3);
    }

    #[test]
    fn test_undo_stack_peek() {
        let mut s = UndoStack::new(10);
        s.push(UndoableAction::new("x", "X"));
        assert!(s.peek().is_some());
        assert_eq!(s.depth(), 1); // peek doesn't remove
    }

    #[test]
    fn test_undo_stack_clear() {
        let mut s = UndoStack::new(10);
        s.push(UndoableAction::new("a", "A"));
        s.clear();
        assert!(s.is_empty());
    }

    // ── RedoStack ─────────────────────────────────────────────────────────────

    #[test]
    fn test_redo_stack_push_pop() {
        let mut r = RedoStack::new(10);
        r.push(UndoableAction::new("r1", "Redo rename"));
        assert_eq!(r.depth(), 1);
        assert_eq!(r.pop().unwrap().description, "Redo rename");
    }

    #[test]
    fn test_redo_stack_empty() {
        let mut r = RedoStack::new(10);
        assert!(r.pop().is_none());
    }

    // ── CollaborationSync ─────────────────────────────────────────────────────

    #[test]
    fn test_collab_receive_apply() {
        let mut sync = CollaborationSync::new("alice");
        let change = CollabChange {
            change_id: "c1".to_string(),
            author: "bob".to_string(),
            timestamp: 0,
            change_type: CollabChangeType::Rename,
            data: serde_json::json!({}),
        };
        sync.receive(change);
        assert_eq!(sync.pending_count(), 1);
        let applied = sync.apply_next().unwrap();
        assert_eq!(applied.author, "bob");
        assert_eq!(sync.pending_count(), 0);
    }

    #[test]
    fn test_collab_no_duplicate_apply() {
        let mut sync = CollaborationSync::new("alice");
        let change = CollabChange {
            change_id: "c1".to_string(),
            author: "bob".to_string(),
            timestamp: 0,
            change_type: CollabChangeType::Comment,
            data: serde_json::json!({}),
        };
        sync.receive(change.clone());
        let _ = sync.apply_next();
        sync.receive(change);
        assert_eq!(sync.pending_count(), 0);
    }

    #[test]
    fn test_collab_outbound_drain() {
        let mut sync = CollaborationSync::new("alice");
        sync.record_local(CollabChange {
            change_id: "out1".to_string(),
            author: "alice".to_string(),
            timestamp: 0,
            change_type: CollabChangeType::Annotation,
            data: serde_json::json!({}),
        });
        let drained = sync.drain_outbound();
        assert_eq!(drained.len(), 1);
        assert!(sync.drain_outbound().is_empty());
    }

    #[test]
    fn test_collab_conflict_log() {
        let mut sync = CollaborationSync::new("alice");
        sync.log_conflict("conflicting rename at 0x1000");
        assert_eq!(sync.conflict_log.len(), 1);
    }

    // ── ProjectExporter ───────────────────────────────────────────────────────

    #[test]
    fn test_exporter_json() {
        let exp = ProjectExporter::new();
        let s = session_with_annotations();
        let r = exp.export(&s, ExportFormat::Json);
        assert!(r.success);
        let content = r.content.unwrap();
        assert!(content.contains("binary_path"));
    }

    #[test]
    fn test_exporter_csv() {
        let exp = ProjectExporter::new();
        let s = session_with_annotations();
        let r = exp.export(&s, ExportFormat::Csv);
        assert!(r.success);
        let content = r.content.unwrap();
        assert!(content.contains("address,annotation"));
    }

    #[test]
    fn test_exporter_markdown() {
        let exp = ProjectExporter::new();
        let s = session_with_annotations();
        let r = exp.export(&s, ExportFormat::Markdown);
        assert!(r.success);
        let md = r.content.unwrap();
        assert!(md.starts_with("# Analysis:"));
    }

    #[test]
    fn test_exporter_html() {
        let exp = ProjectExporter::new();
        let s = AnalysisSession::new("s1", "p1", "test.exe");
        let r = exp.export(&s, ExportFormat::Html);
        assert!(r.success);
        let html = r.content.unwrap();
        assert!(html.contains("<html>"));
    }

    #[test]
    fn test_exporter_xml() {
        let exp = ProjectExporter::new();
        let s = AnalysisSession::new("s1", "p1", "test.bin");
        let r = exp.export(&s, ExportFormat::Xml);
        assert!(r.success);
        assert!(r.content.unwrap().contains("<analysis>"));
    }

    #[test]
    fn test_exporter_custom_fails() {
        let exp = ProjectExporter::new();
        let s = AnalysisSession::new("s1", "p1", "test");
        let r = exp.export(&s, ExportFormat::Custom("unknown_fmt".to_string()));
        assert!(!r.success);
        assert!(r.error.is_some());
    }

    #[test]
    fn test_exporter_binja_compat() {
        let exp = ProjectExporter::new();
        let s = AnalysisSession::new("s1", "p1", "malware.exe");
        let r = exp.export(&s, ExportFormat::BinjaCompat);
        assert!(r.success);
    }

    // ── ProjectDbExtended ─────────────────────────────────────────────────────

    #[test]
    fn test_db_create_session() {
        let mut d = db();
        d.create_session("s1", "p1", "/bin/test");
        assert_eq!(d.session_count(), 1);
    }

    #[test]
    fn test_db_get_session() {
        let mut d = db();
        d.create_session("s1", "p1", "/bin/test");
        assert!(d.get_session("s1").is_some());
        assert!(d.get_session("missing").is_none());
    }

    #[test]
    fn test_db_annotate_and_history() {
        let mut d = db();
        d.create_session("s1", "p1", "/bin/test");
        assert!(d.annotate("s1", 0x1000, "entry point"));
        assert_eq!(d.undo.depth(), 1);
        assert!(!d.history.is_empty());
    }

    #[test]
    fn test_db_undo_redo() {
        let mut d = db();
        d.create_session("s1", "p1", "/bin/test");
        d.annotate("s1", 0x1000, "test");
        let undone = d.undo().unwrap();
        assert!(undone.contains("Annotate"));
        assert_eq!(d.redo.depth(), 1);
        let redone = d.redo().unwrap();
        assert!(!redone.is_empty());
    }

    #[test]
    fn test_db_export_session() {
        let mut d = db();
        d.create_session("s1", "p1", "/bin/test");
        let result = d.export_session("s1", ExportFormat::Json).unwrap();
        assert!(result.success);
    }

    #[test]
    fn test_db_export_missing_session() {
        let d = db();
        assert!(d.export_session("missing", ExportFormat::Json).is_none());
    }

    #[test]
    fn test_db_delete_session() {
        let mut d = db();
        d.create_session("s1", "p1", "/bin/test");
        assert!(d.delete_session("s1"));
        assert_eq!(d.session_count(), 0);
    }

    #[test]
    fn test_db_session_ids() {
        let mut d = db();
        d.create_session("s1", "p1", "/bin/a");
        d.create_session("s2", "p1", "/bin/b");
        let ids = d.session_ids();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn test_db_history_grows_with_actions() {
        let mut d = db();
        d.create_session("s1", "p1", "/bin/x");
        d.annotate("s1", 0x100, "first");
        d.annotate("s1", 0x200, "second");
        assert!(d.history.len() >= 3); // create + 2 annotations
    }

    #[test]
    fn test_db_collab_outbound_on_annotate() {
        let mut d = db();
        d.create_session("s1", "p1", "/bin/test");
        d.annotate("s1", 0x1000, "note");
        let outbound = d.collaboration.drain_outbound();
        assert!(!outbound.is_empty());
    }
}
