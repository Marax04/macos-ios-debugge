//! Undo/redo manager for the hex editor: groups atomic edits into named
//! transactions, supports undo/redo with a configurable depth limit, and
//! emits change notifications.

use std::fmt;

// ── HexEdit ───────────────────────────────────────────────────────────────────

/// A single, reversible edit operation on the hex buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexEdit {
    /// Replace `len` bytes at `offset` with different values.
    Replace {
        offset: usize,
        /// Original bytes (for undo).
        old: Vec<u8>,
        /// New bytes (for redo).
        new: Vec<u8>,
    },
    /// Insert `bytes` before `offset`, shifting subsequent data right.
    Insert {
        offset: usize,
        bytes: Vec<u8>,
    },
    /// Delete `len` bytes starting at `offset`.
    Delete {
        offset: usize,
        /// The bytes that were deleted (needed for undo).
        bytes: Vec<u8>,
    },
}

impl HexEdit {
    /// Return the inverse of this edit (for undo).
    #[must_use]
    pub fn inverse(&self) -> Self {
        match self {
            Self::Replace { offset, old, new } => Self::Replace {
                offset: *offset,
                old: new.clone(),
                new: old.clone(),
            },
            Self::Insert { offset, bytes } => Self::Delete {
                offset: *offset,
                bytes: bytes.clone(),
            },
            Self::Delete { offset, bytes } => Self::Insert {
                offset: *offset,
                bytes: bytes.clone(),
            },
        }
    }

    /// The file offset at which this edit begins.
    #[must_use]
    pub const fn offset(&self) -> usize {
        match self {
            Self::Replace { offset, .. }
            | Self::Insert { offset, .. }
            | Self::Delete { offset, .. } => *offset,
        }
    }

    /// Number of bytes affected by this edit.
    #[must_use]
    pub const fn byte_count(&self) -> usize {
        match self {
            Self::Replace { new, .. } => new.len(),
            Self::Insert { bytes, .. } | Self::Delete { bytes, .. } => bytes.len(),
        }
    }

    /// Short human-readable description.
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::Replace { offset, old, new } => format!(
                "Replace {} byte(s) at {offset:#x} (old={} new={})",
                new.len(),
                hex_preview(old),
                hex_preview(new)
            ),
            Self::Insert { offset, bytes } => {
                format!("Insert {} byte(s) at {offset:#x}", bytes.len())
            }
            Self::Delete { offset, bytes } => {
                format!("Delete {} byte(s) at {offset:#x}", bytes.len())
            }
        }
    }
}

impl fmt::Display for HexEdit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

// ── Transaction ───────────────────────────────────────────────────────────────

/// A named group of [`HexEdit`]s applied as an atomic unit.
#[derive(Debug, Clone)]
pub struct Transaction {
    /// Human-readable action name (e.g. `"Fill selection"`, `"Paste"`).
    pub name: String,
    /// Edits in application order.
    pub edits: Vec<HexEdit>,
    /// Whether this transaction has been reverted (for display only).
    pub reverted: bool,
}

impl Transaction {
    /// Create a named transaction with no edits.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            edits: Vec::new(),
            reverted: false,
        }
    }

    /// Add an edit to this transaction.
    pub fn push(&mut self, edit: HexEdit) {
        self.edits.push(edit);
    }

    /// Return the total number of bytes changed by this transaction.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.edits.iter().map(HexEdit::byte_count).sum()
    }

    /// Return `true` if this transaction contains no edits.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.edits.is_empty()
    }
}

impl fmt::Display for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Transaction({:?}, {} edit(s))",
            self.name,
            self.edits.len()
        )
    }
}

// ── UndoStack ─────────────────────────────────────────────────────────────────

/// A bounded stack of [`Transaction`]s used for undo/redo history.
#[derive(Debug, Clone, Default)]
pub struct UndoStack {
    entries: Vec<Transaction>,
    capacity: usize,
}

impl UndoStack {
    /// Create a stack with the given maximum depth.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::new(),
            capacity: capacity.max(1),
        }
    }

    /// Push a transaction, evicting the oldest entry if over capacity.
    pub fn push(&mut self, tx: Transaction) {
        if self.entries.len() >= self.capacity {
            self.entries.remove(0);
        }
        self.entries.push(tx);
    }

    /// Pop the most recently pushed transaction.
    #[must_use]
    pub fn pop(&mut self) -> Option<Transaction> {
        self.entries.pop()
    }

    /// Peek at the top of the stack without removing it.
    #[must_use]
    pub fn peek(&self) -> Option<&Transaction> {
        self.entries.last()
    }

    /// Total number of transactions on the stack.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when no transactions are present.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Return an iterator over all transactions (oldest first).
    pub fn iter(&self) -> impl Iterator<Item = &Transaction> {
        self.entries.iter()
    }

    /// Maximum number of entries this stack can hold.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }
}

// ── HexUndoManager ────────────────────────────────────────────────────────────

/// Full undo/redo manager for a hex editor session.
///
/// Edits are grouped into named transactions.  An open transaction accumulates
/// edits; when committed it is pushed onto the undo stack and the redo stack is
/// cleared.
///
/// # Example
/// ```
/// use rustre_hex::hex_undo_manager::{HexUndoManager, HexEdit};
///
/// let mut mgr = HexUndoManager::new(100);
/// mgr.begin_transaction("Patch bytes");
/// mgr.record(HexEdit::Replace {
///     offset: 0x100,
///     old: vec![0x00, 0x00],
///     new: vec![0x90, 0x90],
/// });
/// mgr.commit_transaction();
///
/// let tx = mgr.undo().unwrap();
/// assert_eq!(tx.name, "Patch bytes");
/// ```
pub struct HexUndoManager {
    undo_stack: UndoStack,
    redo_stack: UndoStack,
    /// The currently open (uncommitted) transaction, if any.
    open_tx: Option<Transaction>,
    /// Total number of edits committed so far (monotonic counter).
    total_edits: u64,
    /// Total number of undo operations performed.
    total_undos: u64,
    /// Total number of redo operations performed.
    total_redos: u64,
}

impl HexUndoManager {
    /// Create a manager with the given undo/redo depth.
    #[must_use]
    pub fn new(depth: usize) -> Self {
        Self {
            undo_stack: UndoStack::new(depth),
            redo_stack: UndoStack::new(depth),
            open_tx: None,
            total_edits: 0,
            total_undos: 0,
            total_redos: 0,
        }
    }

    // ── Transaction control ──────────────────────────────────────────────────

    /// Begin a new named transaction.  Any uncommitted transaction is
    /// automatically committed before starting the new one.
    pub fn begin_transaction(&mut self, name: impl Into<String>) {
        if let Some(tx) = self.open_tx.take()
            && !tx.is_empty() {
                self.push_to_undo(tx);
            }
        self.open_tx = Some(Transaction::new(name));
    }

    /// Add an edit to the currently open transaction.
    ///
    /// If no transaction is open, a default `"Auto"` transaction is started.
    pub fn record(&mut self, edit: HexEdit) {
        if self.open_tx.is_none() {
            self.open_tx = Some(Transaction::new("Auto"));
        }
        if let Some(tx) = self.open_tx.as_mut() {
            tx.push(edit);
            self.total_edits += 1;
        }
    }

    /// Commit the current open transaction to the undo stack.
    ///
    /// Empty transactions are discarded.  Returns `true` if a non-empty
    /// transaction was committed.
    pub fn commit_transaction(&mut self) -> bool {
        if let Some(tx) = self.open_tx.take() {
            if tx.is_empty() {
                return false;
            }
            self.push_to_undo(tx);
            return true;
        }
        false
    }

    /// Discard the current open transaction without committing.
    pub fn rollback_transaction(&mut self) {
        self.open_tx = None;
    }

    /// Returns `true` when a transaction is currently open.
    #[must_use]
    pub const fn is_transaction_open(&self) -> bool {
        self.open_tx.is_some()
    }

    // ── Undo / redo ──────────────────────────────────────────────────────────

    /// Undo the most recently committed transaction.
    ///
    /// Returns the transaction (with edits in reverse order and inverted) that
    /// should be replayed by the caller to revert the buffer, or `None` if the
    /// undo stack is empty.
    #[must_use]
    pub fn undo(&mut self) -> Option<Transaction> {
        // Auto-commit any open transaction first
        let _ = self.commit_transaction();

        let mut tx = self.undo_stack.pop()?;
        // Build the inverse: reverse the edit list and invert each edit
        let mut inv_tx = Transaction::new(tx.name.clone());
        for edit in tx.edits.iter().rev() {
            inv_tx.push(edit.inverse());
        }
        tx.reverted = true;
        self.redo_stack.push(tx);
        self.total_undos += 1;
        Some(inv_tx)
    }

    /// Redo the most recently undone transaction.
    ///
    /// Returns the transaction (in original application order) that the caller
    /// should replay to re-apply the edit, or `None` if the redo stack is empty.
    #[must_use]
    pub fn redo(&mut self) -> Option<Transaction> {
        let mut tx = self.redo_stack.pop()?;
        let mut redo_tx = Transaction::new(tx.name.clone());
        for edit in &tx.edits {
            redo_tx.push(edit.clone());
        }
        tx.reverted = false;
        self.undo_stack.push(tx);
        self.total_redos += 1;
        Some(redo_tx)
    }

    // ── State queries ─────────────────────────────────────────────────────────

    /// Returns `true` if there is at least one transaction that can be undone.
    #[must_use]
    pub const fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    /// Returns `true` if there is at least one transaction that can be redone.
    #[must_use]
    pub const fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    /// Number of transactions on the undo stack.
    #[must_use]
    pub const fn undo_depth(&self) -> usize {
        self.undo_stack.len()
    }

    /// Number of transactions on the redo stack.
    #[must_use]
    pub const fn redo_depth(&self) -> usize {
        self.redo_stack.len()
    }

    /// Clear both undo and redo stacks (e.g. after a file save).
    pub fn clear_all(&mut self) {
        self.undo_stack.clear();
        self.redo_stack.clear();
        self.open_tx = None;
    }

    /// Name of the transaction at the top of the undo stack, if any.
    #[must_use]
    pub fn undo_action_name(&self) -> Option<&str> {
        self.undo_stack.peek().map(|tx| tx.name.as_str())
    }

    /// Name of the transaction at the top of the redo stack, if any.
    #[must_use]
    pub fn redo_action_name(&self) -> Option<&str> {
        self.redo_stack.peek().map(|tx| tx.name.as_str())
    }

    /// Total committed edits since the manager was created.
    #[must_use]
    pub const fn total_edits(&self) -> u64 {
        self.total_edits
    }

    /// Total undo operations performed.
    #[must_use]
    pub const fn total_undos(&self) -> u64 {
        self.total_undos
    }

    /// Total redo operations performed.
    #[must_use]
    pub const fn total_redos(&self) -> u64 {
        self.total_redos
    }

    /// Return a snapshot of the undo history (oldest first).
    #[must_use]
    pub fn history(&self) -> Vec<&Transaction> {
        self.undo_stack.iter().collect()
    }

    // ── Private ───────────────────────────────────────────────────────────────

    fn push_to_undo(&mut self, tx: Transaction) {
        self.undo_stack.push(tx);
        self.redo_stack.clear();
    }
}

impl fmt::Debug for HexUndoManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HexUndoManager {{ undo={}, redo={}, edits={} }}",
            self.undo_stack.len(),
            self.redo_stack.len(),
            self.total_edits
        )
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn hex_preview(data: &[u8]) -> String {
    data.iter()
        .take(8)
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_replace(offset: usize, old: u8, new: u8) -> HexEdit {
        HexEdit::Replace {
            offset,
            old: vec![old],
            new: vec![new],
        }
    }

    #[test]
    fn basic_undo_redo() {
        let mut mgr = HexUndoManager::new(10);
        mgr.begin_transaction("edit1");
        mgr.record(make_replace(0, 0x00, 0xCC));
        mgr.commit_transaction();

        assert!(mgr.can_undo());
        assert!(!mgr.can_redo());

        let undo_tx = mgr.undo().unwrap();
        assert!(undo_tx.name.contains("edit1"));
        assert!(!mgr.can_undo());
        assert!(mgr.can_redo());

        let redo_tx = mgr.redo().unwrap();
        assert!(redo_tx.name.contains("edit1"));
        assert!(mgr.can_undo());
        assert!(!mgr.can_redo());
    }

    #[test]
    fn undo_empty_returns_none() {
        let mut mgr = HexUndoManager::new(10);
        assert!(mgr.undo().is_none());
    }

    #[test]
    fn redo_empty_returns_none() {
        let mut mgr = HexUndoManager::new(10);
        assert!(mgr.redo().is_none());
    }

    #[test]
    fn redo_cleared_after_new_edit() {
        let mut mgr = HexUndoManager::new(10);
        mgr.begin_transaction("a");
        mgr.record(make_replace(0, 0, 1));
        mgr.commit_transaction();

        let _ = mgr.undo();
        assert!(mgr.can_redo());

        mgr.begin_transaction("b");
        mgr.record(make_replace(0, 0, 2));
        mgr.commit_transaction();
        assert!(!mgr.can_redo());
    }

    #[test]
    fn empty_transaction_not_pushed() {
        let mut mgr = HexUndoManager::new(10);
        mgr.begin_transaction("empty");
        mgr.commit_transaction();
        assert!(!mgr.can_undo());
    }

    #[test]
    fn rollback_discards_edits() {
        let mut mgr = HexUndoManager::new(10);
        mgr.begin_transaction("discarded");
        mgr.record(make_replace(0, 0, 1));
        mgr.rollback_transaction();
        assert!(!mgr.can_undo());
    }

    #[test]
    fn capacity_limit_evicts_oldest() {
        let mut mgr = HexUndoManager::new(2);
        for i in 0u8..5 {
            mgr.begin_transaction(format!("tx{i}"));
            mgr.record(make_replace(i as usize, 0, i));
            mgr.commit_transaction();
        }
        assert_eq!(mgr.undo_depth(), 2);
    }

    #[test]
    fn auto_commit_on_new_begin() {
        let mut mgr = HexUndoManager::new(10);
        mgr.begin_transaction("first");
        mgr.record(make_replace(0, 0, 1));
        // Start a new transaction without explicit commit
        mgr.begin_transaction("second");
        mgr.record(make_replace(1, 0, 2));
        mgr.commit_transaction();
        // Both should be on the stack
        assert_eq!(mgr.undo_depth(), 2);
    }

    #[test]
    fn hex_edit_inverse_replace() {
        let e = HexEdit::Replace {
            offset: 0,
            old: vec![0xAA],
            new: vec![0xBB],
        };
        let inv = e.inverse();
        if let HexEdit::Replace { old, new, .. } = inv {
            assert_eq!(old, vec![0xBB]);
            assert_eq!(new, vec![0xAA]);
        } else {
            panic!("expected Replace");
        }
    }

    #[test]
    fn hex_edit_inverse_insert_becomes_delete() {
        let e = HexEdit::Insert {
            offset: 0,
            bytes: vec![0x90],
        };
        assert!(matches!(e.inverse(), HexEdit::Delete { .. }));
    }

    #[test]
    fn hex_edit_inverse_delete_becomes_insert() {
        let e = HexEdit::Delete {
            offset: 0,
            bytes: vec![0x90],
        };
        assert!(matches!(e.inverse(), HexEdit::Insert { .. }));
    }

    #[test]
    fn record_without_begin_auto_opens() {
        let mut mgr = HexUndoManager::new(10);
        mgr.record(make_replace(0, 0, 1));
        assert!(mgr.is_transaction_open());
        mgr.commit_transaction();
        assert!(mgr.can_undo());
    }

    #[test]
    fn clear_all_empties_everything() {
        let mut mgr = HexUndoManager::new(10);
        mgr.begin_transaction("x");
        mgr.record(make_replace(0, 0, 1));
        mgr.commit_transaction();
        mgr.clear_all();
        assert!(!mgr.can_undo());
        assert!(!mgr.can_redo());
    }

    #[test]
    fn action_names() {
        let mut mgr = HexUndoManager::new(10);
        mgr.begin_transaction("my_edit");
        mgr.record(make_replace(0, 0, 1));
        mgr.commit_transaction();
        assert_eq!(mgr.undo_action_name(), Some("my_edit"));
        let _ = mgr.undo();
        assert_eq!(mgr.redo_action_name(), Some("my_edit"));
    }

    #[test]
    fn undo_inverts_edits_in_reverse_order() {
        let mut mgr = HexUndoManager::new(10);
        mgr.begin_transaction("multi");
        mgr.record(make_replace(0, 10, 20));
        mgr.record(make_replace(1, 30, 40));
        mgr.commit_transaction();

        let undo_tx = mgr.undo().unwrap();
        // Should have two edits in reversed + inverted order
        assert_eq!(undo_tx.edits.len(), 2);
        // First undo edit should be at offset 1 (second edit, reversed)
        assert_eq!(undo_tx.edits[0].offset(), 1);
        assert_eq!(undo_tx.edits[1].offset(), 0);
    }

    #[test]
    fn history_returns_oldest_first() {
        let mut mgr = HexUndoManager::new(10);
        for i in 0u8..3 {
            mgr.begin_transaction(format!("t{i}"));
            mgr.record(make_replace(i as usize, 0, i));
            mgr.commit_transaction();
        }
        let h = mgr.history();
        assert_eq!(h.len(), 3);
        assert_eq!(h[0].name, "t0");
    }

    #[test]
    fn total_counters() {
        let mut mgr = HexUndoManager::new(10);
        mgr.begin_transaction("a");
        mgr.record(make_replace(0, 0, 1));
        mgr.commit_transaction();
        let _ = mgr.undo();
        let _ = mgr.redo();
        assert_eq!(mgr.total_edits(), 1);
        assert_eq!(mgr.total_undos(), 1);
        assert_eq!(mgr.total_redos(), 1);
    }

    #[test]
    fn transaction_byte_count() {
        let mut tx = Transaction::new("t");
        tx.push(HexEdit::Insert {
            offset: 0,
            bytes: vec![1, 2, 3],
        });
        tx.push(make_replace(5, 0, 1));
        assert_eq!(tx.total_bytes(), 4);
    }

    #[test]
    fn hex_edit_display() {
        let e = make_replace(0x100, 0xAA, 0xBB);
        let s = e.to_string();
        assert!(s.contains("0x100"));
    }
}
