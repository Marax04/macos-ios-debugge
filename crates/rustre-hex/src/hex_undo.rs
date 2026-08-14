//! `hex_undo` — Command-pattern undo/redo for the hex editor.
//!
//! Implements an unlimited undo history (capped by configurable memory limit),
//! selective undo (undo only within a byte range), named checkpoints, and a
//! branching undo tree.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// EditCommand — the command pattern
// ─────────────────────────────────────────────────────────────────────────────

/// A single undoable / redoable editing operation on a byte buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EditCommand {
    /// Write a single byte.
    WriteByte {
        offset: usize,
        old_value: u8,
        new_value: u8,
    },
    /// Write a contiguous byte range.
    WriteRange {
        offset: usize,
        old_bytes: Vec<u8>,
        new_bytes: Vec<u8>,
    },
    /// Fill a range with a repeating pattern.
    Fill {
        offset: usize,
        length: usize,
        old_bytes: Vec<u8>,
        fill_byte: u8,
    },
    /// Copy bytes from `src_offset` to `dst_offset`.
    CopyPaste {
        src_offset: usize,
        dst_offset: usize,
        length: usize,
        old_dst_bytes: Vec<u8>,
    },
    /// Delete bytes at `offset` (buffer shrinks).
    Delete {
        offset: usize,
        deleted_bytes: Vec<u8>,
    },
    /// Insert bytes at `offset` (buffer grows).
    Insert {
        offset: usize,
        inserted_bytes: Vec<u8>,
    },
    /// Group of commands applied atomically.
    Group {
        description: String,
        commands: Vec<Self>,
    },
}

impl EditCommand {
    /// Human-readable description of the command.
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::WriteByte { offset, old_value: _, new_value } => {
                format!("Write {new_value:#04x} at {offset:#010x}")
            }
            Self::WriteRange { offset, new_bytes, .. } => {
                format!("Write {} bytes at {offset:#010x}", new_bytes.len())
            }
            Self::Fill { offset, length, fill_byte, .. } => {
                format!("Fill {length} bytes with {fill_byte:#04x} at {offset:#010x}")
            }
            Self::CopyPaste { src_offset, dst_offset, length, .. } => {
                format!(
                    "Copy {length} bytes from {src_offset:#010x} to {dst_offset:#010x}"
                )
            }
            Self::Delete { offset, deleted_bytes } => {
                format!("Delete {} bytes at {offset:#010x}", deleted_bytes.len())
            }
            Self::Insert { offset, inserted_bytes } => {
                format!("Insert {} bytes at {offset:#010x}", inserted_bytes.len())
            }
            Self::Group { description, .. } => description.clone(),
        }
    }

    /// Approximate memory usage in bytes.
    #[must_use]
    pub fn memory_size(&self) -> usize {
        match self {
            Self::WriteByte { .. } => 32,
            Self::WriteRange { old_bytes, new_bytes, .. } => {
                64 + old_bytes.len() + new_bytes.len()
            }
            Self::Fill { old_bytes, .. } => 64 + old_bytes.len(),
            Self::CopyPaste { old_dst_bytes, length, .. } => 64 + old_dst_bytes.len() + length,
            Self::Delete { deleted_bytes, .. } => 64 + deleted_bytes.len(),
            Self::Insert { inserted_bytes, .. } => 64 + inserted_bytes.len(),
            Self::Group { commands, .. } => {
                64 + commands.iter().map(Self::memory_size).sum::<usize>()
            }
        }
    }

    /// Returns the primary byte range affected by this command.
    #[must_use]
    pub fn affected_range(&self) -> Option<std::ops::Range<usize>> {
        match self {
            Self::WriteByte { offset, .. } => Some(*offset..*offset + 1),
            Self::WriteRange { offset, new_bytes, .. } => {
                Some(*offset..*offset + new_bytes.len())
            }
            Self::Fill { offset, length, .. } => Some(*offset..*offset + length),
            Self::CopyPaste { dst_offset, length, .. } => {
                Some(*dst_offset..*dst_offset + length)
            }
            Self::Delete { offset, deleted_bytes } => {
                Some(*offset..*offset + deleted_bytes.len())
            }
            Self::Insert { offset, inserted_bytes } => {
                Some(*offset..*offset + inserted_bytes.len())
            }
            Self::Group { commands, .. } => {
                let starts = commands.iter().filter_map(Self::affected_range);
                let mut min = usize::MAX;
                let mut max = 0usize;
                for r in starts {
                    min = min.min(r.start);
                    max = max.max(r.end);
                }
                if min <= max {
                    Some(min..max)
                } else {
                    None
                }
            }
        }
    }

    /// Apply this command to a mutable byte buffer.
    ///
    /// # Errors
    ///
    /// Returns `Err` if any byte offset or range is out of bounds.
    pub fn apply(&self, buf: &mut Vec<u8>) -> Result<(), String> {
        match self {
            Self::WriteByte { offset, new_value, .. } => {
                *buf.get_mut(*offset).ok_or_else(|| format!("offset {offset} OOB"))? =
                    *new_value;
            }
            Self::WriteRange { offset, new_bytes, .. } => {
                let end = offset + new_bytes.len();
                if end > buf.len() {
                    return Err(format!("range {offset}..{end} OOB (buf len {})", buf.len()));
                }
                buf[*offset..end].copy_from_slice(new_bytes);
            }
            Self::Fill { offset, length, fill_byte, .. } => {
                let end = offset + length;
                if end > buf.len() {
                    return Err("fill range OOB".to_string());
                }
                buf[*offset..end].fill(*fill_byte);
            }
            Self::CopyPaste { src_offset, dst_offset, length, .. } => {
                if src_offset + length > buf.len() || dst_offset + length > buf.len() {
                    return Err("copy/paste OOB".to_string());
                }
                let src_bytes = buf[*src_offset..*src_offset + length].to_vec();
                buf[*dst_offset..*dst_offset + length].copy_from_slice(&src_bytes);
            }
            Self::Delete { offset, deleted_bytes } => {
                let end = offset + deleted_bytes.len();
                if end > buf.len() {
                    return Err("delete OOB".to_string());
                }
                buf.drain(*offset..end);
            }
            Self::Insert { offset, inserted_bytes } => {
                if *offset > buf.len() {
                    return Err("insert OOB".to_string());
                }
                let iter = inserted_bytes.iter().copied();
                buf.splice(*offset..*offset, iter);
            }
            Self::Group { commands, .. } => {
                for cmd in commands {
                    cmd.apply(buf)?;
                }
            }
        }
        Ok(())
    }

    /// Undo this command on a mutable byte buffer.
    ///
    /// # Errors
    ///
    /// Returns `Err` if any byte offset or range is out of bounds.
    pub fn undo(&self, buf: &mut Vec<u8>) -> Result<(), String> {
        match self {
            Self::WriteByte { offset, old_value, .. } => {
                *buf.get_mut(*offset).ok_or_else(|| format!("offset {offset} OOB"))? =
                    *old_value;
            }
            Self::WriteRange { offset, old_bytes, .. } => {
                let end = offset + old_bytes.len();
                if end > buf.len() {
                    return Err("undo WriteRange OOB".to_string());
                }
                buf[*offset..end].copy_from_slice(old_bytes);
            }
            Self::Fill { offset, old_bytes, .. } => {
                let end = offset + old_bytes.len();
                if end > buf.len() {
                    return Err("undo Fill OOB".to_string());
                }
                buf[*offset..end].copy_from_slice(old_bytes);
            }
            Self::CopyPaste { dst_offset, old_dst_bytes, .. } => {
                let end = dst_offset + old_dst_bytes.len();
                if end > buf.len() {
                    return Err("undo CopyPaste OOB".to_string());
                }
                buf[*dst_offset..end].copy_from_slice(old_dst_bytes);
            }
            Self::Delete { offset, deleted_bytes } => {
                let iter = deleted_bytes.iter().copied();
                buf.splice(*offset..*offset, iter);
            }
            Self::Insert { offset, inserted_bytes } => {
                let end = offset + inserted_bytes.len();
                if end > buf.len() {
                    return Err("undo Insert OOB".to_string());
                }
                buf.drain(*offset..end);
            }
            Self::Group { commands, .. } => {
                for cmd in commands.iter().rev() {
                    cmd.undo(buf)?;
                }
            }
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HistoryEntry
// ─────────────────────────────────────────────────────────────────────────────

/// An entry in the undo history.
#[derive(Debug, Clone)]
pub struct HistoryEntry {
    pub command: EditCommand,
    pub timestamp: u64,
    /// Optional branch id (for undo tree).
    pub branch: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Checkpoint
// ─────────────────────────────────────────────────────────────────────────────

/// A named save point in the undo history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub name: String,
    pub history_index: usize,
    pub timestamp: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// UndoConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the undo system.
#[derive(Debug, Clone)]
pub struct UndoConfig {
    /// Maximum number of bytes the undo history may use. `None` = unlimited.
    pub max_memory_bytes: Option<usize>,
    /// Maximum number of undo steps. `None` = unlimited.
    pub max_steps: Option<usize>,
    /// Enable the undo tree (branching).
    pub enable_tree: bool,
}

impl Default for UndoConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: Some(64 * 1024 * 1024), // 64 MiB
            max_steps: Some(10_000),
            enable_tree: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UndoManager
// ─────────────────────────────────────────────────────────────────────────────

/// Full undo/redo manager with branching tree support.
#[derive(Debug)]
pub struct UndoManager {
    history: Vec<HistoryEntry>,
    /// Current position (points past the last applied command).
    cursor: usize,
    checkpoints: Vec<Checkpoint>,
    config: UndoConfig,
    current_branch: u32,
    next_branch: u32,
    total_memory: usize,
    /// For the undo tree: map from (`parent_cursor`, `branch_id`) → child history entries.
    branches: HashMap<(usize, u32), Vec<HistoryEntry>>,
}

impl Default for UndoManager {
    fn default() -> Self {
        Self::new(UndoConfig::default())
    }
}

impl UndoManager {
    /// Create a new undo manager with the given config.
    #[must_use]
    pub fn new(config: UndoConfig) -> Self {
        Self {
            history: vec![],
            cursor: 0,
            checkpoints: vec![],
            config,
            current_branch: 0,
            next_branch: 1,
            total_memory: 0,
            branches: HashMap::new(),
        }
    }

    /// Record a new command and apply it to `buf`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the command application fails (out-of-bounds or other buffer error).
    pub fn execute(
        &mut self,
        command: EditCommand,
        buf: &mut Vec<u8>,
    ) -> Result<(), String> {
        command.apply(buf)?;
        self.push_command(command);
        Ok(())
    }

    /// Push a command that has already been applied.
    pub fn push_command(&mut self, command: EditCommand) {
        let mem = command.memory_size();

        // If we're not at the end of history, save the future as a branch
        if self.cursor < self.history.len() && self.config.enable_tree {
            let future = self.history.drain(self.cursor..).collect::<Vec<_>>();
            if !future.is_empty() {
                let branch_id = self.next_branch;
                self.next_branch += 1;
                self.branches.insert((self.cursor, branch_id), future);
            }
        } else {
            // Discard redo stack
            self.history.truncate(self.cursor);
        }

        let entry = HistoryEntry {
            command,
            timestamp: timestamp_secs(),
            branch: self.current_branch,
        };

        self.history.push(entry);
        self.cursor += 1;
        self.total_memory += mem;

        self.enforce_limits();
    }

    /// Undo the last command. Returns the description of what was undone.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the undo application fails.
    pub fn undo(&mut self, buf: &mut Vec<u8>) -> Result<Option<String>, String> {
        if self.cursor == 0 {
            return Ok(None);
        }
        self.cursor -= 1;
        let entry = &self.history[self.cursor];
        let desc = entry.command.description();
        let cmd = entry.command.clone();
        cmd.undo(buf)?;
        Ok(Some(desc))
    }

    /// Redo the next command.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the redo application fails.
    pub fn redo(&mut self, buf: &mut Vec<u8>) -> Result<Option<String>, String> {
        if self.cursor >= self.history.len() {
            return Ok(None);
        }
        let entry = &self.history[self.cursor];
        let desc = entry.command.description();
        let cmd = entry.command.clone();
        cmd.apply(buf)?;
        self.cursor += 1;
        Ok(Some(desc))
    }

    /// Undo all commands that touched bytes within `range`.
    /// Commands outside the range are left intact.
    ///
    /// # Errors
    ///
    /// Returns `Err` if any undo application fails.
    pub fn undo_in_range(
        &mut self,
        range: std::ops::Range<usize>,
        buf: &mut Vec<u8>,
    ) -> Result<usize, String> {
        let mut undone = 0usize;
        // Walk backwards through applied history
        let mut i = self.cursor;
        while i > 0 {
            i -= 1;
            let affected = self.history[i].command.affected_range();
            let overlaps = affected.is_some_and(|r| r.start < range.end && r.end > range.start);
            if overlaps {
                self.history[i].command.clone().undo(buf)?;
                self.history.remove(i);
                self.cursor -= 1;
                undone += 1;
            }
        }
        Ok(undone)
    }

    /// Save a named checkpoint at the current position.
    pub fn save_checkpoint(&mut self, name: impl Into<String>) {
        self.checkpoints.push(Checkpoint {
            name: name.into(),
            history_index: self.cursor,
            timestamp: timestamp_secs(),
        });
    }

    /// Restore a named checkpoint, undoing/redoing as needed.
    ///
    /// # Errors
    ///
    /// Returns `Err` if any undo/redo application fails.
    pub fn restore_checkpoint(
        &mut self,
        name: &str,
        buf: &mut Vec<u8>,
    ) -> Result<bool, String> {
        let target = match self.checkpoints.iter().rev().find(|c| c.name == name) {
            Some(c) => c.history_index,
            None => return Ok(false),
        };

        // Undo back or redo forward
        while self.cursor > target {
            if self.undo(buf)?.is_none() {
                break;
            }
        }
        while self.cursor < target {
            if self.redo(buf)?.is_none() {
                break;
            }
        }
        Ok(true)
    }

    /// List all checkpoints.
    #[must_use]
    pub fn checkpoints(&self) -> &[Checkpoint] {
        &self.checkpoints
    }

    /// Whether there is anything to undo.
    #[must_use]
    pub const fn can_undo(&self) -> bool {
        self.cursor > 0
    }

    /// Whether there is anything to redo.
    #[must_use]
    pub const fn can_redo(&self) -> bool {
        self.cursor < self.history.len()
    }

    /// Number of steps available to undo.
    #[must_use]
    pub const fn undo_depth(&self) -> usize {
        self.cursor
    }

    /// Number of steps available to redo.
    #[must_use]
    pub const fn redo_depth(&self) -> usize {
        self.history.len() - self.cursor
    }

    /// Total memory used by the undo history.
    #[must_use]
    pub const fn memory_usage(&self) -> usize {
        self.total_memory
    }

    /// Clear all history (cannot be undone).
    pub fn clear(&mut self) {
        self.history.clear();
        self.cursor = 0;
        self.total_memory = 0;
        self.branches.clear();
        self.checkpoints.clear();
    }

    /// List the recent history (up to `n` entries, most-recent first).
    #[must_use]
    pub fn recent_history(&self, n: usize) -> Vec<&HistoryEntry> {
        self.history[..self.cursor]
            .iter()
            .rev()
            .take(n)
            .collect()
    }

    /// Available undo tree branches at the current cursor position.
    #[must_use]
    pub fn available_branches(&self) -> Vec<u32> {
        self.branches
            .keys()
            .filter(|(pos, _)| *pos == self.cursor)
            .map(|(_, bid)| *bid)
            .collect()
    }

    /// Switch to a specific undo-tree branch.
    ///
    /// # Errors
    ///
    /// Currently infallible; reserved for future use.
    pub fn switch_branch(
        &mut self,
        branch_id: u32,
        _buf: &mut Vec<u8>,
    ) -> Result<bool, String> {
        let key = (self.cursor, branch_id);
        let Some(future) = self.branches.remove(&key) else {
            return Ok(false);
        };

        // Save current future as a new branch
        let current_future = self.history.drain(self.cursor..).collect::<Vec<_>>();
        if !current_future.is_empty() {
            let new_bid = self.next_branch;
            self.next_branch += 1;
            self.branches.insert((self.cursor, new_bid), current_future);
        }

        // Append the branch future
        for entry in future {
            self.history.push(entry);
        }

        self.current_branch = branch_id;
        Ok(true)
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn enforce_limits(&mut self) {
        // Enforce step limit
        if let Some(max) = self.config.max_steps {
            while self.history.len() > max {
                let removed = self.history.remove(0);
                self.total_memory = self.total_memory.saturating_sub(removed.command.memory_size());
                if self.cursor > 0 {
                    self.cursor -= 1;
                }
            }
        }

        // Enforce memory limit
        if let Some(max_mem) = self.config.max_memory_bytes {
            while self.total_memory > max_mem && !self.history.is_empty() {
                let removed = self.history.remove(0);
                self.total_memory = self.total_memory.saturating_sub(removed.command.memory_size());
                if self.cursor > 0 {
                    self.cursor -= 1;
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CommandBuilder — convenience builder for grouped commands
// ─────────────────────────────────────────────────────────────────────────────

/// Builds a [`EditCommand::Group`] from individual operations.
#[derive(Debug, Default)]
pub struct CommandBuilder {
    commands: Vec<EditCommand>,
    description: String,
}

impl CommandBuilder {
    #[must_use]
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            commands: vec![],
            description: description.into(),
        }
    }

    #[must_use] 
    pub fn write_byte(mut self, offset: usize, old: u8, new: u8) -> Self {
        self.commands.push(EditCommand::WriteByte {
            offset,
            old_value: old,
            new_value: new,
        });
        self
    }

    #[must_use] 
    pub fn write_range(
        mut self,
        offset: usize,
        old_bytes: Vec<u8>,
        new_bytes: Vec<u8>,
    ) -> Self {
        self.commands.push(EditCommand::WriteRange {
            offset,
            old_bytes,
            new_bytes,
        });
        self
    }

    #[must_use] 
    pub fn fill(
        mut self,
        offset: usize,
        old_bytes: Vec<u8>,
        fill_byte: u8,
    ) -> Self {
        let length = old_bytes.len();
        self.commands.push(EditCommand::Fill {
            offset,
            length,
            old_bytes,
            fill_byte,
        });
        self
    }

    /// Build the grouped command.
    #[must_use]
    pub fn build(self) -> EditCommand {
        EditCommand::Group {
            description: self.description,
            commands: self.commands,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn timestamp_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_buf(data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    #[test]
    fn write_undo_redo() {
        let mut buf = make_buf(b"AAABBB");
        let mut um = UndoManager::default();

        let cmd = EditCommand::WriteByte {
            offset: 2,
            old_value: b'A',
            new_value: b'X',
        };
        um.execute(cmd, &mut buf).unwrap();
        assert_eq!(buf[2], b'X');

        um.undo(&mut buf).unwrap();
        assert_eq!(buf[2], b'A');

        um.redo(&mut buf).unwrap();
        assert_eq!(buf[2], b'X');
    }

    #[test]
    fn fill_undo() {
        let mut buf = make_buf(b"AAAAAA");
        let mut um = UndoManager::default();
        let cmd = EditCommand::Fill {
            offset: 2,
            length: 3,
            old_bytes: buf[2..5].to_vec(),
            fill_byte: 0xFF,
        };
        um.execute(cmd, &mut buf).unwrap();
        assert_eq!(&buf[2..5], &[0xFF, 0xFF, 0xFF]);
        um.undo(&mut buf).unwrap();
        assert_eq!(&buf[2..5], b"AAA");
    }

    #[test]
    fn checkpoint_restore() {
        let mut buf = make_buf(b"hello");
        let mut um = UndoManager::default();

        um.save_checkpoint("initial");
        let cmd = EditCommand::WriteByte {
            offset: 0,
            old_value: b'h',
            new_value: b'H',
        };
        um.execute(cmd, &mut buf).unwrap();
        assert_eq!(buf[0], b'H');

        um.restore_checkpoint("initial", &mut buf).unwrap();
        assert_eq!(buf[0], b'h');
    }

    #[test]
    fn group_command() {
        let mut buf = make_buf(b"AABBCC");
        let mut um = UndoManager::default();
        let cmd = CommandBuilder::new("swap A->X")
            .write_byte(0, b'A', b'X')
            .write_byte(1, b'A', b'X')
            .build();
        um.execute(cmd, &mut buf).unwrap();
        assert_eq!(&buf[..2], b"XX");
        um.undo(&mut buf).unwrap();
        assert_eq!(&buf[..2], b"AA");
    }

    #[test]
    fn memory_limit_enforced() {
        let config = UndoConfig {
            max_steps: Some(3),
            max_memory_bytes: None,
            enable_tree: false,
        };
        let mut um = UndoManager::new(config);
        let mut buf = make_buf(b"AAAAAAAAAA");
        for i in 0..10usize {
            let cmd = EditCommand::WriteByte {
                offset: i % 10,
                old_value: buf[i % 10],
                new_value: i as u8,
            };
            um.execute(cmd, &mut buf).unwrap();
        }
        assert!(um.undo_depth() <= 3);
    }
}
