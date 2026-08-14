//! `rustre-hex` — hex editor core subsystem.
//!
//! Provides a production-ready hex editor data model with full undo/redo,
//! multiple cursors, clipboard operations, a find/replace engine, byte
//! insertion helpers, and selection ranges.
//!
//! # Structs
//! - [`EditBuffer`]       — mutable byte buffer with undo/redo
//! - [`UndoHistory`]      — undo stack manager
//! - [`RedoHistory`]      — redo stack manager
//! - [`SelectionRange`]   — a byte-level selection with an optional anchor
//! - [`ClipboardOps`]     — cut / copy / paste into an `EditBuffer`
//! - [`FindReplaceEngine`]— batch find & replace with multiple modes
//! - [`ByteInserter`]     — typed / aligned byte insertion helpers
//! - [`HexEditorCore`]    — top-level coordinator combining all subsystems

use std::collections::VecDeque;
use std::ops::Range;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use crate::{Edit, HexBuffer};
use crate::{HexError, kmp_search};

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from the hex editor core.
#[derive(Debug, Error)]
pub enum EditorError {
    #[error("offset {0} out of bounds (buffer length {1})")]
    OutOfBounds(usize, usize),
    #[error("invalid range {0}..{1}")]
    InvalidRange(usize, usize),
    #[error("clipboard is empty")]
    ClipboardEmpty,
    #[error("undo history is empty")]
    UndoEmpty,
    #[error("redo history is empty")]
    RedoEmpty,
    #[error("search returned no results")]
    NoResults,
    #[error("invalid encoding: {0}")]
    Encoding(String),
    #[error("buffer is empty")]
    EmptyBuffer,
    #[error("hex error: {0}")]
    Hex(#[from] HexError),
}

// ─────────────────────────────────────────────────────────────────────────────
// EditCommand
// ─────────────────────────────────────────────────────────────────────────────

/// An atomic editor command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EditCommand {
    /// Write bytes at offset (overwrites).
    Write {
        offset: usize,
        old: Vec<u8>,
        new: Vec<u8>,
    },
    /// Insert bytes at offset (shifts following bytes right).
    Insert { offset: usize, bytes: Vec<u8> },
    /// Delete bytes from offset.
    Delete { offset: usize, bytes: Vec<u8> },
    /// Fill a range with a repeating pattern.
    Fill {
        offset: usize,
        old: Vec<u8>,
        pattern: Vec<u8>,
    },
    /// XOR a range with a key.
    Xor {
        offset: usize,
        old: Vec<u8>,
        key: Vec<u8>,
    },
}

impl EditCommand {
    /// Compute the inverse command (for undo).
    #[must_use]
    pub fn inverse(&self) -> Self {
        match self {
            Self::Write { offset, old, new } => Self::Write {
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
            Self::Fill {
                offset,
                old,
                pattern,
            } => Self::Write {
                offset: *offset,
                old: pattern.clone(),
                new: old.clone(),
            },
            Self::Xor { offset, old, key } => Self::Xor {
                offset: *offset,
                old: key.clone(),
                key: old.clone(),
            },
        }
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Write { .. } => "write",
            Self::Insert { .. } => "insert",
            Self::Delete { .. } => "delete",
            Self::Fill { .. } => "fill",
            Self::Xor { .. } => "xor",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UndoHistory
// ─────────────────────────────────────────────────────────────────────────────

/// Manages the undo stack.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct UndoHistory {
    stack: VecDeque<EditCommand>,
    max_depth: usize,
    pub total_undone: u64,
}

impl UndoHistory {
    #[must_use]
    pub fn new(max_depth: usize) -> Self {
        Self {
            stack: VecDeque::new(),
            max_depth: max_depth.max(1),
            total_undone: 0,
        }
    }

    pub fn push(&mut self, cmd: EditCommand) {
        self.stack.push_back(cmd);
        if self.stack.len() > self.max_depth {
            self.stack.pop_front();
        }
    }

    pub fn pop(&mut self) -> Option<EditCommand> {
        let cmd = self.stack.pop_back();
        if cmd.is_some() {
            self.total_undone += 1;
        }
        cmd
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.stack.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    pub fn clear(&mut self) {
        self.stack.clear();
    }

    /// Peek at the most recent command without removing it.
    #[must_use]
    pub fn peek(&self) -> Option<&EditCommand> {
        self.stack.back()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RedoHistory
// ─────────────────────────────────────────────────────────────────────────────

/// Manages the redo stack.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RedoHistory {
    stack: VecDeque<EditCommand>,
    max_depth: usize,
    pub total_redone: u64,
}

impl RedoHistory {
    #[must_use]
    pub fn new(max_depth: usize) -> Self {
        Self {
            stack: VecDeque::new(),
            max_depth: max_depth.max(1),
            total_redone: 0,
        }
    }

    pub fn push(&mut self, cmd: EditCommand) {
        self.stack.push_back(cmd);
        if self.stack.len() > self.max_depth {
            self.stack.pop_front();
        }
    }

    pub fn pop(&mut self) -> Option<EditCommand> {
        let cmd = self.stack.pop_back();
        if cmd.is_some() {
            self.total_redone += 1;
        }
        cmd
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.stack.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    pub fn clear(&mut self) {
        self.stack.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EditBuffer
// ─────────────────────────────────────────────────────────────────────────────

/// Mutable byte buffer with integrated undo/redo.
#[derive(Debug)]
pub struct EditBuffer {
    pub data: Vec<u8>,
    pub undo: UndoHistory,
    pub redo: RedoHistory,
    pub modified: bool,
    pub total_edits: u64,
}

impl EditBuffer {
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            undo: UndoHistory::new(1000),
            redo: RedoHistory::new(1000),
            modified: false,
            total_edits: 0,
        }
    }

    #[must_use]
    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Write bytes at `offset` (overwrite, no resize).
    ///
    /// # Errors
    ///
    /// Returns [`EditorError::OutOfBounds`] if `offset` exceeds the buffer length.
    pub fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), EditorError> {
        if offset > self.data.len() {
            return Err(EditorError::OutOfBounds(offset, self.data.len()));
        }
        let end = (offset + bytes.len()).min(self.data.len());
        let len = end - offset;
        let old = self.data[offset..end].to_vec();
        let new = bytes[..len].to_vec();
        self.data[offset..end].copy_from_slice(&new);
        self.undo.push(EditCommand::Write { offset, old, new });
        self.redo.clear();
        self.modified = true;
        self.total_edits += 1;
        Ok(())
    }

    /// Insert bytes at `offset`.
    ///
    /// # Errors
    ///
    /// Returns [`EditorError::OutOfBounds`] if `offset` exceeds the buffer length.
    pub fn insert(&mut self, offset: usize, bytes: &[u8]) -> Result<(), EditorError> {
        if offset > self.data.len() {
            return Err(EditorError::OutOfBounds(offset, self.data.len()));
        }
        self.data.splice(offset..offset, bytes.iter().copied());
        self.undo.push(EditCommand::Insert {
            offset,
            bytes: bytes.to_vec(),
        });
        self.redo.clear();
        self.modified = true;
        self.total_edits += 1;
        Ok(())
    }

    /// Delete `len` bytes starting at `offset`.
    ///
    /// # Errors
    ///
    /// Returns [`EditorError::OutOfBounds`] if `offset` exceeds the buffer length.
    pub fn delete(&mut self, offset: usize, len: usize) -> Result<(), EditorError> {
        if offset > self.data.len() {
            return Err(EditorError::OutOfBounds(offset, self.data.len()));
        }
        let end = (offset + len).min(self.data.len());
        let removed: Vec<u8> = self.data.drain(offset..end).collect();
        self.undo.push(EditCommand::Delete {
            offset,
            bytes: removed,
        });
        self.redo.clear();
        self.modified = true;
        self.total_edits += 1;
        Ok(())
    }

    /// Fill `range` with a repeating `pattern`.
    ///
    /// # Errors
    ///
    /// Returns [`EditorError::InvalidRange`] if the range is invalid, or
    /// [`EditorError::EmptyBuffer`] if `pattern` is empty.
    pub fn fill(&mut self, range: Range<usize>, pattern: &[u8]) -> Result<(), EditorError> {
        if range.start > range.end || range.end > self.data.len() {
            return Err(EditorError::InvalidRange(range.start, range.end));
        }
        if pattern.is_empty() {
            return Err(EditorError::EmptyBuffer);
        }
        let len = range.len();
        let old = self.data[range.clone()].to_vec();
        let new: Vec<u8> = (0..len).map(|i| pattern[i % pattern.len()]).collect();
        self.data[range.clone()].copy_from_slice(&new);
        self.undo.push(EditCommand::Fill {
            offset: range.start,
            old,
            pattern: new,
        });
        self.redo.clear();
        self.modified = true;
        self.total_edits += 1;
        Ok(())
    }

    /// XOR `range` with a repeating `key`.
    ///
    /// # Errors
    ///
    /// Returns [`EditorError::InvalidRange`] if the range is invalid, or
    /// [`EditorError::EmptyBuffer`] if `key` is empty.
    pub fn xor(&mut self, range: Range<usize>, key: &[u8]) -> Result<(), EditorError> {
        if range.start > range.end || range.end > self.data.len() {
            return Err(EditorError::InvalidRange(range.start, range.end));
        }
        if key.is_empty() {
            return Err(EditorError::EmptyBuffer);
        }
        let old = self.data[range.clone()].to_vec();
        let new: Vec<u8> = old
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();
        self.data[range.clone()].copy_from_slice(&new);
        self.undo.push(EditCommand::Xor {
            offset: range.start,
            old,
            key: key.to_vec(),
        });
        self.redo.clear();
        self.modified = true;
        self.total_edits += 1;
        Ok(())
    }

    /// Undo the last edit.
    ///
    /// # Errors
    ///
    /// Returns [`EditorError::UndoEmpty`] if there is nothing to undo.
    pub fn undo(&mut self) -> Result<(), EditorError> {
        let cmd = self.undo.pop().ok_or(EditorError::UndoEmpty)?;
        self.apply_inverse(&cmd);
        self.redo.push(cmd);
        Ok(())
    }

    /// Redo the last undone edit.
    ///
    /// # Errors
    ///
    /// Returns [`EditorError::RedoEmpty`] if there is nothing to redo.
    pub fn redo(&mut self) -> Result<(), EditorError> {
        let cmd = self.redo.pop().ok_or(EditorError::RedoEmpty)?;
        self.apply_command(&cmd)?;
        Ok(())
    }

    fn apply_inverse(&mut self, cmd: &EditCommand) {
        match cmd {
            EditCommand::Write { offset, old, .. }
            | EditCommand::Fill { offset, old, .. }
            | EditCommand::Xor { offset, old, .. } => {
                let end = (*offset + old.len()).min(self.data.len());
                let len = end - offset;
                self.data[*offset..end].copy_from_slice(&old[..len]);
            }
            EditCommand::Insert { offset, bytes } => {
                let end = (*offset + bytes.len()).min(self.data.len());
                self.data.drain(*offset..end);
            }
            EditCommand::Delete { offset, bytes } => {
                self.data.splice(*offset..*offset, bytes.iter().copied());
            }
        }
    }

    fn apply_command(&mut self, cmd: &EditCommand) -> Result<(), EditorError> {
        match cmd {
            EditCommand::Write { offset, new, .. } => self.write(*offset, new),
            EditCommand::Insert { offset, bytes } => self.insert(*offset, bytes),
            EditCommand::Delete { offset, bytes } => self.delete(*offset, bytes.len()),
            EditCommand::Fill {
                offset,
                pattern,
                old,
            } => {
                let end = offset.checked_add(old.len())
                    .ok_or(EditorError::OutOfBounds(*offset, self.data.len()))?;
                self.fill(*offset..end, pattern)
            }
            EditCommand::Xor { offset, key, old } => {
                let end = offset.checked_add(old.len())
                    .ok_or(EditorError::OutOfBounds(*offset, self.data.len()))?;
                self.xor(*offset..end, key)
            }
        }
    }

    /// Reset modified flag (save point).
    pub const fn mark_saved(&mut self) {
        self.modified = false;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SelectionRange
// ─────────────────────────────────────────────────────────────────────────────

/// A byte-level selection with an optional anchor for extending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SelectionRange {
    /// Primary cursor byte offset.
    pub cursor: usize,
    /// Selection anchor (selection spans `min(cursor,anchor)..=max(cursor,anchor)`).
    pub anchor: Option<usize>,
}

impl SelectionRange {
    #[must_use]
    pub const fn new(cursor: usize) -> Self {
        Self {
            cursor,
            anchor: None,
        }
    }

    #[must_use]
    pub const fn with_anchor(cursor: usize, anchor: usize) -> Self {
        Self {
            cursor,
            anchor: Some(anchor),
        }
    }

    /// Whether there is an active selection.
    #[must_use]
    pub const fn has_selection(&self) -> bool {
        self.anchor.is_some()
    }

    /// Start of the selected range (inclusive).
    #[must_use]
    pub fn start(&self) -> usize {
        self.anchor.map_or(self.cursor, |a| self.cursor.min(a))
    }

    /// End of the selected range (exclusive).
    #[must_use]
    pub fn end(&self) -> usize {
        self.anchor.map_or_else(|| self.cursor + 1, |a| self.cursor.max(a) + 1)
    }

    /// Range `[start, end)`.
    #[must_use]
    pub fn range(&self) -> Range<usize> {
        self.start()..self.end()
    }

    /// Length of selection in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.end() - self.start()
    }

    /// Returns `true` when [`len`](Self::len) is zero.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Extend selection to include `new_cursor`.
    pub const fn extend_to(&mut self, new_cursor: usize) {
        if self.anchor.is_none() {
            self.anchor = Some(self.cursor);
        }
        self.cursor = new_cursor;
    }

    /// Clear selection (move cursor, drop anchor).
    pub const fn move_to(&mut self, offset: usize) {
        self.cursor = offset;
        self.anchor = None;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Clipboard
// ─────────────────────────────────────────────────────────────────────────────

/// In-memory clipboard for cut/copy/paste operations.
#[derive(Debug, Default, Clone)]
pub struct Clipboard {
    pub content: Vec<u8>,
    pub history: VecDeque<Vec<u8>>,
    max_history: usize,
}

impl Clipboard {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            content: Vec::new(),
            history: VecDeque::new(),
            max_history: 32,
        }
    }

    pub fn set(&mut self, data: Vec<u8>) {
        if !self.content.is_empty() {
            self.history.push_back(self.content.clone());
            if self.history.len() > self.max_history {
                self.history.pop_front();
            }
        }
        self.content = data;
    }

    #[must_use]
    pub fn get(&self) -> &[u8] {
        &self.content
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.content.is_empty()
    }

    #[must_use]
    pub fn history_len(&self) -> usize {
        self.history.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ClipboardOps
// ─────────────────────────────────────────────────────────────────────────────

/// Provides cut / copy / paste operations on an [`EditBuffer`].
pub struct ClipboardOps {
    pub clipboard: Clipboard,
}

impl ClipboardOps {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            clipboard: Clipboard::new(),
        }
    }

    /// Copy bytes in `range` from `buf` to clipboard.
    ///
    /// # Errors
    ///
    /// Returns [`EditorError::InvalidRange`] if the range is invalid.
    pub fn copy(&mut self, buf: &EditBuffer, range: Range<usize>) -> Result<(), EditorError> {
        if range.start > range.end || range.end > buf.data.len() {
            return Err(EditorError::InvalidRange(range.start, range.end));
        }
        self.clipboard.set(buf.data[range].to_vec());
        Ok(())
    }

    /// Cut bytes in `range` from `buf` to clipboard.
    ///
    /// # Errors
    ///
    /// Returns [`EditorError::InvalidRange`] if the range is invalid, or propagates errors from
    /// `copy` or `delete`.
    pub fn cut(&mut self, buf: &mut EditBuffer, range: Range<usize>) -> Result<(), EditorError> {
        self.copy(buf, range.clone())?;
        buf.delete(range.start, range.len())?;
        Ok(())
    }

    /// Paste clipboard content at `offset` in `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`EditorError::ClipboardEmpty`] if the clipboard is empty, or propagates
    /// insert errors.
    pub fn paste(&self, buf: &mut EditBuffer, offset: usize) -> Result<(), EditorError> {
        if self.clipboard.is_empty() {
            return Err(EditorError::ClipboardEmpty);
        }
        buf.insert(offset, self.clipboard.get())?;
        Ok(())
    }

    /// Paste by overwriting at `offset` in `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`EditorError::ClipboardEmpty`] if the clipboard is empty, or propagates
    /// write errors.
    pub fn paste_overwrite(&self, buf: &mut EditBuffer, offset: usize) -> Result<(), EditorError> {
        if self.clipboard.is_empty() {
            return Err(EditorError::ClipboardEmpty);
        }
        buf.write(offset, self.clipboard.get())?;
        Ok(())
    }
}

impl Default for ClipboardOps {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FindMatch
// ─────────────────────────────────────────────────────────────────────────────

/// A single search match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindMatch {
    pub offset: usize,
    pub len: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// FindReplaceEngine
// ─────────────────────────────────────────────────────────────────────────────

/// Batch find & replace engine with KMP search and wildcard support.
pub struct FindReplaceEngine {
    pub last_matches: Vec<FindMatch>,
    pub total_replacements: u64,
    pub total_searches: u64,
}

impl FindReplaceEngine {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last_matches: Vec::new(),
            total_replacements: 0,
            total_searches: 0,
        }
    }

    /// Find all occurrences of `needle` in `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`EditorError::NoResults`] if `needle` is empty or not found.
    pub fn find_all(
        &mut self,
        buf: &EditBuffer,
        needle: &[u8],
    ) -> Result<Vec<FindMatch>, EditorError> {
        if needle.is_empty() {
            return Err(EditorError::NoResults);
        }
        self.total_searches += 1;
        let offsets = kmp_search(&buf.data, needle);
        if offsets.is_empty() {
            return Err(EditorError::NoResults);
        }
        let matches: Vec<FindMatch> = offsets
            .into_iter()
            .map(|o| FindMatch {
                offset: o,
                len: needle.len(),
            })
            .collect();
        self.last_matches.clone_from(&matches);
        Ok(matches)
    }

    /// Find all occurrences of a hex-wildcard pattern (e.g. `"DE AD ?? EF"`).
    ///
    /// # Errors
    ///
    /// Returns [`EditorError::NoResults`] if the pattern is empty or not found, or
    /// [`EditorError::Encoding`] if a token is not a valid hex byte or wildcard.
    pub fn find_hex_pattern(
        &mut self,
        buf: &EditBuffer,
        pattern: &str,
    ) -> Result<Vec<FindMatch>, EditorError> {
        self.total_searches += 1;
        let tokens: Vec<&str> = pattern.split_whitespace().collect();
        if tokens.is_empty() {
            return Err(EditorError::NoResults);
        }
        let mut pat: Vec<Option<u8>> = Vec::with_capacity(tokens.len());
        for t in &tokens {
            if *t == "??" || *t == "?" {
                pat.push(None);
            } else if t.len() == 2 && t.is_ascii() {
                let hi = u8::from_str_radix(&t[..1], 16)
                    .map_err(|_| EditorError::Encoding(t.to_string()))?;
                let lo = u8::from_str_radix(&t[1..], 16)
                    .map_err(|_| EditorError::Encoding(t.to_string()))?;
                pat.push(Some((hi << 4) | lo));
            } else {
                return Err(EditorError::Encoding(format!("invalid token: {t}")));
            }
        }
        let pat_len = pat.len();
        if buf.data.len() < pat_len {
            return Err(EditorError::NoResults);
        }
        let mut matches = Vec::new();
        'outer: for start in 0..=(buf.data.len() - pat_len) {
            for (i, slot) in pat.iter().enumerate() {
                if let Some(b) = slot
                    && buf.data[start + i] != *b {
                        continue 'outer;
                    }
            }
            matches.push(FindMatch {
                offset: start,
                len: pat_len,
            });
        }
        if matches.is_empty() {
            return Err(EditorError::NoResults);
        }
        self.last_matches.clone_from(&matches);
        Ok(matches)
    }

    /// Replace all occurrences of `needle` with `replacement`.  Returns count.
    ///
    /// # Errors
    ///
    /// Returns errors propagated from `find_all` or buffer write/delete/insert operations.
    pub fn replace_all(
        &mut self,
        buf: &mut EditBuffer,
        needle: &[u8],
        replacement: &[u8],
    ) -> Result<usize, EditorError> {
        let matches = self.find_all(buf, needle)?;
        let count = matches.len();
        // Apply back-to-front to preserve earlier offsets.
        for m in matches.iter().rev() {
            let end = m.offset + m.len;
            // Skip any stale match whose tail no longer lies within the buffer
            // (e.g. when the buffer was truncated between `find_all` and now).
            if end > buf.len() {
                continue;
            }
            let new = replacement.to_vec();
            if new.len() == m.len {
                buf.write(m.offset, &new)?;
            } else {
                buf.delete(m.offset, m.len)?;
                buf.insert(m.offset, &new)?;
            }
        }
        self.total_replacements += count as u64;
        Ok(count)
    }

    /// Replace only the first occurrence.
    ///
    /// # Errors
    ///
    /// Returns errors propagated from `find_all` or buffer write/delete/insert operations.
    pub fn replace_first(
        &mut self,
        buf: &mut EditBuffer,
        needle: &[u8],
        replacement: &[u8],
    ) -> Result<bool, EditorError> {
        let matches = self.find_all(buf, needle)?;
        if let Some(m) = matches.into_iter().next() {
            let new = replacement.to_vec();
            if new.len() == m.len {
                buf.write(m.offset, &new)?;
            } else {
                buf.delete(m.offset, m.len)?;
                buf.insert(m.offset, &new)?;
            }
            self.total_replacements += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Find next occurrence after `after_offset`.
    ///
    /// # Errors
    ///
    /// Returns [`EditorError::NoResults`] if no occurrence exists after `after_offset`.
    pub fn find_next(
        &mut self,
        buf: &EditBuffer,
        needle: &[u8],
        after_offset: usize,
    ) -> Result<FindMatch, EditorError> {
        let all = self.find_all(buf, needle)?;
        all.into_iter()
            .find(|m| m.offset > after_offset)
            .ok_or(EditorError::NoResults)
    }

    /// Find previous occurrence before `before_offset`.
    ///
    /// # Errors
    ///
    /// Returns [`EditorError::NoResults`] if no occurrence exists before `before_offset`.
    pub fn find_prev(
        &mut self,
        buf: &EditBuffer,
        needle: &[u8],
        before_offset: usize,
    ) -> Result<FindMatch, EditorError> {
        let all = self.find_all(buf, needle)?;
        all.into_iter().rfind(|m| m.offset < before_offset)
            .ok_or(EditorError::NoResults)
    }
}

impl Default for FindReplaceEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ByteInserter
// ─────────────────────────────────────────────────────────────────────────────

/// Typed / aligned byte-insertion helpers.
pub struct ByteInserter;

impl ByteInserter {
    /// Insert a `u8` at `offset`.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`EditBuffer::insert`].
    pub fn insert_u8(buf: &mut EditBuffer, offset: usize, value: u8) -> Result<(), EditorError> {
        buf.insert(offset, &[value])
    }

    /// Insert a `u16` (LE) at `offset`.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`EditBuffer::insert`].
    pub fn insert_u16_le(
        buf: &mut EditBuffer,
        offset: usize,
        value: u16,
    ) -> Result<(), EditorError> {
        buf.insert(offset, &value.to_le_bytes())
    }

    /// Insert a `u16` (BE) at `offset`.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`EditBuffer::insert`].
    pub fn insert_u16_be(
        buf: &mut EditBuffer,
        offset: usize,
        value: u16,
    ) -> Result<(), EditorError> {
        buf.insert(offset, &value.to_be_bytes())
    }

    /// Insert a `u32` (LE) at `offset`.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`EditBuffer::insert`].
    pub fn insert_u32_le(
        buf: &mut EditBuffer,
        offset: usize,
        value: u32,
    ) -> Result<(), EditorError> {
        buf.insert(offset, &value.to_le_bytes())
    }

    /// Insert a `u32` (BE) at `offset`.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`EditBuffer::insert`].
    pub fn insert_u32_be(
        buf: &mut EditBuffer,
        offset: usize,
        value: u32,
    ) -> Result<(), EditorError> {
        buf.insert(offset, &value.to_be_bytes())
    }

    /// Insert a `u64` (LE) at `offset`.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`EditBuffer::insert`].
    pub fn insert_u64_le(
        buf: &mut EditBuffer,
        offset: usize,
        value: u64,
    ) -> Result<(), EditorError> {
        buf.insert(offset, &value.to_le_bytes())
    }

    /// Insert a null-terminated C string.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`EditBuffer::insert`].
    pub fn insert_cstr(buf: &mut EditBuffer, offset: usize, s: &str) -> Result<(), EditorError> {
        let mut bytes = s.as_bytes().to_vec();
        bytes.push(0); // null terminator
        buf.insert(offset, &bytes)
    }

    /// Overwrite a `u32` (LE) at `offset`.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`EditBuffer::write`].
    pub fn write_u32_le(
        buf: &mut EditBuffer,
        offset: usize,
        value: u32,
    ) -> Result<(), EditorError> {
        buf.write(offset, &value.to_le_bytes())
    }

    /// Overwrite a `u64` (LE) at `offset`.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`EditBuffer::write`].
    pub fn write_u64_le(
        buf: &mut EditBuffer,
        offset: usize,
        value: u64,
    ) -> Result<(), EditorError> {
        buf.write(offset, &value.to_le_bytes())
    }

    /// Align `offset` up to `alignment` by inserting zero padding.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`EditBuffer::insert`].
    pub fn align_up(
        buf: &mut EditBuffer,
        offset: usize,
        alignment: usize,
    ) -> Result<(), EditorError> {
        if alignment == 0 || alignment == 1 {
            return Ok(());
        }
        let pad = (alignment - (offset % alignment)) % alignment;
        if pad > 0 {
            buf.insert(offset, &vec![0u8; pad])?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexEditorCore
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level hex editor coordinator.
///
/// Combines `EditBuffer`, `ClipboardOps`, `FindReplaceEngine`, and
/// `SelectionRange` into a single coherent editing session.
pub struct HexEditorCore {
    pub buffer: EditBuffer,
    pub clipboard: ClipboardOps,
    pub finder: FindReplaceEngine,
    pub selection: SelectionRange,
    /// Virtual base address added to all displayed offsets.
    pub base_address: u64,
    /// Whether the editor is in insert mode (vs overwrite).
    pub insert_mode: bool,
}

impl HexEditorCore {
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            buffer: EditBuffer::new(data),
            clipboard: ClipboardOps::new(),
            finder: FindReplaceEngine::new(),
            selection: SelectionRange::default(),
            base_address: 0,
            insert_mode: false,
        }
    }

    /// Move cursor to `offset`.
    pub fn goto(&mut self, offset: usize) {
        self.selection
            .move_to(offset.min(self.buffer.len().saturating_sub(1)));
    }

    /// Select range `[start, end)`.
    pub fn select(&mut self, start: usize, end: usize) {
        let len = self.buffer.len();
        let s = start.min(len);
        let e = end.min(len);
        self.selection = if e <= s {
            SelectionRange::new(s)
        } else {
            SelectionRange::with_anchor(e - 1, s)
        };
    }

    /// Read bytes at current cursor.
    #[must_use]
    pub fn read_at_cursor(&self, len: usize) -> &[u8] {
        let off = self.selection.cursor;
        let end = (off + len).min(self.buffer.data.len());
        &self.buffer.data[off..end]
    }

    /// Write bytes at current cursor.
    ///
    /// # Errors
    ///
    /// Propagates errors from buffer insert or write operations.
    pub fn write_at_cursor(&mut self, bytes: &[u8]) -> Result<(), EditorError> {
        let offset = self.selection.cursor;
        if self.insert_mode {
            self.buffer.insert(offset, bytes)?;
        } else {
            self.buffer.write(offset, bytes)?;
        }
        self.selection.cursor = (offset + bytes.len()).min(self.buffer.len());
        Ok(())
    }

    /// Copy current selection to clipboard.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`ClipboardOps::copy`].
    pub fn copy_selection(&mut self) -> Result<(), EditorError> {
        if !self.selection.has_selection() {
            return Ok(());
        }
        let range = self.selection.range();
        self.clipboard.copy(&self.buffer, range)
    }

    /// Cut current selection.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`ClipboardOps::cut`].
    pub fn cut_selection(&mut self) -> Result<(), EditorError> {
        if !self.selection.has_selection() {
            return Ok(());
        }
        let range = self.selection.range();
        self.clipboard.cut(&mut self.buffer, range)
    }

    /// Paste at current cursor.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`ClipboardOps::paste`].
    pub fn paste(&mut self) -> Result<(), EditorError> {
        let offset = self.selection.cursor;
        self.clipboard.paste(&mut self.buffer, offset)
    }

    /// Undo.
    ///
    /// # Errors
    ///
    /// Returns [`EditorError::UndoEmpty`] if there is nothing to undo.
    pub fn undo(&mut self) -> Result<(), EditorError> {
        self.buffer.undo()
    }

    /// Redo.
    ///
    /// # Errors
    ///
    /// Returns [`EditorError::RedoEmpty`] if there is nothing to redo.
    pub fn redo(&mut self) -> Result<(), EditorError> {
        self.buffer.redo()
    }

    /// Find all occurrences of `needle`.
    ///
    /// # Errors
    ///
    /// Returns [`EditorError::NoResults`] if `needle` is empty or not found.
    pub fn find_all(&mut self, needle: &[u8]) -> Result<Vec<FindMatch>, EditorError> {
        self.finder.find_all(&self.buffer, needle)
    }

    /// Replace all.
    ///
    /// # Errors
    ///
    /// Returns errors propagated from search or buffer operations.
    pub fn replace_all(&mut self, needle: &[u8], replacement: &[u8]) -> Result<usize, EditorError> {
        self.finder
            .replace_all(&mut self.buffer, needle, replacement)
    }

    /// Virtual address at `offset`.
    #[must_use]
    pub fn va(&self, offset: usize) -> u64 {
        self.base_address
            .saturating_add(u64::try_from(offset).unwrap_or(u64::MAX))
    }

    /// Offset for virtual address.
    #[must_use]
    pub fn offset_for_va(&self, va: u64) -> Option<usize> {
        if va < self.base_address {
            return None;
        }
        let off = usize::try_from(va - self.base_address).ok()?;
        if off < self.buffer.len() {
            Some(off)
        } else {
            None
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn buf(data: &[u8]) -> EditBuffer {
        EditBuffer::new(data.to_vec())
    }

    // ── EditCommand ───────────────────────────────────────────────────────────

    #[test]
    fn edit_command_inverse_write() {
        let cmd = EditCommand::Write {
            offset: 0,
            old: vec![1],
            new: vec![2],
        };
        let inv = cmd.inverse();
        assert!(matches!(inv, EditCommand::Write { .. }));
        if let EditCommand::Write { old, new, .. } = inv {
            assert_eq!(old, vec![2]);
            assert_eq!(new, vec![1]);
        }
    }

    #[test]
    fn edit_command_inverse_insert_becomes_delete() {
        let cmd = EditCommand::Insert {
            offset: 0,
            bytes: vec![1, 2],
        };
        assert!(matches!(cmd.inverse(), EditCommand::Delete { .. }));
    }

    #[test]
    fn edit_command_inverse_delete_becomes_insert() {
        let cmd = EditCommand::Delete {
            offset: 0,
            bytes: vec![1, 2],
        };
        assert!(matches!(cmd.inverse(), EditCommand::Insert { .. }));
    }

    #[test]
    fn edit_command_name() {
        assert_eq!(
            EditCommand::Insert {
                offset: 0,
                bytes: vec![]
            }
            .name(),
            "insert"
        );
        assert_eq!(
            EditCommand::Delete {
                offset: 0,
                bytes: vec![]
            }
            .name(),
            "delete"
        );
        assert_eq!(
            EditCommand::Write {
                offset: 0,
                old: vec![],
                new: vec![]
            }
            .name(),
            "write"
        );
    }

    // ── UndoHistory ───────────────────────────────────────────────────────────

    #[test]
    fn undo_history_push_pop() {
        let mut h = UndoHistory::new(10);
        h.push(EditCommand::Insert {
            offset: 0,
            bytes: vec![1],
        });
        assert_eq!(h.len(), 1);
        assert!(h.pop().is_some());
        assert!(h.is_empty());
    }

    #[test]
    fn undo_history_max_depth() {
        let mut h = UndoHistory::new(3);
        for i in 0..5 {
            h.push(EditCommand::Insert {
                offset: i,
                bytes: vec![i as u8],
            });
        }
        assert_eq!(h.len(), 3);
    }

    #[test]
    fn undo_history_total_undone() {
        let mut h = UndoHistory::new(10);
        h.push(EditCommand::Insert {
            offset: 0,
            bytes: vec![1],
        });
        h.pop();
        assert_eq!(h.total_undone, 1);
    }

    // ── RedoHistory ───────────────────────────────────────────────────────────

    #[test]
    fn redo_history_push_pop() {
        let mut r = RedoHistory::new(10);
        r.push(EditCommand::Delete {
            offset: 0,
            bytes: vec![1],
        });
        assert!(!r.is_empty());
        assert!(r.pop().is_some());
        assert!(r.is_empty());
    }

    // ── EditBuffer ────────────────────────────────────────────────────────────

    #[test]
    fn edit_buffer_write() {
        let mut b = buf(&[0u8; 8]);
        b.write(2, &[0xDE, 0xAD]).unwrap();
        assert_eq!(&b.data[2..4], &[0xDE, 0xAD]);
        assert!(b.modified);
    }

    #[test]
    fn edit_buffer_insert() {
        let mut b = buf(&[1, 2, 3]);
        b.insert(1, &[0xAA, 0xBB]).unwrap();
        assert_eq!(b.data, vec![1, 0xAA, 0xBB, 2, 3]);
    }

    #[test]
    fn edit_buffer_delete() {
        let mut b = buf(&[1, 2, 3, 4, 5]);
        b.delete(1, 2).unwrap();
        assert_eq!(b.data, vec![1, 4, 5]);
    }

    #[test]
    fn edit_buffer_fill() {
        let mut b = buf(&[0u8; 8]);
        b.fill(2..6, &[0xFF]).unwrap();
        assert_eq!(&b.data[2..6], &[0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn edit_buffer_xor() {
        let mut b = buf(&[0xFFu8; 4]);
        b.xor(0..4, &[0x0F]).unwrap();
        assert!(b.data.iter().all(|&x| x == 0xF0));
    }

    #[test]
    fn edit_buffer_undo_write() {
        let mut b = buf(&[1, 2, 3]);
        b.write(0, &[0xFF]).unwrap();
        b.undo().unwrap();
        assert_eq!(b.data[0], 1);
    }

    #[test]
    fn edit_buffer_undo_insert() {
        let mut b = buf(&[1, 2, 3]);
        b.insert(1, &[0xAA]).unwrap();
        b.undo().unwrap();
        assert_eq!(b.data, vec![1, 2, 3]);
    }

    #[test]
    fn edit_buffer_redo() {
        let mut b = buf(&[1, 2, 3]);
        b.write(0, &[0xFF]).unwrap();
        b.undo().unwrap();
        b.redo().unwrap();
        assert_eq!(b.data[0], 0xFF);
    }

    #[test]
    fn edit_buffer_undo_empty_error() {
        let mut b = buf(&[1, 2]);
        assert!(matches!(b.undo().unwrap_err(), EditorError::UndoEmpty));
    }

    #[test]
    fn edit_buffer_out_of_bounds() {
        let mut b = buf(&[1, 2]);
        assert!(matches!(
            b.write(100, &[0]).unwrap_err(),
            EditorError::OutOfBounds(_, _)
        ));
    }

    // ── SelectionRange ────────────────────────────────────────────────────────

    #[test]
    fn selection_range_no_anchor() {
        let s = SelectionRange::new(5);
        assert!(!s.has_selection());
        assert_eq!(s.start(), 5);
        assert_eq!(s.end(), 6);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn selection_range_with_anchor() {
        let s = SelectionRange::with_anchor(8, 3);
        assert!(s.has_selection());
        assert_eq!(s.start(), 3);
        assert_eq!(s.end(), 9);
        assert_eq!(s.len(), 6);
    }

    #[test]
    fn selection_range_extend_to() {
        let mut s = SelectionRange::new(5);
        s.extend_to(9);
        assert!(s.has_selection());
        assert_eq!(s.start(), 5);
        assert_eq!(s.end(), 10);
    }

    #[test]
    fn selection_range_move_to() {
        let mut s = SelectionRange::with_anchor(8, 3);
        s.move_to(4);
        assert!(!s.has_selection());
        assert_eq!(s.cursor, 4);
    }

    // ── ClipboardOps ──────────────────────────────────────────────────────────

    #[test]
    fn clipboard_copy_and_paste() {
        let mut buf = buf(&[1, 2, 3, 4, 5]);
        let mut ops = ClipboardOps::new();
        ops.copy(&buf, 1..3).unwrap();
        assert_eq!(ops.clipboard.get(), &[2, 3]);
        ops.paste(&mut buf, 0).unwrap();
        assert_eq!(&buf.data[..2], &[2, 3]);
    }

    #[test]
    fn clipboard_cut() {
        let mut buf = buf(&[1, 2, 3, 4, 5]);
        let mut ops = ClipboardOps::new();
        ops.cut(&mut buf, 1..3).unwrap();
        assert_eq!(buf.data, vec![1, 4, 5]);
        assert_eq!(ops.clipboard.get(), &[2, 3]);
    }

    #[test]
    fn clipboard_paste_overwrite() {
        let mut buf = buf(&[0u8; 4]);
        let mut ops = ClipboardOps::new();
        ops.copy(&EditBuffer::new(vec![0xFF, 0xFE]), 0..2).unwrap();
        ops.paste_overwrite(&mut buf, 1).unwrap();
        assert_eq!(&buf.data[1..3], &[0xFF, 0xFE]);
    }

    #[test]
    fn clipboard_empty_paste_error() {
        let mut buf = buf(&[1, 2]);
        let ops = ClipboardOps::new();
        assert!(matches!(
            ops.paste(&mut buf, 0).unwrap_err(),
            EditorError::ClipboardEmpty
        ));
    }

    // ── FindReplaceEngine ─────────────────────────────────────────────────────

    #[test]
    fn find_all_exact() {
        let buf = buf(&[0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD]);
        let mut eng = FindReplaceEngine::new();
        let matches = eng.find_all(&buf, &[0xDE, 0xAD]).unwrap();
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].offset, 0);
        assert_eq!(matches[1].offset, 4);
    }

    #[test]
    fn find_no_match_error() {
        let buf = buf(&[1, 2, 3]);
        let mut eng = FindReplaceEngine::new();
        assert!(matches!(
            eng.find_all(&buf, &[0xFF]).unwrap_err(),
            EditorError::NoResults
        ));
    }

    #[test]
    fn replace_all() {
        let mut buf = buf(&[0xDE, 0xAD, 0xDE, 0xAD]);
        let mut eng = FindReplaceEngine::new();
        let count = eng
            .replace_all(&mut buf, &[0xDE, 0xAD], &[0xFF, 0xFF])
            .unwrap();
        assert_eq!(count, 2);
        assert_eq!(buf.data, vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn find_hex_pattern() {
        let buf = buf(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let mut eng = FindReplaceEngine::new();
        let matches = eng.find_hex_pattern(&buf, "DE ?? BE EF").unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].offset, 0);
    }

    #[test]
    fn find_next_after_offset() {
        let buf = buf(&[0xAA, 0xBB, 0xCC, 0xAA, 0xBB]);
        let mut eng = FindReplaceEngine::new();
        let m = eng.find_next(&buf, &[0xAA, 0xBB], 1).unwrap();
        assert_eq!(m.offset, 3);
    }

    #[test]
    fn find_prev_before_offset() {
        let buf = buf(&[0xAA, 0xBB, 0xCC, 0xAA, 0xBB]);
        let mut eng = FindReplaceEngine::new();
        let m = eng.find_prev(&buf, &[0xAA, 0xBB], 3).unwrap();
        assert_eq!(m.offset, 0);
    }

    // ── ByteInserter ──────────────────────────────────────────────────────────

    #[test]
    fn insert_u8() {
        let mut b = buf(&[1, 2, 3]);
        ByteInserter::insert_u8(&mut b, 1, 0xAA).unwrap();
        assert_eq!(b.data[1], 0xAA);
    }

    #[test]
    fn insert_u32_le() {
        let mut b = buf(&[0u8; 8]);
        ByteInserter::insert_u32_le(&mut b, 0, 0xDEAD_BEEF).unwrap();
        assert_eq!(&b.data[0..4], &0xDEAD_BEEFu32.to_le_bytes());
    }

    #[test]
    fn insert_cstr() {
        let mut b = EditBuffer::empty();
        ByteInserter::insert_cstr(&mut b, 0, "hello").unwrap();
        assert_eq!(&b.data[..6], b"hello\0");
    }

    #[test]
    fn write_u64_le() {
        let mut b = buf(&[0u8; 8]);
        ByteInserter::write_u64_le(&mut b, 0, 0xCAFE_BABE_DEAD_BEEF).unwrap();
        assert_eq!(&b.data[..8], &0xCAFE_BABE_DEAD_BEEFu64.to_le_bytes());
    }

    #[test]
    fn align_up_inserts_padding() {
        let mut b = buf(&[1, 2, 3]);
        ByteInserter::align_up(&mut b, 3, 4).unwrap();
        assert_eq!(b.len() % 4, 0);
    }

    // ── HexEditorCore ─────────────────────────────────────────────────────────

    #[test]
    fn editor_core_new() {
        let e = HexEditorCore::new(vec![1, 2, 3, 4]);
        assert_eq!(e.buffer.len(), 4);
        assert!(!e.insert_mode);
    }

    #[test]
    fn editor_core_goto() {
        let mut e = HexEditorCore::new(vec![0u8; 10]);
        e.goto(5);
        assert_eq!(e.selection.cursor, 5);
    }

    #[test]
    fn editor_core_write_at_cursor() {
        let mut e = HexEditorCore::new(vec![0u8; 8]);
        e.goto(2);
        e.write_at_cursor(&[0xAA, 0xBB]).unwrap();
        assert_eq!(&e.buffer.data[2..4], &[0xAA, 0xBB]);
    }

    #[test]
    fn editor_core_find_all() {
        let mut e = HexEditorCore::new(vec![0xDE, 0xAD, 0x00, 0xDE, 0xAD]);
        let m = e.find_all(&[0xDE, 0xAD]).unwrap();
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn editor_core_replace_all() {
        let mut e = HexEditorCore::new(vec![0xDE, 0xAD, 0xDE, 0xAD]);
        let n = e.replace_all(&[0xDE, 0xAD], &[0xFF, 0xFF]).unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn editor_core_undo_redo() {
        let mut e = HexEditorCore::new(vec![1, 2, 3]);
        e.write_at_cursor(&[0xFF]).unwrap();
        e.undo().unwrap();
        assert_eq!(e.buffer.data[0], 1);
        e.redo().unwrap();
        assert_eq!(e.buffer.data[0], 0xFF);
    }

    #[test]
    fn editor_core_va_and_offset() {
        let mut e = HexEditorCore::new(vec![0u8; 16]);
        e.base_address = 0x400000;
        assert_eq!(e.va(4), 0x400004);
        assert_eq!(e.offset_for_va(0x400004), Some(4));
        assert_eq!(e.offset_for_va(0x100000), None);
    }

    #[test]
    fn editor_core_copy_paste_selection() {
        let mut e = HexEditorCore::new(vec![1, 2, 3, 4, 5]);
        e.select(1, 3);
        e.copy_selection().unwrap();
        e.goto(0);
        e.paste().unwrap();
        assert_eq!(&e.buffer.data[0..2], &[2, 3]);
    }
}
