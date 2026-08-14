//! `rustre-hex` — Core hex editor data model and utilities.
//!
//! Provides `HexBuffer` with full undo/redo, search, typed reads,
//! diff, entropy analysis, struct-overlay support, multi-cursor editing,
//! block operations (fill, reverse, shift), bitwise transforms (XOR/AND/OR/NOT),
//! byte statistics, histogram, find/replace (literal, regex, hex pattern),
//! and structured data overlay.

pub mod hex_analysis;
pub mod hex_bookmarks;
pub mod hex_diff;
pub mod hex_disassembler;
pub mod hex_editor_core;
pub mod hex_search_engine;
pub mod hex_undo;
pub mod hex_patch_manager;
pub mod hex_bookmark_manager;
pub mod hex_undo_manager;
pub mod hex_selection;
pub mod hex_goto_dialog;

use std::collections::HashMap;
use std::ops::Range;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the hex module.
#[derive(Debug, Error)]
pub enum HexError {
    #[error("offset {0} is out of bounds (buffer length {1})")]
    OutOfBounds(usize, usize),
    #[error("invalid range {0}..{1}")]
    InvalidRange(usize, usize),
    #[error("regex error: {0}")]
    Regex(String),
    #[error("invalid encoding: {0}")]
    Encoding(String),
    #[error("buffer is empty")]
    EmptyBuffer,
    #[error("type read error at offset {0}: {1}")]
    TypeRead(usize, String),
    #[error("replace error: {0}")]
    Replace(String),
    #[error("cursor index {0} out of range")]
    CursorIndex(usize),
}

// ─────────────────────────────────────────────────────────────────────────────
// Encoding
// ─────────────────────────────────────────────────────────────────────────────

/// Character encodings understood by the hex buffer's string search.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Encoding {
    Utf8,
    Utf16Le,
    Utf16Be,
    Ascii,
    Latin1,
}

// ─────────────────────────────────────────────────────────────────────────────
// DataType
// ─────────────────────────────────────────────────────────────────────────────

/// Primitive and composite data types for struct-overlay reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataType {
    U8,
    U16Le,
    U16Be,
    U32Le,
    U32Be,
    U64Le,
    U64Be,
    I8,
    I16Le,
    I16Be,
    I32Le,
    I32Be,
    I64Le,
    I64Be,
    F32Le,
    F32Be,
    F64Le,
    F64Be,
    /// Raw byte slice of fixed length.
    Bytes(usize),
    /// Null-terminated UTF-8 / ASCII C string.
    CStr,
    /// UTF-16 string of `n` code units (bytes = n*2).
    Utf16(usize),
}

impl DataType {
    /// Returns the fixed byte size of the type, or `None` for variable-length types.
    #[must_use]
    pub const fn fixed_size(&self) -> Option<usize> {
        match self {
            Self::U8 | Self::I8 => Some(1),
            Self::U16Le | Self::U16Be | Self::I16Le | Self::I16Be => Some(2),
            Self::U32Le | Self::U32Be | Self::I32Le | Self::I32Be | Self::F32Le | Self::F32Be => {
                Some(4)
            }
            Self::U64Le | Self::U64Be | Self::I64Le | Self::I64Be | Self::F64Le | Self::F64Be => {
                Some(8)
            }
            Self::Bytes(n) => Some(*n),
            Self::Utf16(n) => n.checked_mul(2),
            Self::CStr => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypedValue
// ─────────────────────────────────────────────────────────────────────────────

/// A value read from the buffer according to a `DataType`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TypedValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    Bytes(Vec<u8>),
    Str(String),
}

impl std::fmt::Display for TypedValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::U8(v) => write!(f, "{v}"),
            Self::U16(v) => write!(f, "{v}"),
            Self::U32(v) => write!(f, "{v}"),
            Self::U64(v) => write!(f, "{v}"),
            Self::I8(v) => write!(f, "{v}"),
            Self::I16(v) => write!(f, "{v}"),
            Self::I32(v) => write!(f, "{v}"),
            Self::I64(v) => write!(f, "{v}"),
            Self::F32(v) => write!(f, "{v}"),
            Self::F64(v) => write!(f, "{v}"),
            Self::Bytes(b) => {
                for byte in b {
                    write!(f, "{byte:02X} ")?;
                }
                Ok(())
            }
            Self::Str(s) => write!(f, "{s}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Edit / undo-redo
// ─────────────────────────────────────────────────────────────────────────────

/// An atomic edit operation stored in the undo/redo stacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Edit {
    Insert {
        offset: usize,
        bytes: Vec<u8>,
    },
    Delete {
        offset: usize,
        bytes: Vec<u8>,
    },
    Replace {
        offset: usize,
        old: Vec<u8>,
        new: Vec<u8>,
    },
}

impl Edit {
    /// Returns the inverse of this edit (for undo).
    #[must_use]
    fn inverse(&self) -> Self {
        match self {
            Self::Insert { offset, bytes } => Self::Delete {
                offset: *offset,
                bytes: bytes.clone(),
            },
            Self::Delete { offset, bytes } => Self::Insert {
                offset: *offset,
                bytes: bytes.clone(),
            },
            Self::Replace { offset, old, new } => Self::Replace {
                offset: *offset,
                old: new.clone(),
                new: old.clone(),
            },
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bookmark
// ─────────────────────────────────────────────────────────────────────────────

/// A named, colour-coded position in the buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bookmark {
    pub offset: usize,
    pub name: String,
    /// Packed ARGB colour.
    pub color: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// DiffRegion
// ─────────────────────────────────────────────────────────────────────────────

/// A region where two buffers differ.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffRegion {
    pub offset: usize,
    pub len: usize,
    pub left: Vec<u8>,
    pub right: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Cursor — single editing position
// ─────────────────────────────────────────────────────────────────────────────

/// A single cursor position with an optional selection anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Cursor {
    /// Byte offset of the cursor in the buffer.
    pub offset: usize,
    /// Anchor for selection; if `Some`, selection spans `anchor..offset` (or `offset..anchor`).
    pub anchor: Option<usize>,
}

impl Cursor {
    /// Create a cursor at `offset` with no selection.
    #[must_use]
    pub const fn new(offset: usize) -> Self {
        Self {
            offset,
            anchor: None,
        }
    }

    /// Return the selected range `[min, max)`, or `None` if no selection.
    #[must_use]
    pub fn selection_range(&self) -> Option<Range<usize>> {
        self.anchor.map(|a| {
            let lo = self.offset.min(a);
            let hi = self.offset.max(a);
            lo..hi
        })
    }

    /// Set selection anchor to the current cursor offset.
    pub const fn begin_selection(&mut self) {
        self.anchor = Some(self.offset);
    }

    /// Clear the selection.
    pub const fn clear_selection(&mut self) {
        self.anchor = None;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MultiCursorState
// ─────────────────────────────────────────────────────────────────────────────

/// Manages multiple simultaneous editing cursors (for column/block editing).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MultiCursorState {
    cursors: Vec<Cursor>,
}

impl MultiCursorState {
    /// Create a state with a single cursor at offset 0.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cursors: vec![Cursor::new(0)],
        }
    }

    /// Number of active cursors.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.cursors.len()
    }

    /// Return a shared reference to all cursors.
    #[must_use]
    pub fn cursors(&self) -> &[Cursor] {
        &self.cursors
    }

    /// Return a mutable reference to cursor at `index`.
    ///
    /// # Errors
    /// Returns `HexError::CursorIndex` if `index` is out of range.
    pub fn cursor_mut(&mut self, index: usize) -> Result<&mut Cursor, HexError> {
        self.cursors
            .get_mut(index)
            .ok_or(HexError::CursorIndex(index))
    }

    /// Add a new cursor at `offset`.  Deduplicates by offset.
    pub fn add_cursor(&mut self, offset: usize) {
        if !self.cursors.iter().any(|c| c.offset == offset) {
            self.cursors.push(Cursor::new(offset));
        }
    }

    /// Remove the cursor at `index`, unless it is the last one.
    ///
    /// # Errors
    /// Returns `HexError::CursorIndex` if index is out of range.
    pub fn remove_cursor(&mut self, index: usize) -> Result<(), HexError> {
        if self.cursors.len() <= 1 {
            return Ok(());
        }
        if index >= self.cursors.len() {
            return Err(HexError::CursorIndex(index));
        }
        self.cursors.remove(index);
        Ok(())
    }

    /// Move all cursors by `delta` bytes (clamped to `[0, max_offset]`).
    pub fn move_all(&mut self, delta: isize, max_offset: usize) {
        for c in &mut self.cursors {
            let delta64 = i64::try_from(delta).unwrap_or(if delta > 0 { i64::MAX } else { i64::MIN });
            let new_off = usize::try_from(
                (i64::try_from(c.offset).unwrap_or(i64::MAX) + delta64)
                    .clamp(0, i64::try_from(max_offset).unwrap_or(i64::MAX))
                    .cast_unsigned(),
            )
            .unwrap_or(max_offset);
            c.offset = new_off;
        }
    }

    /// Collapse all cursors to the primary (first) cursor.
    pub fn collapse(&mut self) {
        let primary = self.cursors.first().copied().unwrap_or_default();
        self.cursors = vec![primary];
    }

    /// Sort cursors by offset.
    pub fn sort(&mut self) {
        self.cursors.sort_by_key(|c| c.offset);
    }

    /// Return the offset of the primary cursor (cursor 0).
    #[must_use]
    pub fn primary_offset(&self) -> usize {
        self.cursors.first().map_or(0, |c| c.offset)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ByteStatistics
// ─────────────────────────────────────────────────────────────────────────────

/// Byte-level statistics computed over a slice of data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByteStatistics {
    /// Total number of bytes analysed.
    pub total: usize,
    /// Minimum byte value present.
    pub min: u8,
    /// Maximum byte value present.
    pub max: u8,
    /// Arithmetic mean.
    pub mean: f64,
    /// Median byte value.
    pub median: f64,
    /// Population standard deviation.
    pub std_dev: f64,
    /// Shannon entropy [0, 8].
    pub entropy: f64,
    /// Number of distinct byte values that appear at least once.
    pub unique_count: usize,
    /// Most-frequent byte value.
    pub mode: u8,
    /// Frequency of the mode value.
    pub mode_count: usize,
}

impl ByteStatistics {
    /// Compute statistics over `data`.
    ///
    /// # Errors
    /// Returns `HexError::EmptyBuffer` if `data` is empty.
    pub fn compute(data: &[u8]) -> Result<Self, HexError> {
        if data.is_empty() {
            return Err(HexError::EmptyBuffer);
        }

        let mut counts = [0u64; 256];
        for &b in data {
            counts[b as usize] += 1;
        }

        let total = data.len();
        let len_f = f64::from(u32::try_from(total).unwrap_or(u32::MAX));

        let min = data.iter().copied().min().unwrap_or(0);
        let max = data.iter().copied().max().unwrap_or(0);

        let mean: f64 = data.iter().map(|&b| f64::from(b)).sum::<f64>() / len_f;

        let variance = data.iter().map(|&b| (f64::from(b) - mean).powi(2)).sum::<f64>() / len_f;
        let std_dev = variance.sqrt();

        let mut sorted = data.to_vec();
        sorted.sort_unstable();
        let median = if total.is_multiple_of(2) {
            f64::midpoint(f64::from(sorted[total / 2 - 1]), f64::from(sorted[total / 2]))
        } else {
            f64::from(sorted[total / 2])
        };

        let entropy = {
            counts
                .iter()
                .filter(|&&c| c > 0)
                .map(|&c| {
                    let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / len_f;
                    -p * p.log2()
                })
                .sum()
        };

        let unique_count = counts.iter().filter(|&&c| c > 0).count();

        let (mode, mode_count) = counts
            .iter()
            .copied()
            .enumerate()
            .max_by_key(|(_, c)| *c)
            .map_or((0, 0), |(i, c)| (u8::try_from(i).unwrap_or(u8::MAX), usize::try_from(c).unwrap_or(usize::MAX)));

        Ok(Self {
            total,
            min,
            max,
            mean,
            median,
            std_dev,
            entropy,
            unique_count,
            mode,
            mode_count,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Histogram
// ─────────────────────────────────────────────────────────────────────────────

/// A 256-bucket byte-value histogram.
#[derive(Debug, Clone)]
pub struct Histogram {
    /// `counts[b]` = how many times byte `b` appears in the data.
    pub counts: [u64; 256],
    /// Total number of bytes counted.
    pub total: u64,
}

impl Histogram {
    /// Compute a histogram over `data`.
    #[must_use]
    pub fn compute(data: &[u8]) -> Self {
        let mut counts = [0u64; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        let total = data.len() as u64;
        Self { counts, total }
    }

    /// Return the relative frequency of byte `b` in range `[0.0, 1.0]`.
    #[must_use]
    pub fn frequency(&self, b: u8) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.counts[usize::from(b)]).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.total).unwrap_or(u32::MAX))
    }

    /// Return the top-`n` most frequent byte values as `(byte, count)` pairs,
    /// sorted descending by count.
    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<(u8, u64)> {
        let mut pairs: Vec<(u8, u64)> = self
            .counts
            .iter()
            .copied()
            .enumerate()
            .map(|(i, c)| (u8::try_from(i).unwrap_or(u8::MAX), c))
            .collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(n);
        pairs
    }

    /// Produce a normalised histogram where each count is mapped to the range
    /// `[0.0, 1.0]` relative to the maximum bucket count.
    #[must_use]
    pub fn normalised(&self) -> [f64; 256] {
        let max_count = self.counts.iter().copied().max().unwrap_or(0);
        let mut out = [0.0f64; 256];
        if max_count > 0 {
            for (i, &c) in self.counts.iter().enumerate() {
                out[i] = f64::from(u32::try_from(c).unwrap_or(u32::MAX))
                    / f64::from(u32::try_from(max_count).unwrap_or(u32::MAX));
            }
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DataAnnotation
// ─────────────────────────────────────────────────────────────────────────────

/// A typed annotation overlaid on a region of the buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataAnnotation {
    pub offset: usize,
    pub size: usize,
    pub name: String,
    pub data_type: DataType,
    pub comment: String,
}

impl DataAnnotation {
    /// Create a new data annotation.
    #[must_use]
    pub fn new(offset: usize, size: usize, name: impl Into<String>, data_type: DataType) -> Self {
        Self {
            offset,
            size,
            name: name.into(),
            data_type,
            comment: String::new(),
        }
    }

    /// Return the range `offset..offset+size`.
    #[must_use]
    pub const fn range(&self) -> Range<usize> {
        self.offset..self.offset + self.size
    }

    /// Read the annotated value from `buf`.
    ///
    /// # Errors
    /// Propagates `HexError` if the read fails.
    pub fn read_value(&self, buf: &HexBuffer) -> Result<TypedValue, HexError> {
        buf.read_typed(self.offset, self.data_type)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FindReplaceOptions
// ─────────────────────────────────────────────────────────────────────────────

/// Search / replace mode selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SearchMode {
    /// Search for an exact sequence of bytes.
    Exact,
    /// Search using the byte-level regex NFA engine.
    Regex,
    /// Search for a hex-string pattern (spaces ignored, `?` wildcards allowed).
    HexPattern,
}

/// Options for a find-replace operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindReplaceOptions {
    pub mode: SearchMode,
    /// Whether to wrap around when reaching the end of the buffer.
    pub wrap: bool,
    /// Search only within `limit` if `Some`.
    pub limit: Option<Range<usize>>,
}

impl Default for FindReplaceOptions {
    fn default() -> Self {
        Self {
            mode: SearchMode::Exact,
            wrap: true,
            limit: None,
        }
    }
}

/// Result of a single find operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindResult {
    pub offset: usize,
    pub len: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// HexBuffer
// ─────────────────────────────────────────────────────────────────────────────

/// The core mutable byte buffer with cursor, selection, undo/redo history,
/// multi-cursor support, bookmarks, and data annotations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexBuffer {
    pub data: Vec<u8>,
    pub cursor: usize,
    pub selection: Option<Range<usize>>,
    pub undo_stack: Vec<Edit>,
    pub redo_stack: Vec<Edit>,
    /// Multi-cursor editing state.
    pub multi_cursor: MultiCursorState,
    /// Named bookmarks.
    pub bookmarks: Vec<Bookmark>,
    /// Typed data annotations.
    pub annotations: Vec<DataAnnotation>,
    /// Virtual base address added to all displayed offsets.
    pub base_address: u64,
}

impl HexBuffer {
    /// Create a new buffer from raw bytes.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            cursor: 0,
            selection: None,
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            multi_cursor: MultiCursorState::new(),
            bookmarks: Vec::new(),
            annotations: Vec::new(),
            base_address: 0,
        }
    }

    /// Create an empty buffer.
    #[must_use]
    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// Set the cursor to a position expressed as a [`rustre_core::address::FileOffset`].
    ///
    /// The `FileOffset` represents a byte position within a file-backed binary view,
    /// which maps directly to the byte index inside this buffer.
    ///
    /// # Errors
    /// Returns [`HexError::OutOfBounds`] if the offset exceeds the buffer length.
    pub fn set_cursor_file_offset(
        &mut self,
        offset: rustre_core::address::FileOffset,
    ) -> Result<(), HexError> {
        let pos = usize::try_from(offset.0)
            .map_err(|_| HexError::OutOfBounds(usize::MAX, self.data.len()))?;
        if pos > self.data.len() {
            return Err(HexError::OutOfBounds(pos, self.data.len()));
        }
        self.cursor = pos;
        Ok(())
    }

    /// Read bytes at a position expressed as a [`rustre_core::address::FileOffset`].
    ///
    /// # Errors
    /// Returns [`HexError::OutOfBounds`] if the range exceeds the buffer.
    pub fn read_at_file_offset(
        &self,
        offset: rustre_core::address::FileOffset,
        len: usize,
    ) -> Result<Vec<u8>, HexError> {
        let pos = usize::try_from(offset.0)
            .map_err(|_| HexError::OutOfBounds(usize::MAX, self.data.len()))?;
        self.read_exact(pos, len)
    }

    /// Create a buffer filled with `len` zero bytes.
    #[must_use]
    pub fn zeroed(len: usize) -> Self {
        Self::new(vec![0u8; len])
    }

    /// Return the total length of the buffer in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the buffer contains no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    // ── Read / write ────────────────────────────────────────────────────────

    /// Read up to `len` bytes starting at `offset`.
    ///
    /// Returns an error if `offset` is out of bounds.
    ///
    /// # Errors
    /// Returns `HexError::OutOfBounds` if `offset > self.len()`.
    pub fn read(&self, offset: usize, len: usize) -> Result<&[u8], HexError> {
        if offset > self.data.len() {
            return Err(HexError::OutOfBounds(offset, self.data.len()));
        }
        let end = (offset + len).min(self.data.len());
        Ok(&self.data[offset..end])
    }

    /// Overwrite bytes at `offset` with `bytes`.
    ///
    /// Records a `Replace` edit for undo support.
    ///
    /// # Errors
    /// Returns `HexError::OutOfBounds` if `offset > self.len()`.
    pub fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), HexError> {
        if offset > self.data.len() {
            return Err(HexError::OutOfBounds(offset, self.data.len()));
        }
        if offset + bytes.len() > self.data.len() {
            return Err(HexError::OutOfBounds(offset + bytes.len(), self.data.len()));
        }
        let end = offset + bytes.len();
        let old = self.data[offset..end].to_vec();
        let new = bytes.to_vec();
        self.data[offset..end].copy_from_slice(&new);
        self.push_edit(Edit::Replace { offset, old, new });
        Ok(())
    }

    /// Insert bytes at `offset`, shifting subsequent bytes right.
    ///
    /// # Errors
    /// Returns `HexError::OutOfBounds` if `offset > self.len()`.
    pub fn insert(&mut self, offset: usize, bytes: &[u8]) -> Result<(), HexError> {
        if offset > self.data.len() {
            return Err(HexError::OutOfBounds(offset, self.data.len()));
        }
        let edit = Edit::Insert {
            offset,
            bytes: bytes.to_vec(),
        };
        self.apply_edit_raw(&edit);
        self.push_edit(edit);
        Ok(())
    }

    /// Delete `len` bytes starting at `offset`.
    ///
    /// # Errors
    /// Returns `HexError::OutOfBounds` if `offset > self.len()`.
    pub fn delete(&mut self, offset: usize, len: usize) -> Result<(), HexError> {
        if offset > self.data.len() {
            return Err(HexError::OutOfBounds(offset, self.data.len()));
        }
        let end = (offset + len).min(self.data.len());
        let removed = self.data[offset..end].to_vec();
        let edit = Edit::Delete {
            offset,
            bytes: removed,
        };
        self.apply_edit_raw(&edit);
        self.push_edit(edit);
        Ok(())
    }

    // ── Undo / redo ─────────────────────────────────────────────────────────

    /// Undo the last edit.  Returns `false` if there is nothing to undo.
    pub fn undo(&mut self) -> bool {
        if let Some(edit) = self.undo_stack.pop() {
            let inv = edit.inverse();
            self.apply_edit_raw(&inv);
            self.redo_stack.push(edit);
            true
        } else {
            false
        }
    }

    /// Redo the last undone edit.  Returns `false` if there is nothing to redo.
    pub fn redo(&mut self) -> bool {
        if let Some(edit) = self.redo_stack.pop() {
            self.apply_edit_raw(&edit);
            self.undo_stack.push(edit);
            true
        } else {
            false
        }
    }

    /// Clear the undo and redo stacks.
    pub fn clear_history(&mut self) {
        self.undo_stack.clear();
        self.redo_stack.clear();
    }

    // ── Block operations ────────────────────────────────────────────────────

    /// Fill a range of bytes with a repeating `pattern`.
    ///
    /// # Errors
    /// Returns `HexError::InvalidRange` if the range is invalid, or
    /// `HexError::EmptyBuffer` if `pattern` is empty.
    pub fn fill(&mut self, range: Range<usize>, pattern: &[u8]) -> Result<(), HexError> {
        if range.start > range.end || range.end > self.data.len() {
            return Err(HexError::InvalidRange(range.start, range.end));
        }
        if pattern.is_empty() {
            return Err(HexError::EmptyBuffer);
        }
        if range.is_empty() {
            return Ok(());
        }
        let old = self.data[range.clone()].to_vec();
        let len = range.len();
        let mut new_data = Vec::with_capacity(len);
        for i in 0..len {
            new_data.push(pattern[i % pattern.len()]);
        }
        self.data[range.clone()].copy_from_slice(&new_data);
        self.push_edit(Edit::Replace {
            offset: range.start,
            old,
            new: new_data,
        });
        Ok(())
    }

    /// Reverse the bytes in `range` in-place.
    ///
    /// # Errors
    /// Returns `HexError::InvalidRange` if the range is invalid.
    pub fn reverse_range(&mut self, range: Range<usize>) -> Result<(), HexError> {
        if range.start > range.end || range.end > self.data.len() {
            return Err(HexError::InvalidRange(range.start, range.end));
        }
        if range.len() < 2 {
            return Ok(());
        }
        let old = self.data[range.clone()].to_vec();
        let mut new_data = old.clone();
        new_data.reverse();
        self.data[range.clone()].copy_from_slice(&new_data);
        self.push_edit(Edit::Replace {
            offset: range.start,
            old,
            new: new_data,
        });
        Ok(())
    }

    /// Shift bytes in `range` left by `amount` positions (bytes shifted out
    /// are lost; vacant positions are filled with `fill_byte`).
    ///
    /// # Errors
    /// Returns `HexError::InvalidRange` if the range is invalid.
    pub fn shift_left(
        &mut self,
        range: Range<usize>,
        amount: usize,
        fill_byte: u8,
    ) -> Result<(), HexError> {
        if range.start > range.end || range.end > self.data.len() {
            return Err(HexError::InvalidRange(range.start, range.end));
        }
        if range.is_empty() || amount == 0 {
            return Ok(());
        }
        let old = self.data[range.clone()].to_vec();
        let len = range.len();
        let shift = amount.min(len);
        let mut new_data = vec![fill_byte; len];
        new_data[..len - shift].copy_from_slice(&old[shift..]);
        self.data[range.clone()].copy_from_slice(&new_data);
        self.push_edit(Edit::Replace {
            offset: range.start,
            old,
            new: new_data,
        });
        Ok(())
    }

    /// Shift bytes in `range` right by `amount` positions (bytes shifted out
    /// are lost; vacant positions are filled with `fill_byte`).
    ///
    /// # Errors
    /// Returns `HexError::InvalidRange` if the range is invalid.
    pub fn shift_right(
        &mut self,
        range: Range<usize>,
        amount: usize,
        fill_byte: u8,
    ) -> Result<(), HexError> {
        if range.start > range.end || range.end > self.data.len() {
            return Err(HexError::InvalidRange(range.start, range.end));
        }
        if range.is_empty() || amount == 0 {
            return Ok(());
        }
        let old = self.data[range.clone()].to_vec();
        let len = range.len();
        let shift = amount.min(len);
        let mut new_data = vec![fill_byte; len];
        new_data[shift..].copy_from_slice(&old[..len - shift]);
        self.data[range.clone()].copy_from_slice(&new_data);
        self.push_edit(Edit::Replace {
            offset: range.start,
            old,
            new: new_data,
        });
        Ok(())
    }

    /// Rotate bytes in `range` left by `amount` positions (circular).
    ///
    /// # Errors
    /// Returns `HexError::InvalidRange` if the range is invalid.
    pub fn rotate_left(&mut self, range: Range<usize>, amount: usize) -> Result<(), HexError> {
        if range.start > range.end || range.end > self.data.len() {
            return Err(HexError::InvalidRange(range.start, range.end));
        }
        let len = range.len();
        if len < 2 || amount == 0 {
            return Ok(());
        }
        let shift = amount % len;
        let old = self.data[range.clone()].to_vec();
        let mut new_data = Vec::with_capacity(len);
        new_data.extend_from_slice(&old[shift..]);
        new_data.extend_from_slice(&old[..shift]);
        self.data[range.clone()].copy_from_slice(&new_data);
        self.push_edit(Edit::Replace {
            offset: range.start,
            old,
            new: new_data,
        });
        Ok(())
    }

    /// Rotate bytes in `range` right by `amount` positions (circular).
    ///
    /// # Errors
    /// Returns `HexError::InvalidRange` if the range is invalid.
    pub fn rotate_right(&mut self, range: Range<usize>, amount: usize) -> Result<(), HexError> {
        if range.start > range.end || range.end > self.data.len() {
            return Err(HexError::InvalidRange(range.start, range.end));
        }
        let len = range.len();
        if len < 2 || amount == 0 {
            return Ok(());
        }
        let shift = amount % len;
        self.rotate_left(range, len - shift)
    }

    // ── Bitwise transforms ───────────────────────────────────────────────────

    /// XOR all bytes in `range` with the repeating `key`.
    ///
    /// # Errors
    /// Returns `HexError::InvalidRange` or `HexError::EmptyBuffer` if invalid.
    pub fn xor_range(&mut self, range: Range<usize>, key: &[u8]) -> Result<(), HexError> {
        if range.start > range.end || range.end > self.data.len() {
            return Err(HexError::InvalidRange(range.start, range.end));
        }
        if key.is_empty() {
            return Err(HexError::EmptyBuffer);
        }
        if range.is_empty() {
            return Ok(());
        }
        let old = self.data[range.clone()].to_vec();
        let new_data: Vec<u8> = old
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();
        self.data[range.clone()].copy_from_slice(&new_data);
        self.push_edit(Edit::Replace {
            offset: range.start,
            old,
            new: new_data,
        });
        Ok(())
    }

    /// AND all bytes in `range` with the repeating `key`.
    ///
    /// # Errors
    /// Returns `HexError::InvalidRange` or `HexError::EmptyBuffer` if invalid.
    pub fn and_range(&mut self, range: Range<usize>, key: &[u8]) -> Result<(), HexError> {
        if range.start > range.end || range.end > self.data.len() {
            return Err(HexError::InvalidRange(range.start, range.end));
        }
        if key.is_empty() {
            return Err(HexError::EmptyBuffer);
        }
        if range.is_empty() {
            return Ok(());
        }
        let old = self.data[range.clone()].to_vec();
        let new_data: Vec<u8> = old
            .iter()
            .enumerate()
            .map(|(i, &b)| b & key[i % key.len()])
            .collect();
        self.data[range.clone()].copy_from_slice(&new_data);
        self.push_edit(Edit::Replace {
            offset: range.start,
            old,
            new: new_data,
        });
        Ok(())
    }

    /// OR all bytes in `range` with the repeating `key`.
    ///
    /// # Errors
    /// Returns `HexError::InvalidRange` or `HexError::EmptyBuffer` if invalid.
    pub fn or_range(&mut self, range: Range<usize>, key: &[u8]) -> Result<(), HexError> {
        if range.start > range.end || range.end > self.data.len() {
            return Err(HexError::InvalidRange(range.start, range.end));
        }
        if key.is_empty() {
            return Err(HexError::EmptyBuffer);
        }
        if range.is_empty() {
            return Ok(());
        }
        let old = self.data[range.clone()].to_vec();
        let new_data: Vec<u8> = old
            .iter()
            .enumerate()
            .map(|(i, &b)| b | key[i % key.len()])
            .collect();
        self.data[range.clone()].copy_from_slice(&new_data);
        self.push_edit(Edit::Replace {
            offset: range.start,
            old,
            new: new_data,
        });
        Ok(())
    }

    /// Bitwise NOT (complement) all bytes in `range`.
    ///
    /// # Errors
    /// Returns `HexError::InvalidRange` if the range is invalid.
    pub fn not_range(&mut self, range: Range<usize>) -> Result<(), HexError> {
        if range.start > range.end || range.end > self.data.len() {
            return Err(HexError::InvalidRange(range.start, range.end));
        }
        if range.is_empty() {
            return Ok(());
        }
        let old = self.data[range.clone()].to_vec();
        let new_data: Vec<u8> = old.iter().map(|&b| !b).collect();
        self.data[range.clone()].copy_from_slice(&new_data);
        self.push_edit(Edit::Replace {
            offset: range.start,
            old,
            new: new_data,
        });
        Ok(())
    }

    /// Add `addend` (modulo 256) to every byte in `range`.
    ///
    /// # Errors
    /// Returns `HexError::InvalidRange` if the range is invalid.
    pub fn add_range(&mut self, range: Range<usize>, addend: u8) -> Result<(), HexError> {
        if range.start > range.end || range.end > self.data.len() {
            return Err(HexError::InvalidRange(range.start, range.end));
        }
        if range.is_empty() {
            return Ok(());
        }
        let old = self.data[range.clone()].to_vec();
        let new_data: Vec<u8> = old.iter().map(|&b| b.wrapping_add(addend)).collect();
        self.data[range.clone()].copy_from_slice(&new_data);
        self.push_edit(Edit::Replace {
            offset: range.start,
            old,
            new: new_data,
        });
        Ok(())
    }

    /// Negate (two's complement) every byte in `range`.
    ///
    /// # Errors
    /// Returns `HexError::InvalidRange` if the range is invalid.
    pub fn negate_range(&mut self, range: Range<usize>) -> Result<(), HexError> {
        if range.start > range.end || range.end > self.data.len() {
            return Err(HexError::InvalidRange(range.start, range.end));
        }
        if range.is_empty() {
            return Ok(());
        }
        let old = self.data[range.clone()].to_vec();
        let new_data: Vec<u8> = old.iter().map(|&b| b.wrapping_neg()).collect();
        self.data[range.clone()].copy_from_slice(&new_data);
        self.push_edit(Edit::Replace {
            offset: range.start,
            old,
            new: new_data,
        });
        Ok(())
    }

    // ── Search ──────────────────────────────────────────────────────────────

    /// Search for all (possibly overlapping) occurrences of `pattern` using KMP.
    #[must_use]
    pub fn search(&self, pattern: &[u8]) -> Vec<usize> {
        if pattern.is_empty() || self.data.len() < pattern.len() {
            return Vec::new();
        }
        kmp_search(&self.data, pattern)
    }

    /// Search using a POSIX-compatible regex applied byte-by-byte.
    ///
    /// # Errors
    /// Returns `HexError::Regex` if the pattern fails to compile.
    pub fn search_regex(&self, pattern: &str) -> Result<Vec<usize>, HexError> {
        regex_search(&self.data, pattern)
    }

    /// Find all occurrences of string `s` encoded as `encoding`.
    ///
    /// # Errors
    /// Returns `HexError::Encoding` if the string cannot be encoded.
    pub fn find_string(&self, s: &str, encoding: Encoding) -> Result<Vec<usize>, HexError> {
        let needle = encode_string(s, encoding)?;
        Ok(self.search(&needle))
    }

    /// Find all occurrences of a hex-string pattern (e.g. `"DE AD ? ? EF"`).
    ///
    /// # Errors
    /// Returns an error if the hex pattern is malformed.
    pub fn find_hex_pattern(&self, hex_pattern: &str) -> Result<Vec<usize>, HexError> {
        // Parse into exact/wildcard bytes, then scan
        let tokens: Vec<&str> = hex_pattern.split_whitespace().collect();
        if tokens.is_empty() {
            return Ok(Vec::new());
        }
        let mut pat: Vec<Option<u8>> = Vec::with_capacity(tokens.len());
        for t in &tokens {
            if *t == "?" || *t == "??" {
                pat.push(None);
            } else if t.len() == 2 {
                let hi = hex_nibble_val(t.as_bytes()[0])?;
                let lo = hex_nibble_val(t.as_bytes()[1])?;
                pat.push(Some((hi << 4) | lo));
            } else {
                return Err(HexError::Regex(format!("invalid hex token: {t}")));
            }
        }
        let pat_len = pat.len();
        if pat_len == 0 || self.data.len() < pat_len {
            return Ok(Vec::new());
        }
        let mut results = Vec::new();
        'outer: for start in 0..=(self.data.len() - pat_len) {
            for (i, slot) in pat.iter().enumerate() {
                if let Some(expected) = slot
                    && self.data[start + i] != *expected {
                        continue 'outer;
                    }
            }
            results.push(start);
        }
        Ok(results)
    }

    /// Find all matches in the buffer using the given `options`.
    ///
    /// # Errors
    /// Propagates errors from the underlying search engine.
    pub fn find_all(
        &self,
        needle: &[u8],
        options: &FindReplaceOptions,
    ) -> Result<Vec<FindResult>, HexError> {
        let search_data = if let Some(ref lim) = options.limit {
            if lim.start > lim.end || lim.end > self.data.len() {
                return Err(HexError::InvalidRange(lim.start, lim.end));
            }
            &self.data[lim.clone()]
        } else {
            &self.data
        };
        let base = options.limit.as_ref().map_or(0, |l| l.start);

        match options.mode {
            SearchMode::Exact => {
                let offsets = kmp_search(search_data, needle);
                Ok(offsets
                    .into_iter()
                    .map(|o| FindResult {
                        offset: base + o,
                        len: needle.len(),
                    })
                    .collect())
            }
            SearchMode::Regex => {
                let pattern = std::str::from_utf8(needle)
                    .map_err(|_| HexError::Regex("pattern is not valid UTF-8".to_string()))?;
                let offsets = regex_search(search_data, pattern)?;
                Ok(offsets
                    .into_iter()
                    .map(|o| FindResult {
                        offset: base + o,
                        len: 1, // NFA doesn't return match lengths
                    })
                    .collect())
            }
            SearchMode::HexPattern => {
                let pattern_str = std::str::from_utf8(needle)
                    .map_err(|_| HexError::Regex("pattern is not valid UTF-8".to_string()))?;
                let sub_buf = Self::new(search_data.to_vec());
                let offsets = sub_buf.find_hex_pattern(pattern_str)?;
                Ok(offsets
                    .into_iter()
                    .map(|o| FindResult {
                        offset: base + o,
                        len: pattern_str.split_whitespace().count(),
                    })
                    .collect())
            }
        }
    }

    /// Replace all occurrences of `needle` with `replacement`.
    ///
    /// Returns the number of replacements made.
    ///
    /// # Errors
    /// Propagates errors from the underlying search engine.
    pub fn replace_all(
        &mut self,
        needle: &[u8],
        replacement: &[u8],
        options: &FindReplaceOptions,
    ) -> Result<usize, HexError> {
        if needle.is_empty() {
            return Err(HexError::Replace("needle cannot be empty".to_string()));
        }
        let matches = self.find_all(needle, options)?;
        let count = matches.len();
        if count == 0 {
            return Ok(0);
        }
        // Clear redo stack once for the whole compound operation, not once per replacement.
        self.redo_stack.clear();
        // Apply replacements from back to front so that earlier byte offsets remain valid
        // even for variable-length replacements (high-offset mutations don't shift low offsets).
        for m in matches.iter().rev() {
            let start = m.offset;
            let end = start + m.len;
            if end > self.data.len() {
                continue;
            }
            let old = self.data[start..end].to_vec();
            let new_data = replacement.to_vec();
            // Use splice for a single unified drain+insert that handles all length cases.
            self.data.splice(start..end, new_data.iter().copied());
            // Push directly to undo_stack (redo already cleared above).
            self.undo_stack.push(Edit::Replace {
                offset: start,
                old,
                new: new_data,
            });
        }
        Ok(count)
    }

    // ── Typed reads ─────────────────────────────────────────────────────────

    /// Read a typed value from the buffer.
    ///
    /// # Errors
    /// Returns `HexError::TypeRead` or `HexError::OutOfBounds` if the value
    /// cannot be read at `offset`.
    ///
    /// # Panics
    /// Panics if the internal read buffer has an unexpected length (should
    /// never happen when `read_exact` returns the requested number of bytes).
    pub fn read_typed(&self, offset: usize, ty: DataType) -> Result<TypedValue, HexError> {
        match ty {
            DataType::U8 => Ok(TypedValue::U8(self.read_exact(offset, 1)?[0])),
            DataType::I8 => Ok(TypedValue::I8(self.read_exact(offset, 1)?[0].cast_signed())),
            DataType::U16Le => Ok(TypedValue::U16(u16::from_le_bytes({
                let b = self.read_exact(offset, 2)?;
                [b[0], b[1]]
            }))),
            DataType::U16Be => Ok(TypedValue::U16(u16::from_be_bytes({
                let b = self.read_exact(offset, 2)?;
                [b[0], b[1]]
            }))),
            DataType::I16Le => Ok(TypedValue::I16(i16::from_le_bytes({
                let b = self.read_exact(offset, 2)?;
                [b[0], b[1]]
            }))),
            DataType::I16Be => Ok(TypedValue::I16(i16::from_be_bytes({
                let b = self.read_exact(offset, 2)?;
                [b[0], b[1]]
            }))),
            DataType::U32Le => Ok(TypedValue::U32(u32::from_le_bytes(
                self.read_exact(offset, 4)?.try_into().unwrap(),
            ))),
            DataType::U32Be => Ok(TypedValue::U32(u32::from_be_bytes(
                self.read_exact(offset, 4)?.try_into().unwrap(),
            ))),
            DataType::I32Le => Ok(TypedValue::I32(i32::from_le_bytes(
                self.read_exact(offset, 4)?.try_into().unwrap(),
            ))),
            DataType::I32Be => Ok(TypedValue::I32(i32::from_be_bytes(
                self.read_exact(offset, 4)?.try_into().unwrap(),
            ))),
            DataType::U64Le => Ok(TypedValue::U64(u64::from_le_bytes(
                self.read_exact(offset, 8)?.try_into().unwrap(),
            ))),
            DataType::U64Be => Ok(TypedValue::U64(u64::from_be_bytes(
                self.read_exact(offset, 8)?.try_into().unwrap(),
            ))),
            DataType::I64Le => Ok(TypedValue::I64(i64::from_le_bytes(
                self.read_exact(offset, 8)?.try_into().unwrap(),
            ))),
            DataType::I64Be => Ok(TypedValue::I64(i64::from_be_bytes(
                self.read_exact(offset, 8)?.try_into().unwrap(),
            ))),
            DataType::F32Le => Ok(TypedValue::F32(f32::from_le_bytes(
                self.read_exact(offset, 4)?.try_into().unwrap(),
            ))),
            DataType::F32Be => Ok(TypedValue::F32(f32::from_be_bytes(
                self.read_exact(offset, 4)?.try_into().unwrap(),
            ))),
            DataType::F64Le => Ok(TypedValue::F64(f64::from_le_bytes(
                self.read_exact(offset, 8)?.try_into().unwrap(),
            ))),
            DataType::F64Be => Ok(TypedValue::F64(f64::from_be_bytes(
                self.read_exact(offset, 8)?.try_into().unwrap(),
            ))),
            DataType::Bytes(n) => Ok(TypedValue::Bytes(self.read_exact(offset, n)?)),
            DataType::CStr => self.read_typed_cstr(offset),
            DataType::Utf16(n) => self.read_typed_utf16(offset, n),
        }
    }

    fn read_typed_cstr(&self, offset: usize) -> Result<TypedValue, HexError> {
        if offset >= self.data.len() {
            return Err(HexError::OutOfBounds(offset, self.data.len()));
        }
        let end = self.data[offset..]
            .iter()
            .position(|&b| b == 0)
            .map_or(self.data.len(), |p| offset + p);
        let s = std::str::from_utf8(&self.data[offset..end])
            .map_err(|e| HexError::TypeRead(offset, e.to_string()))?;
        Ok(TypedValue::Str(s.to_string()))
    }

    fn read_typed_utf16(&self, offset: usize, n: usize) -> Result<TypedValue, HexError> {
        let byte_len = n.checked_mul(2).ok_or_else(|| {
            HexError::TypeRead(offset, "Utf16 code-unit count overflows".into())
        })?;
        let b = self.read_exact(offset, byte_len)?;
        let u16s: Vec<u16> = b
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let s = String::from_utf16(&u16s)
            .map_err(|e| HexError::TypeRead(offset, e.to_string()))?;
        Ok(TypedValue::Str(s))
    }

    // ── Statistics and histogram ─────────────────────────────────────────────

    /// Compute byte statistics over the entire buffer.
    ///
    /// # Errors
    /// Returns `HexError::EmptyBuffer` if the buffer is empty.
    pub fn statistics(&self) -> Result<ByteStatistics, HexError> {
        ByteStatistics::compute(&self.data)
    }

    /// Compute byte statistics over a sub-range.
    ///
    /// # Errors
    /// Returns `HexError::InvalidRange` if the range is out of bounds,
    /// or `HexError::EmptyBuffer` if the range is empty.
    pub fn statistics_range(&self, range: Range<usize>) -> Result<ByteStatistics, HexError> {
        if range.start > range.end || range.end > self.data.len() {
            return Err(HexError::InvalidRange(range.start, range.end));
        }
        ByteStatistics::compute(&self.data[range])
    }

    /// Compute a 256-bucket histogram over the entire buffer.
    #[must_use]
    pub fn histogram(&self) -> Histogram {
        Histogram::compute(&self.data)
    }

    /// Compute a histogram over a sub-range.
    ///
    /// # Errors
    /// Returns `HexError::InvalidRange` if the range is out of bounds.
    pub fn histogram_range(&self, range: Range<usize>) -> Result<Histogram, HexError> {
        if range.start > range.end || range.end > self.data.len() {
            return Err(HexError::InvalidRange(range.start, range.end));
        }
        Ok(Histogram::compute(&self.data[range]))
    }

    // ── Bookmarks ────────────────────────────────────────────────────────────

    /// Add or replace a bookmark at `offset`.
    pub fn add_bookmark(&mut self, offset: usize, name: impl Into<String>, color: u32) {
        let name = name.into();
        if let Some(bm) = self.bookmarks.iter_mut().find(|b| b.offset == offset) {
            bm.name = name;
            bm.color = color;
        } else {
            self.bookmarks.push(Bookmark {
                offset,
                name,
                color,
            });
            self.bookmarks.sort_by_key(|b| b.offset);
        }
    }

    /// Remove the bookmark at `offset`. Returns `true` if one was removed.
    pub fn remove_bookmark(&mut self, offset: usize) -> bool {
        let before = self.bookmarks.len();
        self.bookmarks.retain(|b| b.offset != offset);
        self.bookmarks.len() != before
    }

    /// Return the bookmark closest to `offset`, searching both directions.
    #[must_use]
    pub fn nearest_bookmark(&self, offset: usize) -> Option<&Bookmark> {
        self.bookmarks
            .iter()
            .min_by_key(|b| (b.offset as isize - offset as isize).unsigned_abs())
    }

    // ── Data annotations ─────────────────────────────────────────────────────

    /// Add a data annotation.
    pub fn add_annotation(&mut self, ann: DataAnnotation) {
        self.annotations.push(ann);
        self.annotations.sort_by_key(|a| a.offset);
    }

    /// Remove annotations whose offset falls within `range`.
    pub fn remove_annotations_in(&mut self, range: Range<usize>) {
        self.annotations
            .retain(|a| a.offset < range.start || a.offset >= range.end);
    }

    /// Return all annotations that overlap `offset..offset+len`.
    #[must_use]
    pub fn annotations_overlapping(&self, offset: usize, len: usize) -> Vec<&DataAnnotation> {
        let end = offset.saturating_add(len);
        self.annotations
            .iter()
            .filter(|a| a.offset < end && a.offset.saturating_add(a.size) > offset)
            .collect()
    }

    // ── Utility reads ────────────────────────────────────────────────────────

    /// Return a copy of `len` bytes starting at `offset`, zero-padded if beyond end.
    #[must_use]
    pub fn read_padded(&self, offset: usize, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        let avail = self.data.len().saturating_sub(offset);
        let copy_len = avail.min(len);
        if copy_len > 0 {
            out[..copy_len].copy_from_slice(&self.data[offset..offset + copy_len]);
        }
        out
    }

    /// Compute Shannon entropy for each block of `block_size` bytes.
    #[must_use]
    pub fn entropy_blocks(&self, block_size: usize) -> Vec<f64> {
        entropy(&self.data, block_size)
    }

    /// Virtual address corresponding to `offset` (`base_address + offset`).
    #[must_use]
    pub const fn virtual_address(&self, offset: usize) -> u64 {
        self.base_address.saturating_add(offset as u64)
    }

    /// Buffer offset for a virtual address, or `None` if out of range.
    #[must_use]
    pub fn offset_for_va(&self, va: u64) -> Option<usize> {
        if va < self.base_address {
            return None;
        }
        let off64 = va - self.base_address;
        let off = usize::try_from(off64).ok()?;
        if off < self.data.len() {
            Some(off)
        } else {
            None
        }
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn read_exact(&self, offset: usize, len: usize) -> Result<Vec<u8>, HexError> {
        let end = offset.checked_add(len).ok_or_else(|| {
            HexError::TypeRead(offset, format!("offset {offset} + len {len} overflows usize"))
        })?;
        if end > self.data.len() {
            return Err(HexError::TypeRead(
                offset,
                format!(
                    "need {len} bytes but only {} available",
                    self.data.len() - offset.min(self.data.len())
                ),
            ));
        }
        Ok(self.data[offset..end].to_vec())
    }

    fn push_edit(&mut self, edit: Edit) {
        self.undo_stack.push(edit);
        self.redo_stack.clear();
    }

    fn apply_edit_raw(&mut self, edit: &Edit) {
        match edit {
            Edit::Insert { offset, bytes } => {
                let idx = (*offset).min(self.data.len());
                self.data.splice(idx..idx, bytes.iter().copied());
            }
            Edit::Delete { offset, bytes } => {
                let start = (*offset).min(self.data.len());
                let end = (start + bytes.len()).min(self.data.len());
                self.data.drain(start..end);
            }
            Edit::Replace { offset, old, new } => {
                let start = (*offset).min(self.data.len());
                let end = (start + old.len()).min(self.data.len());
                self.data.splice(start..end, new.iter().copied());
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexDiff
// ─────────────────────────────────────────────────────────────────────────────

/// Diff engine: compare two buffers and return changed regions.
pub struct HexDiff;

impl HexDiff {
    /// Compare `left` and `right`, returning a list of differing regions.
    #[must_use]
    pub fn compare(left: &HexBuffer, right: &HexBuffer) -> Vec<DiffRegion> {
        Self::compare_slices(&left.data, &right.data)
    }

    /// Compare raw byte slices.
    #[must_use]
    pub fn compare_slices(left: &[u8], right: &[u8]) -> Vec<DiffRegion> {
        let max_len = left.len().max(right.len());
        let mut regions: Vec<DiffRegion> = Vec::new();
        let mut i = 0;
        while i < max_len {
            let lb = left.get(i).copied();
            let rb = right.get(i).copied();
            if lb == rb {
                i += 1;
            } else {
                let start = i;
                let mut lbytes = Vec::new();
                let mut rbytes = Vec::new();
                while i < max_len {
                    let l2 = left.get(i).copied();
                    let r2 = right.get(i).copied();
                    if l2 == r2 {
                        break;
                    }
                    if let Some(b) = l2 {
                        lbytes.push(b);
                    }
                    if let Some(b) = r2 {
                        rbytes.push(b);
                    }
                    i += 1;
                }
                regions.push(DiffRegion {
                    offset: start,
                    len: i - start,
                    left: lbytes,
                    right: rbytes,
                });
            }
        }
        regions
    }

    /// Apply a `DiffRegion` from `right` onto `left`, patching `left` to match.
    pub fn apply_patch(left: &mut HexBuffer, region: &DiffRegion) -> Result<(), HexError> {
        left.write(region.offset, &region.right)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Entropy
// ─────────────────────────────────────────────────────────────────────────────

/// Compute Shannon entropy for each block of `block_size` bytes.
///
/// Returns one `f64` per block in range [0.0, 8.0].
#[must_use]
pub fn entropy(data: &[u8], block_size: usize) -> Vec<f64> {
    if data.is_empty() || block_size == 0 {
        return Vec::new();
    }
    data.chunks(block_size)
        .map(shannon_entropy)
        .collect()
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / len;
            -p * p.log2()
        })
        .sum()
}

// ─────────────────────────────────────────────────────────────────────────────
// KMP search
// ─────────────────────────────────────────────────────────────────────────────

/// KMP exact-match search; returns all (possibly overlapping) match offsets.
#[must_use]
pub fn kmp_search(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() {
        return (0..=haystack.len()).collect();
    }
    let fail = build_failure_fn(needle);
    let mut matches = Vec::new();
    let mut j = 0usize;
    for (i, &byte) in haystack.iter().enumerate() {
        while j > 0 && byte != needle[j] {
            j = fail[j - 1];
        }
        if byte == needle[j] {
            j += 1;
        }
        if j == needle.len() {
            matches.push(i + 1 - j);
            j = fail[j - 1];
        }
    }
    matches
}

fn build_failure_fn(pattern: &[u8]) -> Vec<usize> {
    let m = pattern.len();
    let mut fail = vec![0usize; m];
    let mut k = 0usize;
    for i in 1..m {
        while k > 0 && pattern[i] != pattern[k] {
            k = fail[k - 1];
        }
        if pattern[i] == pattern[k] {
            k += 1;
        }
        fail[i] = k;
    }
    fail
}

// ─────────────────────────────────────────────────────────────────────────────
// Regex search (hand-rolled NFA subset)
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum number of compiled regex atoms accepted from user input.
/// Prevents runaway backtracking proportional to pattern complexity.
const MAX_REGEX_PARTS: usize = 64;

/// Maximum number of NFA simulation steps per `find` call.
/// Caps worst-case exponential backtracking caused by nested `*`/`+` quantifiers.
const MAX_REGEX_STEPS: usize = 1_000_000;

/// A minimal regex NFA for byte-level pattern matching.
/// Supports: `.` (any byte), `[abc]` / `[^abc]` character classes,
/// `*` `+` `?` quantifiers, `\xHH` hex escapes, `^` `$` anchors, literal bytes.
fn regex_search(data: &[u8], pattern: &str) -> Result<Vec<usize>, HexError> {
    let nfa = ByteRegex::compile(pattern)?;
    let mut results = Vec::new();
    for start in 0..data.len() {
        let mut steps = 0usize;
        if let Some(_end) = nfa.find_with_budget(data, start, &mut steps) {
            results.push(start);
        }
    }
    Ok(results)
}

// ── ByteRegex ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum RegexAtom {
    Literal(u8),
    AnyByte,
    Class(Vec<u8>, bool), // bytes, negated
}

#[derive(Debug, Clone)]
enum Quantifier {
    One,
    ZeroOrMore,
    OneOrMore,
    ZeroOrOne,
}

#[derive(Debug, Clone)]
struct RegexPart {
    atom: RegexAtom,
    quant: Quantifier,
}

#[derive(Debug)]
struct ByteRegex {
    parts: Vec<RegexPart>,
    anchored_start: bool,
    anchored_end: bool,
}

impl ByteRegex {
    fn compile(pattern: &str) -> Result<Self, HexError> {
        let bytes = pattern.as_bytes();
        let mut parts: Vec<RegexPart> = Vec::new();
        let mut anchored_start = false;
        let mut anchored_end = false;
        let mut i = 0;

        if bytes.first() == Some(&b'^') {
            anchored_start = true;
            i += 1;
        }

        while i < bytes.len() {
            if bytes[i] == b'$' && i + 1 == bytes.len() {
                anchored_end = true;
                i += 1;
                continue;
            }
            let atom = if bytes[i] == b'.' {
                i += 1;
                RegexAtom::AnyByte
            } else if bytes[i] == b'[' {
                i += 1;
                let negated = if bytes.get(i) == Some(&b'^') {
                    i += 1;
                    true
                } else {
                    false
                };
                let mut class_bytes = Vec::new();
                while i < bytes.len() && bytes[i] != b']' {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        class_bytes.push(unescape_byte(bytes, &mut i)?);
                    } else if i + 2 < bytes.len() && bytes[i + 1] == b'-' && bytes[i + 2] != b']' {
                        let from = bytes[i];
                        let to = bytes[i + 2];
                        for b in from..=to {
                            class_bytes.push(b);
                        }
                        i += 3;
                    } else {
                        class_bytes.push(bytes[i]);
                        i += 1;
                    }
                }
                if i < bytes.len() {
                    i += 1; // consume ']'
                }
                RegexAtom::Class(class_bytes, negated)
            } else if bytes[i] == b'\\' {
                let b = unescape_byte(bytes, &mut i)?;
                RegexAtom::Literal(b)
            } else {
                let b = bytes[i];
                i += 1;
                RegexAtom::Literal(b)
            };

            let quant = match bytes.get(i) {
                Some(b'*') => {
                    i += 1;
                    Quantifier::ZeroOrMore
                }
                Some(b'+') => {
                    i += 1;
                    Quantifier::OneOrMore
                }
                Some(b'?') => {
                    i += 1;
                    Quantifier::ZeroOrOne
                }
                _ => Quantifier::One,
            };

            parts.push(RegexPart { atom, quant });
        }

        if parts.len() > MAX_REGEX_PARTS {
            return Err(HexError::Regex(format!(
                "regex pattern too complex: {} atoms (max {})",
                parts.len(),
                MAX_REGEX_PARTS
            )));
        }

        Ok(Self {
            parts,
            anchored_start,
            anchored_end,
        })
    }

    /// Attempt to match starting at `start`; return end position on success.
    /// `steps` is a shared budget that is decremented on each NFA step to
    /// prevent exponential backtracking (`ReDoS`).
    fn find_with_budget(&self, data: &[u8], start: usize, steps: &mut usize) -> Option<usize> {
        if self.anchored_start && start != 0 {
            return None;
        }
        let result = self.match_parts(data, start, 0, steps);
        if let Some(end) = result {
            if self.anchored_end && end != data.len() {
                return None;
            }
            Some(end)
        } else {
            None
        }
    }

    fn match_parts(&self, data: &[u8], pos: usize, part_idx: usize, steps: &mut usize) -> Option<usize> {
        // Guard against budget exhaustion caused by backtracking.
        *steps = steps.saturating_add(1);
        if *steps > MAX_REGEX_STEPS {
            return None;
        }

        if part_idx == self.parts.len() {
            return Some(pos);
        }
        let part = &self.parts[part_idx];
        match &part.quant {
            Quantifier::One => {
                if Self::atom_matches(&part.atom, data, pos) {
                    self.match_parts(data, pos + 1, part_idx + 1, steps)
                } else {
                    None
                }
            }
            Quantifier::ZeroOrOne => {
                if Self::atom_matches(&part.atom, data, pos)
                    && let Some(end) = self.match_parts(data, pos + 1, part_idx + 1, steps) {
                        return Some(end);
                    }
                self.match_parts(data, pos, part_idx + 1, steps)
            }
            Quantifier::ZeroOrMore => {
                let mut positions = vec![pos];
                let mut cur = pos;
                while Self::atom_matches(&part.atom, data, cur) {
                    cur += 1;
                    positions.push(cur);
                }
                for &p in positions.iter().rev() {
                    if let Some(end) = self.match_parts(data, p, part_idx + 1, steps) {
                        return Some(end);
                    }
                }
                None
            }
            Quantifier::OneOrMore => {
                if !Self::atom_matches(&part.atom, data, pos) {
                    return None;
                }
                let mut positions = Vec::new();
                let mut cur = pos;
                while Self::atom_matches(&part.atom, data, cur) {
                    cur += 1;
                    positions.push(cur);
                }
                for &p in positions.iter().rev() {
                    if let Some(end) = self.match_parts(data, p, part_idx + 1, steps) {
                        return Some(end);
                    }
                }
                None
            }
        }
    }

    fn atom_matches(atom: &RegexAtom, data: &[u8], pos: usize) -> bool {
        match atom {
            RegexAtom::AnyByte => pos < data.len(),
            RegexAtom::Literal(b) => data.get(pos) == Some(b),
            RegexAtom::Class(bytes, negated) => {
                if let Some(b) = data.get(pos) {
                    let found = bytes.contains(b);
                    if *negated { !found } else { found }
                } else {
                    false
                }
            }
        }
    }
}

fn unescape_byte(bytes: &[u8], i: &mut usize) -> Result<u8, HexError> {
    *i += 1; // skip '\'
    match bytes.get(*i) {
        Some(b'x') => {
            *i += 1;
            let hi = hex_nibble(bytes.get(*i).copied().unwrap_or(0))?;
            *i += 1;
            let lo = hex_nibble(bytes.get(*i).copied().unwrap_or(0))?;
            *i += 1;
            Ok((hi << 4) | lo)
        }
        Some(&c) => {
            *i += 1;
            Ok(c)
        }
        None => Err(HexError::Regex("trailing backslash".to_string())),
    }
}

fn hex_nibble(b: u8) -> Result<u8, HexError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(HexError::Regex(format!("invalid hex nibble: {b:#x}"))),
    }
}

fn hex_nibble_val(b: u8) -> Result<u8, HexError> {
    hex_nibble(b)
}

// ─────────────────────────────────────────────────────────────────────────────
// String encoding helpers
// ─────────────────────────────────────────────────────────────────────────────

fn encode_string(s: &str, encoding: Encoding) -> Result<Vec<u8>, HexError> {
    match encoding {
        Encoding::Utf8 => Ok(s.as_bytes().to_vec()),
        Encoding::Ascii => {
            if s.is_ascii() {
                Ok(s.as_bytes().to_vec())
            } else {
                Err(HexError::Encoding("string is not pure ASCII".to_string()))
            }
        }
        Encoding::Latin1 => s
            .chars()
            .map(|c| {
                if (c as u32) <= 0xFF {
                    Ok(c as u8)
                } else {
                    Err(HexError::Encoding(format!("char '{c}' not in Latin-1")))
                }
            })
            .collect(),
        Encoding::Utf16Le => {
            let mut out = Vec::new();
            for c in s.encode_utf16() {
                out.extend_from_slice(&c.to_le_bytes());
            }
            Ok(out)
        }
        Encoding::Utf16Be => {
            let mut out = Vec::new();
            for c in s.encode_utf16() {
                out.extend_from_slice(&c.to_be_bytes());
            }
            Ok(out)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StructuredOverlay
// ─────────────────────────────────────────────────────────────────────────────

/// A collection of typed field reads applied to a buffer at fixed offsets.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StructuredOverlay {
    pub name: String,
    pub fields: Vec<OverlayField>,
}

/// A single field in a `StructuredOverlay`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayField {
    pub name: String,
    pub offset: usize,
    pub data_type: DataType,
    pub comment: String,
}

/// The resolved result of applying a `StructuredOverlay` to a buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayResult {
    pub name: String,
    pub fields: Vec<OverlayFieldResult>,
}

/// A single resolved field from an overlay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayFieldResult {
    pub name: String,
    pub offset: usize,
    pub value: TypedValue,
    pub comment: String,
}

impl StructuredOverlay {
    /// Create a new empty overlay.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            fields: Vec::new(),
        }
    }

    /// Add a field to this overlay.
    pub fn add_field(
        &mut self,
        name: impl Into<String>,
        offset: usize,
        data_type: DataType,
        comment: impl Into<String>,
    ) {
        self.fields.push(OverlayField {
            name: name.into(),
            offset,
            data_type,
            comment: comment.into(),
        });
    }

    /// Apply this overlay to `buf`, reading each field.
    ///
    /// # Errors
    /// Returns `HexError` if any field read fails.
    pub fn apply(&self, buf: &HexBuffer) -> Result<OverlayResult, HexError> {
        let mut results = Vec::with_capacity(self.fields.len());
        for field in &self.fields {
            let value = buf.read_typed(field.offset, field.data_type)?;
            results.push(OverlayFieldResult {
                name: field.name.clone(),
                offset: field.offset,
                value,
                comment: field.comment.clone(),
            });
        }
        Ok(OverlayResult {
            name: self.name.clone(),
            fields: results,
        })
    }

    /// Build a field-name → value map from the applied overlay.
    ///
    /// # Errors
    /// Returns `HexError` if any field read fails.
    pub fn apply_as_map(&self, buf: &HexBuffer) -> Result<HashMap<String, TypedValue>, HexError> {
        let result = self.apply(buf)?;
        Ok(result
            .fields
            .into_iter()
            .map(|f| (f.name, f.value))
            .collect())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── HexBuffer basic ───────────────────────────────────────────────────────

    #[test]
    fn test_new_and_len() {
        let buf = HexBuffer::new(vec![1, 2, 3]);
        assert_eq!(buf.len(), 3);
        assert!(!buf.is_empty());
    }

    #[test]
    fn test_empty() {
        let buf = HexBuffer::empty();
        assert!(buf.is_empty());
    }

    #[test]
    fn test_zeroed() {
        let buf = HexBuffer::zeroed(8);
        assert_eq!(buf.len(), 8);
        assert!(buf.data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_read_in_bounds() {
        let buf = HexBuffer::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(buf.read(0, 2).unwrap(), &[0xDE, 0xAD]);
        assert_eq!(buf.read(2, 2).unwrap(), &[0xBE, 0xEF]);
    }

    #[test]
    fn test_read_out_of_bounds() {
        let buf = HexBuffer::new(vec![1, 2]);
        assert!(buf.read(10, 1).is_err());
    }

    #[test]
    fn test_write_basic() {
        let mut buf = HexBuffer::new(vec![0x00; 4]);
        buf.write(0, &[0xAA, 0xBB]).unwrap();
        assert_eq!(&buf.data[0..2], &[0xAA, 0xBB]);
    }

    #[test]
    fn test_insert_at_start() {
        let mut buf = HexBuffer::new(vec![2, 3]);
        buf.insert(0, &[1]).unwrap();
        assert_eq!(buf.data, vec![1, 2, 3]);
    }

    #[test]
    fn test_insert_at_end() {
        let mut buf = HexBuffer::new(vec![1, 2]);
        buf.insert(2, &[3]).unwrap();
        assert_eq!(buf.data, vec![1, 2, 3]);
    }

    #[test]
    fn test_delete_basic() {
        let mut buf = HexBuffer::new(vec![1, 2, 3, 4]);
        buf.delete(1, 2).unwrap();
        assert_eq!(buf.data, vec![1, 4]);
    }

    // ── Undo / redo ───────────────────────────────────────────────────────────

    #[test]
    fn test_undo_write() {
        let mut buf = HexBuffer::new(vec![0x00, 0x00]);
        buf.write(0, &[0xFF]).unwrap();
        assert_eq!(buf.data[0], 0xFF);
        buf.undo();
        assert_eq!(buf.data[0], 0x00);
    }

    #[test]
    fn test_undo_insert() {
        let mut buf = HexBuffer::new(vec![1, 3]);
        buf.insert(1, &[2]).unwrap();
        assert_eq!(buf.data, vec![1, 2, 3]);
        buf.undo();
        assert_eq!(buf.data, vec![1, 3]);
    }

    #[test]
    fn test_undo_delete() {
        let mut buf = HexBuffer::new(vec![1, 2, 3]);
        buf.delete(1, 1).unwrap();
        assert_eq!(buf.data, vec![1, 3]);
        buf.undo();
        assert_eq!(buf.data, vec![1, 2, 3]);
    }

    #[test]
    fn test_redo() {
        let mut buf = HexBuffer::new(vec![0x00]);
        buf.write(0, &[0xFF]).unwrap();
        buf.undo();
        assert_eq!(buf.data[0], 0x00);
        buf.redo();
        assert_eq!(buf.data[0], 0xFF);
    }

    #[test]
    fn test_undo_empty_stack() {
        let mut buf = HexBuffer::empty();
        assert!(!buf.undo());
        assert!(!buf.redo());
    }

    #[test]
    fn test_clear_history() {
        let mut buf = HexBuffer::new(vec![0]);
        buf.write(0, &[1]).unwrap();
        buf.clear_history();
        assert!(!buf.undo());
        assert!(!buf.redo());
    }

    // ── Block operations ──────────────────────────────────────────────────────

    #[test]
    fn test_fill_single_byte() {
        let mut buf = HexBuffer::new(vec![0u8; 8]);
        buf.fill(2..6, &[0xFF]).unwrap();
        assert_eq!(buf.data, vec![0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0]);
    }

    #[test]
    fn test_fill_pattern() {
        let mut buf = HexBuffer::new(vec![0u8; 6]);
        buf.fill(0..6, &[0xAA, 0xBB]).unwrap();
        assert_eq!(buf.data, vec![0xAA, 0xBB, 0xAA, 0xBB, 0xAA, 0xBB]);
    }

    #[test]
    fn test_reverse_range() {
        let mut buf = HexBuffer::new(vec![1, 2, 3, 4, 5]);
        buf.reverse_range(1..4).unwrap();
        assert_eq!(buf.data, vec![1, 4, 3, 2, 5]);
    }

    #[test]
    fn test_shift_left() {
        let mut buf = HexBuffer::new(vec![1, 2, 3, 4, 5]);
        buf.shift_left(0..5, 2, 0).unwrap();
        assert_eq!(buf.data, vec![3, 4, 5, 0, 0]);
    }

    #[test]
    fn test_shift_right() {
        let mut buf = HexBuffer::new(vec![1, 2, 3, 4, 5]);
        buf.shift_right(0..5, 2, 0).unwrap();
        assert_eq!(buf.data, vec![0, 0, 1, 2, 3]);
    }

    #[test]
    fn test_rotate_left() {
        let mut buf = HexBuffer::new(vec![1, 2, 3, 4, 5]);
        buf.rotate_left(0..5, 2).unwrap();
        assert_eq!(buf.data, vec![3, 4, 5, 1, 2]);
    }

    #[test]
    fn test_rotate_right() {
        let mut buf = HexBuffer::new(vec![1, 2, 3, 4, 5]);
        buf.rotate_right(0..5, 2).unwrap();
        assert_eq!(buf.data, vec![4, 5, 1, 2, 3]);
    }

    // ── Bitwise transforms ────────────────────────────────────────────────────

    #[test]
    fn test_xor_range() {
        let mut buf = HexBuffer::new(vec![0xFF, 0x00, 0xAA]);
        buf.xor_range(0..3, &[0xFF]).unwrap();
        assert_eq!(buf.data, vec![0x00, 0xFF, 0x55]);
    }

    #[test]
    fn test_and_range() {
        let mut buf = HexBuffer::new(vec![0xFF, 0xF0, 0x0F]);
        buf.and_range(0..3, &[0x0F]).unwrap();
        assert_eq!(buf.data, vec![0x0F, 0x00, 0x0F]);
    }

    #[test]
    fn test_or_range() {
        let mut buf = HexBuffer::new(vec![0x00, 0xF0, 0x0F]);
        buf.or_range(0..3, &[0x0F]).unwrap();
        assert_eq!(buf.data, vec![0x0F, 0xFF, 0x0F]);
    }

    #[test]
    fn test_not_range() {
        let mut buf = HexBuffer::new(vec![0xFF, 0x00, 0xAA]);
        buf.not_range(0..3).unwrap();
        assert_eq!(buf.data, vec![0x00, 0xFF, 0x55]);
    }

    #[test]
    fn test_add_range() {
        let mut buf = HexBuffer::new(vec![1, 2, 3]);
        buf.add_range(0..3, 10).unwrap();
        assert_eq!(buf.data, vec![11, 12, 13]);
    }

    #[test]
    fn test_negate_range() {
        let mut buf = HexBuffer::new(vec![0x01, 0x80, 0x00]);
        buf.negate_range(0..3).unwrap();
        assert_eq!(buf.data, vec![0xFF, 0x80, 0x00]);
    }

    // ── Search ────────────────────────────────────────────────────────────────

    #[test]
    fn test_search_single_match() {
        let buf = HexBuffer::new(vec![0, 1, 2, 3, 4]);
        assert_eq!(buf.search(&[2, 3]), vec![2]);
    }

    #[test]
    fn test_search_multiple_matches() {
        let buf = HexBuffer::new(vec![1, 2, 1, 2, 1]);
        assert_eq!(buf.search(&[1, 2]), vec![0, 2]);
    }

    #[test]
    fn test_search_no_match() {
        let buf = HexBuffer::new(vec![1, 2, 3]);
        assert!(buf.search(&[5]).is_empty());
    }

    #[test]
    fn test_search_empty_pattern() {
        let buf = HexBuffer::new(vec![1, 2, 3]);
        assert!(buf.search(&[]).is_empty());
    }

    #[test]
    fn test_find_string_utf8() {
        let buf = HexBuffer::new(b"hello world".to_vec());
        let offsets = buf.find_string("world", Encoding::Utf8).unwrap();
        assert_eq!(offsets, vec![6]);
    }

    #[test]
    fn test_find_string_utf16le() {
        let mut data: Vec<u8> = Vec::new();
        for c in "AB".encode_utf16() {
            data.extend_from_slice(&c.to_le_bytes());
        }
        let buf = HexBuffer::new(data);
        let offsets = buf.find_string("AB", Encoding::Utf16Le).unwrap();
        assert_eq!(offsets, vec![0]);
    }

    #[test]
    fn test_find_hex_pattern() {
        let buf = HexBuffer::new(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xDE, 0x11, 0xBE, 0xEF]);
        let matches = buf.find_hex_pattern("DE ? BE EF").unwrap();
        assert_eq!(matches, vec![0, 5]);
    }

    #[test]
    fn test_find_all_exact() {
        let buf = HexBuffer::new(vec![0xAA, 0xBB, 0xAA, 0xBB]);
        let opts = FindReplaceOptions::default();
        let results = buf.find_all(&[0xAA, 0xBB], &opts).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].offset, 0);
        assert_eq!(results[1].offset, 2);
    }

    #[test]
    fn test_replace_all() {
        let mut buf = HexBuffer::new(vec![0xAA, 0xBB, 0xCC, 0xAA, 0xBB, 0xDD]);
        let opts = FindReplaceOptions::default();
        let count = buf.replace_all(&[0xAA, 0xBB], &[0xFF], &opts).unwrap();
        assert_eq!(count, 2);
    }

    // ── TypedValue reads ──────────────────────────────────────────────────────

    #[test]
    fn test_read_u8() {
        let buf = HexBuffer::new(vec![0x42]);
        assert_eq!(
            buf.read_typed(0, DataType::U8).unwrap(),
            TypedValue::U8(0x42)
        );
    }

    #[test]
    fn test_read_u32le() {
        let buf = HexBuffer::new(vec![0x01, 0x00, 0x00, 0x00]);
        assert_eq!(
            buf.read_typed(0, DataType::U32Le).unwrap(),
            TypedValue::U32(1)
        );
    }

    #[test]
    fn test_read_f32le() {
        let bytes = 1.0f32.to_le_bytes();
        let buf = HexBuffer::new(bytes.to_vec());
        if let TypedValue::F32(v) = buf.read_typed(0, DataType::F32Le).unwrap() {
            assert!((v - 1.0f32).abs() < f32::EPSILON);
        } else {
            panic!("wrong type");
        }
    }

    #[test]
    fn test_read_cstr() {
        let buf = HexBuffer::new(b"hello\0world".to_vec());
        assert_eq!(
            buf.read_typed(0, DataType::CStr).unwrap(),
            TypedValue::Str("hello".to_string())
        );
    }

    #[test]
    fn test_read_typed_out_of_bounds() {
        let buf = HexBuffer::new(vec![0x01]);
        assert!(buf.read_typed(0, DataType::U32Le).is_err());
    }

    // ── ByteStatistics ────────────────────────────────────────────────────────

    #[test]
    fn test_statistics_basic() {
        let buf = HexBuffer::new(vec![0, 1, 2, 3, 4]);
        let stats = buf.statistics().unwrap();
        assert_eq!(stats.total, 5);
        assert_eq!(stats.min, 0);
        assert_eq!(stats.max, 4);
        assert!((stats.mean - 2.0).abs() < 1e-9);
    }

    #[test]
    fn test_statistics_empty() {
        let buf = HexBuffer::empty();
        assert!(buf.statistics().is_err());
    }

    #[test]
    fn test_statistics_uniform_entropy() {
        let data: Vec<u8> = (0u8..=255u8).collect();
        let buf = HexBuffer::new(data);
        let stats = buf.statistics().unwrap();
        assert!((stats.entropy - 8.0).abs() < 0.001);
        assert_eq!(stats.unique_count, 256);
    }

    // ── Histogram ────────────────────────────────────────────────────────────

    #[test]
    fn test_histogram_counts() {
        let buf = HexBuffer::new(vec![0xAA, 0xAA, 0xBB]);
        let hist = buf.histogram();
        assert_eq!(hist.counts[0xAA], 2);
        assert_eq!(hist.counts[0xBB], 1);
        assert_eq!(hist.total, 3);
    }

    #[test]
    fn test_histogram_frequency() {
        let buf = HexBuffer::new(vec![0xFF; 10]);
        let hist = buf.histogram();
        assert!((hist.frequency(0xFF) - 1.0).abs() < 1e-9);
        assert!((hist.frequency(0x00)).abs() < 1e-9);
    }

    #[test]
    fn test_histogram_top_n() {
        let buf = HexBuffer::new(vec![0xAA, 0xAA, 0xBB, 0xCC]);
        let hist = buf.histogram();
        let top = hist.top_n(2);
        assert_eq!(top[0].0, 0xAA);
        assert_eq!(top[0].1, 2);
    }

    // ── HexDiff ───────────────────────────────────────────────────────────────

    #[test]
    fn test_diff_identical() {
        let a = HexBuffer::new(vec![1, 2, 3]);
        let b = HexBuffer::new(vec![1, 2, 3]);
        assert!(HexDiff::compare(&a, &b).is_empty());
    }

    #[test]
    fn test_diff_one_byte() {
        let a = HexBuffer::new(vec![1, 2, 3]);
        let b = HexBuffer::new(vec![1, 9, 3]);
        let regions = HexDiff::compare(&a, &b);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].offset, 1);
        assert_eq!(regions[0].left, vec![2]);
        assert_eq!(regions[0].right, vec![9]);
    }

    #[test]
    fn test_diff_different_lengths() {
        let a = HexBuffer::new(vec![1, 2]);
        let b = HexBuffer::new(vec![1, 2, 3]);
        let regions = HexDiff::compare(&a, &b);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].offset, 2);
    }

    #[test]
    fn test_diff_apply_patch() {
        let mut a = HexBuffer::new(vec![1, 2, 3]);
        let b = HexBuffer::new(vec![1, 9, 3]);
        let regions = HexDiff::compare(&a, &b);
        for r in &regions {
            HexDiff::apply_patch(&mut a, r).unwrap();
        }
        assert_eq!(a.data, vec![1, 9, 3]);
    }

    // ── Entropy ───────────────────────────────────────────────────────────────

    #[test]
    fn test_entropy_uniform() {
        let data: Vec<u8> = (0u8..=255u8).collect();
        let result = entropy(&data, 256);
        assert_eq!(result.len(), 1);
        assert!((result[0] - 8.0).abs() < 0.001);
    }

    #[test]
    fn test_entropy_constant() {
        let data = vec![0u8; 100];
        let result = entropy(&data, 100);
        assert_eq!(result.len(), 1);
        assert!(result[0].abs() < 0.001);
    }

    #[test]
    fn test_entropy_blocks() {
        let data: Vec<u8> = (0u8..128u8).collect();
        let result = entropy(&data, 64);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_entropy_empty() {
        assert!(entropy(&[], 64).is_empty());
    }

    // ── KMP search standalone ─────────────────────────────────────────────────

    #[test]
    fn test_kmp_overlapping() {
        let hay = b"aabaabaab";
        let needle = b"aab";
        let matches = kmp_search(hay, needle);
        assert_eq!(matches, vec![0, 3, 6]);
    }

    // ── Regex search ──────────────────────────────────────────────────────────

    #[test]
    fn test_regex_literal() {
        let data = b"hello world";
        let results = regex_search(data, "world").unwrap();
        assert!(results.contains(&6));
    }

    #[test]
    fn test_regex_dot() {
        let data = b"abc";
        let results = regex_search(data, "a.c").unwrap();
        assert!(results.contains(&0));
    }

    #[test]
    fn test_regex_class() {
        let data = b"cat bat rat";
        let results = regex_search(data, "[cbr]at").unwrap();
        assert!(!results.is_empty());
    }

    // ── MultiCursorState ──────────────────────────────────────────────────────

    #[test]
    fn test_multicursor_initial() {
        let mc = MultiCursorState::new();
        assert_eq!(mc.count(), 1);
        assert_eq!(mc.primary_offset(), 0);
    }

    #[test]
    fn test_multicursor_add_remove() {
        let mut mc = MultiCursorState::new();
        mc.add_cursor(10);
        mc.add_cursor(20);
        assert_eq!(mc.count(), 3);
        mc.remove_cursor(1).unwrap();
        assert_eq!(mc.count(), 2);
    }

    #[test]
    fn test_multicursor_no_duplicates() {
        let mut mc = MultiCursorState::new();
        mc.add_cursor(0); // duplicate of initial cursor
        assert_eq!(mc.count(), 1);
    }

    #[test]
    fn test_multicursor_move_all() {
        let mut mc = MultiCursorState::new();
        mc.add_cursor(10);
        mc.move_all(5, 100);
        assert_eq!(mc.cursors()[0].offset, 5);
        assert_eq!(mc.cursors()[1].offset, 15);
    }

    #[test]
    fn test_multicursor_collapse() {
        let mut mc = MultiCursorState::new();
        mc.add_cursor(10);
        mc.add_cursor(20);
        mc.collapse();
        assert_eq!(mc.count(), 1);
    }

    // ── Cursor selection ──────────────────────────────────────────────────────

    #[test]
    fn test_cursor_selection_range() {
        let mut c = Cursor::new(5);
        assert!(c.selection_range().is_none());
        c.begin_selection();
        c.offset = 10;
        assert_eq!(c.selection_range(), Some(5..10));
    }

    // ── Bookmark ──────────────────────────────────────────────────────────────

    #[test]
    fn test_bookmark_construction() {
        let bm = Bookmark {
            offset: 0x100,
            name: "entry_point".to_string(),
            color: 0xFF_FF_00_00,
        };
        assert_eq!(bm.offset, 0x100);
        assert_eq!(bm.name, "entry_point");
    }

    #[test]
    fn test_buffer_bookmarks() {
        let mut buf = HexBuffer::new(vec![0u8; 256]);
        buf.add_bookmark(0x10, "ep", 0xFF0000);
        buf.add_bookmark(0x20, "str", 0x00FF00);
        assert_eq!(buf.bookmarks.len(), 2);
        assert!(buf.remove_bookmark(0x10));
        assert_eq!(buf.bookmarks.len(), 1);
        assert!(!buf.remove_bookmark(0x99));
    }

    #[test]
    fn test_nearest_bookmark() {
        let mut buf = HexBuffer::new(vec![0u8; 256]);
        buf.add_bookmark(0x10, "a", 0);
        buf.add_bookmark(0x40, "b", 0);
        let nearest = buf.nearest_bookmark(0x15).unwrap();
        assert_eq!(nearest.offset, 0x10);
    }

    // ── DataAnnotation ────────────────────────────────────────────────────────

    #[test]
    fn test_annotation_read() {
        let buf = HexBuffer::new(vec![0x01, 0x00, 0x00, 0x00]);
        let ann = DataAnnotation::new(0, 4, "count", DataType::U32Le);
        let val = ann.read_value(&buf).unwrap();
        assert_eq!(val, TypedValue::U32(1));
    }

    // ── DataType ──────────────────────────────────────────────────────────────

    #[test]
    fn test_datatype_fixed_size() {
        assert_eq!(DataType::U8.fixed_size(), Some(1));
        assert_eq!(DataType::U64Le.fixed_size(), Some(8));
        assert_eq!(DataType::Bytes(16).fixed_size(), Some(16));
        assert_eq!(DataType::CStr.fixed_size(), None);
        assert_eq!(DataType::Utf16(4).fixed_size(), Some(8));
    }

    // ── StructuredOverlay ─────────────────────────────────────────────────────

    #[test]
    fn test_overlay_basic() {
        let buf = HexBuffer::new(vec![0x42, 0x00, 0x01, 0x00, 0x00, 0x00]);
        let mut overlay = StructuredOverlay::new("TestStruct");
        overlay.add_field("byte_field", 0, DataType::U8, "a byte");
        overlay.add_field("u32_field", 1, DataType::U32Le, "a u32");
        let result = overlay.apply(&buf).unwrap();
        assert_eq!(result.fields.len(), 2);
        assert_eq!(result.fields[0].value, TypedValue::U8(0x42));
        assert_eq!(result.fields[1].value, TypedValue::U32(0x0100));
    }

    // ── Virtual address ───────────────────────────────────────────────────────

    #[test]
    fn test_virtual_address_mapping() {
        let mut buf = HexBuffer::new(vec![0u8; 0x100]);
        buf.base_address = 0x0040_0000;
        assert_eq!(buf.virtual_address(0), 0x0040_0000);
        assert_eq!(buf.virtual_address(0x10), 0x0040_0010);
        assert_eq!(buf.offset_for_va(0x0040_0010), Some(0x10));
        assert_eq!(buf.offset_for_va(0x0030_0000), None);
    }

    // ── Read padded ───────────────────────────────────────────────────────────

    #[test]
    fn test_read_padded() {
        let buf = HexBuffer::new(vec![1, 2, 3]);
        let out = buf.read_padded(2, 4);
        assert_eq!(out, vec![3, 0, 0, 0]);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexRegion — a named byte range inside a buffer
// ─────────────────────────────────────────────────────────────────────────────

/// A labelled byte region with optional colour tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HexRegion {
    /// Display name.
    pub name: String,
    /// Start offset (inclusive).
    pub start: usize,
    /// End offset (exclusive).
    pub end: usize,
    /// Optional CSS/hex colour string (e.g. `"#FF0000"`).
    pub colour: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
}

impl HexRegion {
    /// Create a new region.
    #[must_use]
    pub fn new(name: impl Into<String>, start: usize, end: usize) -> Self {
        Self {
            name: name.into(),
            start,
            end,
            colour: None,
            comment: None,
        }
    }

    /// Attach a colour.
    #[must_use]
    pub fn with_colour(mut self, colour: impl Into<String>) -> Self {
        self.colour = Some(colour.into());
        self
    }

    /// Attach a comment.
    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Byte length of the region.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Whether the region is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.end <= self.start
    }

    /// Whether `offset` falls within this region.
    #[must_use]
    pub const fn contains(&self, offset: usize) -> bool {
        offset >= self.start && offset < self.end
    }

    /// Whether this region overlaps with another.
    #[must_use]
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && self.end > other.start
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexRegionMap — set of named regions over a buffer
// ─────────────────────────────────────────────────────────────────────────────

/// A collection of [`HexRegion`]s over a single buffer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HexRegionMap {
    regions: Vec<HexRegion>,
}

impl HexRegionMap {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a region.
    pub fn add(&mut self, region: HexRegion) {
        self.regions.push(region);
    }

    /// Remove a region by name (first match).
    pub fn remove(&mut self, name: &str) -> bool {
        if let Some(pos) = self.regions.iter().position(|r| r.name == name) {
            self.regions.remove(pos);
            true
        } else {
            false
        }
    }

    /// Find regions that contain the given offset.
    #[must_use]
    pub fn at_offset(&self, offset: usize) -> Vec<&HexRegion> {
        self.regions.iter().filter(|r| r.contains(offset)).collect()
    }

    /// Find a region by name (first match).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&HexRegion> {
        self.regions.iter().find(|r| r.name == name)
    }

    /// All regions.
    #[must_use]
    pub fn all(&self) -> &[HexRegion] {
        &self.regions
    }

    /// Number of regions.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.regions.len()
    }

    /// Whether the map is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Sort regions by start offset.
    pub fn sort(&mut self) {
        self.regions.sort_by_key(|r| r.start);
    }

    /// Find any overlapping pairs of regions.
    #[must_use]
    pub fn overlapping_pairs(&self) -> Vec<(&HexRegion, &HexRegion)> {
        let mut pairs = Vec::new();
        for i in 0..self.regions.len() {
            for j in (i + 1)..self.regions.len() {
                if self.regions[i].overlaps(&self.regions[j]) {
                    pairs.push((&self.regions[i], &self.regions[j]));
                }
            }
        }
        pairs
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ByteClass — classify bytes into categories
// ─────────────────────────────────────────────────────────────────────────────

/// Broad classification of a single byte value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ByteClass {
    Null,
    PrintableAscii,
    ControlAscii,
    HighByte,
}

impl ByteClass {
    /// Classify a single byte.
    #[must_use]
    pub const fn of(b: u8) -> Self {
        match b {
            0 => Self::Null,
            0x01..=0x1F | 0x7F => Self::ControlAscii,
            0x20..=0x7E => Self::PrintableAscii,
            _ => Self::HighByte,
        }
    }

    /// Whether the byte is printable ASCII.
    #[must_use]
    pub fn is_printable(self) -> bool {
        self == Self::PrintableAscii
    }
}

/// Classify all bytes in a slice.
#[must_use]
pub fn classify_bytes(data: &[u8]) -> Vec<ByteClass> {
    data.iter().map(|&b| ByteClass::of(b)).collect()
}

/// Count printable ASCII bytes in a slice.
#[must_use]
pub fn printable_count(data: &[u8]) -> usize {
    data.iter()
        .filter(|&&b| ByteClass::of(b).is_printable())
        .count()
}

/// Count null bytes in a slice.
#[must_use]
pub fn null_count(data: &[u8]) -> usize {
    data.iter().filter(|&&b| b == 0).count()
}

// ─────────────────────────────────────────────────────────────────────────────
// RunLengthSummary — compress repeated bytes
// ─────────────────────────────────────────────────────────────────────────────

/// A run of identical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteRun {
    /// The repeated byte value.
    pub value: u8,
    /// Offset of the first byte in the run.
    pub offset: usize,
    /// Length of the run.
    pub length: usize,
}

impl ByteRun {
    /// Create a new run record.
    #[must_use]
    pub const fn new(value: u8, offset: usize, length: usize) -> Self {
        Self {
            value,
            offset,
            length,
        }
    }

    /// End offset (exclusive) of the run.
    #[must_use]
    pub const fn end(&self) -> usize {
        self.offset + self.length
    }
}

/// Compute the run-length encoding of a byte slice.
#[must_use]
pub fn run_length_encode(data: &[u8]) -> Vec<ByteRun> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut runs = Vec::new();
    let mut current_val = data[0];
    let mut current_start = 0usize;
    let mut current_len = 1usize;
    for (i, &b) in data.iter().enumerate().skip(1) {
        if b == current_val {
            current_len += 1;
        } else {
            runs.push(ByteRun::new(current_val, current_start, current_len));
            current_val = b;
            current_start = i;
            current_len = 1;
        }
    }
    runs.push(ByteRun::new(current_val, current_start, current_len));
    runs
}

/// Find the longest run in the run-length encoding.
#[must_use]
pub fn longest_run(data: &[u8]) -> Option<ByteRun> {
    run_length_encode(data).into_iter().max_by_key(|r| r.length)
}

// ─────────────────────────────────────────────────────────────────────────────
// ByteFrequency — frequency analysis of individual byte values
// ─────────────────────────────────────────────────────────────────────────────

/// Frequency analysis results for a byte slice.
#[derive(Debug, Clone)]
pub struct ByteFrequency {
    /// Counts indexed by byte value 0–255.
    pub counts: [u64; 256],
    /// Total bytes analysed.
    pub total: u64,
}

impl ByteFrequency {
    /// Compute frequency for a slice.
    #[must_use]
    pub fn compute(data: &[u8]) -> Self {
        let mut counts = [0u64; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        Self {
            counts,
            total: data.len() as u64,
        }
    }

    /// Fraction of total bytes that have value `b`.
    #[must_use]
    pub fn frequency(&self, b: u8) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        self.counts[b as usize] as f64 / self.total as f64
    }

    /// Most common byte value and its count.
    #[must_use]
    pub fn most_common(&self) -> (u8, u64) {
        let (idx, count) = self
            .counts
            .iter()
            .enumerate()
            .max_by_key(|(_, c)| *c)
            .map_or((0, 0), |(i, c)| (i, *c));
        (idx as u8, count)
    }

    /// Least common byte value that appears at least once.
    #[must_use]
    pub fn least_common_nonzero(&self) -> Option<(u8, u64)> {
        self.counts
            .iter()
            .enumerate()
            .filter(|(_, c)| **c > 0)
            .min_by_key(|(_, c)| *c)
            .map(|(i, c)| (i as u8, *c))
    }

    /// Number of distinct byte values that appear at least once.
    #[must_use]
    pub fn distinct_count(&self) -> usize {
        self.counts.iter().filter(|&&c| c > 0).count()
    }

    /// Shannon entropy computed from the frequency table.
    #[must_use]
    pub fn entropy(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let total = self.total as f64;
        self.counts
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / total;
                -p * p.log2()
            })
            .sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexAnnotation — user notes attached to byte offsets
// ─────────────────────────────────────────────────────────────────────────────

/// A user annotation attached to a specific byte offset in a buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexAnnotation {
    /// Byte offset.
    pub offset: usize,
    /// Length in bytes (may be 1).
    pub length: usize,
    /// Annotation text.
    pub text: String,
    /// Optional colour string.
    pub colour: Option<String>,
}

impl HexAnnotation {
    /// Create a new single-byte annotation.
    #[must_use]
    pub fn new(offset: usize, text: impl Into<String>) -> Self {
        Self {
            offset,
            length: 1,
            text: text.into(),
            colour: None,
        }
    }

    /// Extend to cover a span.
    #[must_use]
    pub const fn with_length(mut self, length: usize) -> Self {
        self.length = length;
        self
    }

    /// Attach a colour.
    #[must_use]
    pub fn with_colour(mut self, colour: impl Into<String>) -> Self {
        self.colour = Some(colour.into());
        self
    }

    /// End offset (exclusive).
    #[must_use]
    pub const fn end(&self) -> usize {
        self.offset + self.length
    }

    /// Whether `offset` falls within this annotation's span.
    #[must_use]
    pub const fn contains(&self, offset: usize) -> bool {
        offset >= self.offset && offset < self.offset + self.length
    }
}

/// A collection of [`HexAnnotation`]s.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HexAnnotationSet {
    annotations: Vec<HexAnnotation>,
}

impl HexAnnotationSet {
    /// Create an empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an annotation.
    pub fn add(&mut self, ann: HexAnnotation) {
        self.annotations.push(ann);
    }

    /// Annotations that cover the given offset.
    #[must_use]
    pub fn at(&self, offset: usize) -> Vec<&HexAnnotation> {
        self.annotations
            .iter()
            .filter(|a| a.contains(offset))
            .collect()
    }

    /// All annotations.
    #[must_use]
    pub fn all(&self) -> &[HexAnnotation] {
        &self.annotations
    }

    /// Number of annotations.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.annotations.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.annotations.is_empty()
    }

    /// Remove annotation at given offset (first match).
    pub fn remove_at(&mut self, offset: usize) -> bool {
        if let Some(pos) = self.annotations.iter().position(|a| a.offset == offset) {
            self.annotations.remove(pos);
            true
        } else {
            false
        }
    }

    /// Serialise to JSON.
    ///
    /// # Errors
    /// Returns an error if JSON serialisation fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.annotations)
    }

    /// Deserialise from JSON.
    ///
    /// # Errors
    /// Returns an error if JSON deserialisation fails.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        let annotations = serde_json::from_str(json)?;
        Ok(Self { annotations })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexBookmark — named positions in a buffer
// ─────────────────────────────────────────────────────────────────────────────

/// A named cursor position in a buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexBookmark {
    /// Bookmark name.
    pub name: String,
    /// Byte offset.
    pub offset: usize,
    /// Optional description.
    pub description: Option<String>,
}

impl HexBookmark {
    /// Create a new bookmark.
    #[must_use]
    pub fn new(name: impl Into<String>, offset: usize) -> Self {
        Self {
            name: name.into(),
            offset,
            description: None,
        }
    }

    /// Attach a description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

/// An ordered list of [`HexBookmark`]s.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HexBookmarkList {
    bookmarks: Vec<HexBookmark>,
}

impl HexBookmarkList {
    /// Create an empty list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a bookmark.
    pub fn add(&mut self, bookmark: HexBookmark) {
        self.bookmarks.push(bookmark);
    }

    /// Find a bookmark by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&HexBookmark> {
        self.bookmarks.iter().find(|b| b.name == name)
    }

    /// Remove a bookmark by name (first match).
    pub fn remove(&mut self, name: &str) -> bool {
        if let Some(pos) = self.bookmarks.iter().position(|b| b.name == name) {
            self.bookmarks.remove(pos);
            true
        } else {
            false
        }
    }

    /// All bookmarks.
    #[must_use]
    pub fn all(&self) -> &[HexBookmark] {
        &self.bookmarks
    }

    /// Number of bookmarks.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bookmarks.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bookmarks.is_empty()
    }

    /// Sort bookmarks by offset.
    pub fn sort_by_offset(&mut self) {
        self.bookmarks.sort_by_key(|b| b.offset);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexCompareResult — compare two buffers byte by byte
// ─────────────────────────────────────────────────────────────────────────────

/// The result of comparing two byte buffers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexCompareResult {
    /// Offsets where the two buffers differ.
    pub diff_offsets: Vec<usize>,
    /// Length of the shorter buffer.
    pub compared_len: usize,
    /// Number of matching bytes.
    pub matching: usize,
    /// Number of differing bytes.
    pub differing: usize,
}

impl HexCompareResult {
    /// Compute the comparison result.
    #[must_use]
    pub fn compare(a: &[u8], b: &[u8]) -> Self {
        let len = a.len().min(b.len());
        let mut diffs = Vec::new();
        for i in 0..len {
            if a[i] != b[i] {
                diffs.push(i);
            }
        }
        let differing = diffs.len();
        let matching = len - differing;
        Self {
            diff_offsets: diffs,
            compared_len: len,
            matching,
            differing,
        }
    }

    /// Whether the buffers are identical in the compared range.
    #[must_use]
    pub const fn is_identical(&self) -> bool {
        self.differing == 0
    }

    /// Similarity as a fraction [0.0, 1.0].
    #[must_use]
    pub fn similarity(&self) -> f64 {
        if self.compared_len == 0 {
            return 1.0;
        }
        self.matching as f64 / self.compared_len as f64
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexPatch — a record of a single-byte or multi-byte patch
// ─────────────────────────────────────────────────────────────────────────────

/// A byte-level patch (original → replacement).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexPatch {
    /// Byte offset.
    pub offset: usize,
    /// Original bytes (before patch).
    pub original: Vec<u8>,
    /// Replacement bytes.
    pub replacement: Vec<u8>,
    /// Optional description.
    pub description: Option<String>,
}

impl HexPatch {
    /// Create a patch.
    #[must_use]
    pub const fn new(offset: usize, original: Vec<u8>, replacement: Vec<u8>) -> Self {
        Self {
            offset,
            original,
            replacement,
            description: None,
        }
    }

    /// Attach a description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Apply this patch to a mutable byte buffer.
    ///
    /// # Errors
    /// Returns `HexError::OutOfBounds` if the patch extends beyond the buffer.
    pub fn apply(&self, buf: &mut [u8]) -> Result<(), HexError> {
        let end = self.offset + self.replacement.len();
        if end > buf.len() {
            return Err(HexError::OutOfBounds(end, buf.len()));
        }
        buf[self.offset..end].copy_from_slice(&self.replacement);
        Ok(())
    }

    /// Revert this patch (apply original bytes back).
    ///
    /// # Errors
    /// Returns `HexError::OutOfBounds` if the revert extends beyond the buffer.
    pub fn revert(&self, buf: &mut [u8]) -> Result<(), HexError> {
        let end = self.offset + self.original.len();
        if end > buf.len() {
            return Err(HexError::OutOfBounds(end, buf.len()));
        }
        buf[self.offset..end].copy_from_slice(&self.original);
        Ok(())
    }
}

/// A set of patches that can be applied together.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HexPatchSet {
    patches: Vec<HexPatch>,
}

impl HexPatchSet {
    /// Create an empty patch set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a patch.
    pub fn add(&mut self, patch: HexPatch) {
        self.patches.push(patch);
    }

    /// Number of patches.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.patches.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }

    /// Apply all patches to a buffer in order.
    ///
    /// # Errors
    /// Returns the first `HexError` encountered.
    pub fn apply_all(&self, buf: &mut [u8]) -> Result<(), HexError> {
        for p in &self.patches {
            p.apply(buf)?;
        }
        Ok(())
    }

    /// Revert all patches in reverse order.
    ///
    /// # Errors
    /// Returns the first `HexError` encountered.
    pub fn revert_all(&self, buf: &mut [u8]) -> Result<(), HexError> {
        for p in self.patches.iter().rev() {
            p.revert(buf)?;
        }
        Ok(())
    }

    /// Serialise to JSON.
    ///
    /// # Errors
    /// Returns an error if JSON serialisation fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.patches)
    }

    /// Deserialise from JSON.
    ///
    /// # Errors
    /// Returns an error if JSON deserialisation fails.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        let patches = serde_json::from_str(json)?;
        Ok(Self { patches })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CrcComputer — standard CRC variants
// ─────────────────────────────────────────────────────────────────────────────

/// Computes CRC-32 (IEEE 802.3 polynomial 0xEDB88320, bit-reversed).
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Computes CRC-16-IBM (polynomial 0x8005, reflected as 0xA001).
#[must_use]
pub fn crc16_ibm(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= u16::from(b);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// Computes CRC-16-CCITT (polynomial 0x1021, initial value 0xFFFF).
#[must_use]
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        let mut x = (crc >> 8) ^ u16::from(b);
        x ^= x >> 4;
        crc = (crc << 8) ^ (x << 12) ^ (x << 5) ^ x;
    }
    crc
}

/// Computes Adler-32 (as used in PNG/zlib).
#[must_use]
pub fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// Computes FNV-1a 32-bit hash.
#[must_use]
pub fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for &b in data {
        hash ^= u32::from(b);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// Computes FNV-1a 64-bit hash.
#[must_use]
pub fn fnv1a64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

// ─────────────────────────────────────────────────────────────────────────────
// HexChunk — divide a buffer into fixed-size chunks
// ─────────────────────────────────────────────────────────────────────────────

/// A single chunk of bytes with its offset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexChunk {
    /// Start offset in the original buffer.
    pub offset: usize,
    /// The bytes in this chunk.
    pub data: Vec<u8>,
}

impl HexChunk {
    /// Whether this chunk contains no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Number of bytes in this chunk.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }
}

/// Divide `data` into chunks of at most `chunk_size` bytes.
#[must_use]
pub fn chunk_bytes(data: &[u8], chunk_size: usize) -> Vec<HexChunk> {
    if chunk_size == 0 || data.is_empty() {
        return Vec::new();
    }
    data.chunks(chunk_size)
        .enumerate()
        .map(|(i, chunk)| HexChunk {
            offset: i * chunk_size,
            data: chunk.to_vec(),
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// StringExtractor — extract printable strings from raw bytes
// ─────────────────────────────────────────────────────────────────────────────

/// A printable string found in a byte buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    /// Byte offset where the string begins.
    pub offset: usize,
    /// The string value.
    pub value: String,
    /// Encoding used.
    pub encoding: Encoding,
}

/// Extract null-terminated ASCII/UTF-8 strings of at least `min_len` chars.
#[must_use]
pub fn extract_strings(data: &[u8], min_len: usize) -> Vec<ExtractedString> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &b) in data.iter().enumerate() {
        if (0x20..=0x7E).contains(&b) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            let len = i - s;
            if len >= min_len
                && let Ok(val) = std::str::from_utf8(&data[s..i]) {
                    out.push(ExtractedString {
                        offset: s,
                        value: val.to_string(),
                        encoding: Encoding::Utf8,
                    });
                }
        }
    }
    // Handle string that runs to end of buffer
    if let Some(s) = start {
        let len = data.len() - s;
        if len >= min_len
            && let Ok(val) = std::str::from_utf8(&data[s..]) {
                out.push(ExtractedString {
                    offset: s,
                    value: val.to_string(),
                    encoding: Encoding::Utf8,
                });
            }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// HexLine — display model for a single hex editor line
// ─────────────────────────────────────────────────────────────────────────────

/// A single rendered line of hex display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexLine {
    /// Starting offset for this line.
    pub offset: usize,
    /// Raw bytes (up to `width` bytes).
    pub bytes: Vec<u8>,
    /// Width (number of bytes per line).
    pub width: usize,
}

impl HexLine {
    /// Create a new line.
    #[must_use]
    pub const fn new(offset: usize, bytes: Vec<u8>, width: usize) -> Self {
        Self {
            offset,
            bytes,
            width,
        }
    }

    /// Render the line as an address + hex + ASCII string.
    #[must_use]
    pub fn render(&self) -> String {
        let addr = format!("{:08X}", self.offset);
        let hex_part: String = {
            let mut s = String::new();
            for (i, &b) in self.bytes.iter().enumerate() {
                if i > 0 && i.is_multiple_of(8) {
                    s.push(' ');
                }
                s.push_str(&format!("{b:02X} "));
            }
            // Pad to full width
            let rendered = self.bytes.len();
            for i in rendered..self.width {
                if i > 0 && i.is_multiple_of(8) {
                    s.push(' ');
                }
                s.push_str("   ");
            }
            s
        };
        let ascii_part: String = self
            .bytes
            .iter()
            .map(|&b| {
                if (0x20..0x7F).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        format!("{addr}  {hex_part} |{ascii_part}|")
    }
}

/// Render a byte slice into a list of [`HexLine`]s.
#[must_use]
pub fn render_hex_lines(data: &[u8], width: usize) -> Vec<HexLine> {
    if width == 0 {
        return Vec::new();
    }
    data.chunks(width)
        .enumerate()
        .map(|(i, chunk)| HexLine::new(i * width, chunk.to_vec(), width))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────────────────────

/// Convert a byte slice to an uppercase hex string with no separators.
#[must_use]
pub fn bytes_to_hex_string(data: &[u8]) -> String {
    data.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02X}"); acc })
}

/// Convert a hex string (with optional spaces) to bytes.
///
/// # Errors
/// Returns `HexError::Encoding` if the string contains invalid hex characters.
pub fn hex_string_to_bytes(s: &str) -> Result<Vec<u8>, HexError> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !s.len().is_multiple_of(2) {
        return Err(HexError::Encoding(
            "hex string has odd number of hex digits".to_string(),
        ));
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|e| HexError::Encoding(e.to_string()))
        })
        .collect()
}

/// Decode bytes as a null-terminated C string.
///
/// Returns the string up to the first null byte, or the entire slice if no null.
#[must_use]
pub fn decode_cstr(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

/// Decode a fixed-length UTF-16LE string.
///
/// # Errors
/// Returns `HexError::Encoding` if the slice has odd length.
pub fn decode_utf16le(data: &[u8]) -> Result<String, HexError> {
    if !data.len().is_multiple_of(2) {
        return Err(HexError::Encoding(
            "UTF-16LE data has odd byte count".to_string(),
        ));
    }
    let words: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&w| w != 0)
        .collect();
    String::from_utf16(&words).map_err(|e| HexError::Encoding(e.to_string()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for expanded functionality
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests_expanded {
    use super::*;

    // ── HexRegion ─────────────────────────────────────────────────────────────

    #[test]
    fn test_region_basic() {
        let r = HexRegion::new("header", 0, 64);
        assert_eq!(r.len(), 64);
        assert!(!r.is_empty());
        assert!(r.contains(32));
        assert!(!r.contains(64));
    }

    #[test]
    fn test_region_empty() {
        let r = HexRegion::new("empty", 10, 10);
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn test_region_overlaps() {
        let a = HexRegion::new("a", 0, 10);
        let b = HexRegion::new("b", 5, 15);
        assert!(a.overlaps(&b));
    }

    #[test]
    fn test_region_no_overlap() {
        let a = HexRegion::new("a", 0, 10);
        let b = HexRegion::new("b", 10, 20);
        assert!(!a.overlaps(&b));
    }

    #[test]
    fn test_region_with_colour_and_comment() {
        let r = HexRegion::new("x", 0, 4)
            .with_colour("#FF0000")
            .with_comment("magic bytes");
        assert_eq!(r.colour.as_deref(), Some("#FF0000"));
        assert_eq!(r.comment.as_deref(), Some("magic bytes"));
    }

    // ── HexRegionMap ──────────────────────────────────────────────────────────

    #[test]
    fn test_region_map_add_and_get() {
        let mut m = HexRegionMap::new();
        m.add(HexRegion::new("hdr", 0, 16));
        assert_eq!(m.len(), 1);
        assert!(m.get("hdr").is_some());
    }

    #[test]
    fn test_region_map_at_offset() {
        let mut m = HexRegionMap::new();
        m.add(HexRegion::new("a", 0, 10));
        m.add(HexRegion::new("b", 5, 15));
        let hits = m.at_offset(7);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn test_region_map_remove() {
        let mut m = HexRegionMap::new();
        m.add(HexRegion::new("x", 0, 4));
        assert!(m.remove("x"));
        assert!(!m.remove("x"));
        assert!(m.is_empty());
    }

    #[test]
    fn test_region_map_overlapping_pairs() {
        let mut m = HexRegionMap::new();
        m.add(HexRegion::new("a", 0, 10));
        m.add(HexRegion::new("b", 5, 15));
        m.add(HexRegion::new("c", 20, 30));
        let pairs = m.overlapping_pairs();
        assert_eq!(pairs.len(), 1);
    }

    // ── ByteClass ─────────────────────────────────────────────────────────────

    #[test]
    fn test_byte_class_null() {
        assert_eq!(ByteClass::of(0), ByteClass::Null);
    }

    #[test]
    fn test_byte_class_printable() {
        assert_eq!(ByteClass::of(b'A'), ByteClass::PrintableAscii);
        assert!(ByteClass::of(b'Z').is_printable());
    }

    #[test]
    fn test_byte_class_control() {
        assert_eq!(ByteClass::of(0x01), ByteClass::ControlAscii);
        assert_eq!(ByteClass::of(0x7F), ByteClass::ControlAscii);
    }

    #[test]
    fn test_byte_class_high() {
        assert_eq!(ByteClass::of(0xFF), ByteClass::HighByte);
    }

    #[test]
    fn test_classify_bytes() {
        let data = [0x00, 0x41, 0x01, 0xFF];
        let classes = classify_bytes(&data);
        assert_eq!(classes[0], ByteClass::Null);
        assert_eq!(classes[1], ByteClass::PrintableAscii);
        assert_eq!(classes[2], ByteClass::ControlAscii);
        assert_eq!(classes[3], ByteClass::HighByte);
    }

    #[test]
    fn test_printable_count() {
        let data = b"hello\x00world";
        assert_eq!(printable_count(data), 10);
    }

    #[test]
    fn test_null_count() {
        let data = [0u8, 1, 0, 2, 0];
        assert_eq!(null_count(&data), 3);
    }

    // ── ByteRun / run_length_encode ───────────────────────────────────────────

    #[test]
    fn test_rle_empty() {
        assert!(run_length_encode(&[]).is_empty());
    }

    #[test]
    fn test_rle_single_run() {
        let data = [0xAAu8; 5];
        let runs = run_length_encode(&data);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].value, 0xAA);
        assert_eq!(runs[0].length, 5);
        assert_eq!(runs[0].offset, 0);
    }

    #[test]
    fn test_rle_multiple_runs() {
        let data = [0x00u8, 0x00, 0xFF, 0xFF, 0xFF, 0x01];
        let runs = run_length_encode(&data);
        assert_eq!(runs.len(), 3);
        assert_eq!(runs[1].value, 0xFF);
        assert_eq!(runs[1].length, 3);
    }

    #[test]
    fn test_rle_end_offset() {
        let data = [0xAAu8; 4];
        let runs = run_length_encode(&data);
        assert_eq!(runs[0].end(), 4);
    }

    #[test]
    fn test_longest_run() {
        let data = [0x00u8, 0xFF, 0xFF, 0xFF, 0x00];
        let run = longest_run(&data).unwrap();
        assert_eq!(run.value, 0xFF);
        assert_eq!(run.length, 3);
    }

    #[test]
    fn test_longest_run_empty() {
        assert!(longest_run(&[]).is_none());
    }

    // ── ByteFrequency ─────────────────────────────────────────────────────────

    #[test]
    fn test_frequency_empty() {
        let f = ByteFrequency::compute(&[]);
        assert_eq!(f.total, 0);
        assert_eq!(f.entropy(), 0.0);
    }

    #[test]
    fn test_frequency_single_value() {
        let data = [0x42u8; 100];
        let f = ByteFrequency::compute(&data);
        assert_eq!(f.counts[0x42], 100);
        assert_eq!(f.distinct_count(), 1);
        assert!((f.entropy() - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_frequency_two_equal_values() {
        let data: Vec<u8> = (0u8..2).cycle().take(256).collect();
        let f = ByteFrequency::compute(&data);
        assert_eq!(f.distinct_count(), 2);
        let h = f.entropy();
        assert!((h - 1.0).abs() < 1e-6, "entropy={h}");
    }

    #[test]
    fn test_frequency_most_common() {
        let mut data = vec![0xFFu8; 10];
        data.extend_from_slice(&[0x00; 5]);
        let f = ByteFrequency::compute(&data);
        let (val, cnt) = f.most_common();
        assert_eq!(val, 0xFF);
        assert_eq!(cnt, 10);
    }

    #[test]
    fn test_frequency_least_common_nonzero() {
        let data = [0x01u8, 0x02, 0x02, 0x02];
        let f = ByteFrequency::compute(&data);
        let (val, cnt) = f.least_common_nonzero().unwrap();
        assert_eq!(val, 0x01);
        assert_eq!(cnt, 1);
    }

    // ── HexAnnotation ─────────────────────────────────────────────────────────

    #[test]
    fn test_annotation_new() {
        let a = HexAnnotation::new(42, "test");
        assert_eq!(a.offset, 42);
        assert_eq!(a.length, 1);
        assert_eq!(a.text, "test");
        assert!(a.contains(42));
        assert!(!a.contains(43));
    }

    #[test]
    fn test_annotation_with_length() {
        let a = HexAnnotation::new(10, "span").with_length(8);
        assert_eq!(a.end(), 18);
        assert!(a.contains(17));
        assert!(!a.contains(18));
    }

    #[test]
    fn test_annotation_set_add_and_query() {
        let mut s = HexAnnotationSet::new();
        s.add(HexAnnotation::new(5, "hi").with_length(3));
        s.add(HexAnnotation::new(10, "there"));
        assert_eq!(s.at(6).len(), 1);
        assert_eq!(s.at(11).len(), 0);
    }

    #[test]
    fn test_annotation_set_remove() {
        let mut s = HexAnnotationSet::new();
        s.add(HexAnnotation::new(0, "first"));
        assert!(s.remove_at(0));
        assert!(!s.remove_at(0));
        assert!(s.is_empty());
    }

    #[test]
    fn test_annotation_set_json_roundtrip() {
        let mut s = HexAnnotationSet::new();
        s.add(HexAnnotation::new(0, "magic").with_colour("red"));
        let json = s.to_json().unwrap();
        let s2 = HexAnnotationSet::from_json(&json).unwrap();
        assert_eq!(s2.len(), 1);
    }

    // ── HexBookmark ───────────────────────────────────────────────────────────

    #[test]
    fn test_bookmark_add_and_get() {
        let mut list = HexBookmarkList::new();
        list.add(HexBookmark::new("entry", 0x1000));
        assert_eq!(list.get("entry").unwrap().offset, 0x1000);
    }

    #[test]
    fn test_bookmark_remove() {
        let mut list = HexBookmarkList::new();
        list.add(HexBookmark::new("a", 0));
        assert!(list.remove("a"));
        assert!(!list.remove("a"));
    }

    #[test]
    fn test_bookmark_sort() {
        let mut list = HexBookmarkList::new();
        list.add(HexBookmark::new("z", 100));
        list.add(HexBookmark::new("a", 0));
        list.sort_by_offset();
        assert_eq!(list.all()[0].name, "a");
    }

    // ── HexCompareResult ──────────────────────────────────────────────────────

    #[test]
    fn test_compare_identical() {
        let a = [0x01u8, 0x02, 0x03];
        let result = HexCompareResult::compare(&a, &a);
        assert!(result.is_identical());
        assert!((result.similarity() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_compare_one_diff() {
        let a = [0x01u8, 0x02, 0x03];
        let b = [0x01u8, 0xFF, 0x03];
        let result = HexCompareResult::compare(&a, &b);
        assert_eq!(result.differing, 1);
        assert_eq!(result.diff_offsets, vec![1]);
        assert!((result.similarity() - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn test_compare_empty_buffers() {
        let result = HexCompareResult::compare(&[], &[]);
        assert!(result.is_identical());
        assert!((result.similarity() - 1.0).abs() < 1e-9);
    }

    // ── HexPatch ──────────────────────────────────────────────────────────────

    #[test]
    fn test_patch_apply_and_revert() {
        let mut buf = vec![0x90u8, 0x90, 0x90, 0x90];
        let patch = HexPatch::new(1, vec![0x90, 0x90], vec![0xEB, 0x02]);
        patch.apply(&mut buf).unwrap();
        assert_eq!(buf, vec![0x90, 0xEB, 0x02, 0x90]);
        patch.revert(&mut buf).unwrap();
        assert_eq!(buf, vec![0x90, 0x90, 0x90, 0x90]);
    }

    #[test]
    fn test_patch_out_of_bounds() {
        let mut buf = vec![0x00u8; 4];
        let patch = HexPatch::new(3, vec![0x00], vec![0xFF, 0xFF]);
        assert!(patch.apply(&mut buf).is_err());
    }

    #[test]
    fn test_patch_set_apply_all() {
        let mut buf = vec![0x00u8, 0x01, 0x02, 0x03];
        let mut ps = HexPatchSet::new();
        ps.add(HexPatch::new(0, vec![0x00], vec![0xAA]));
        ps.add(HexPatch::new(3, vec![0x03], vec![0xBB]));
        ps.apply_all(&mut buf).unwrap();
        assert_eq!(buf[0], 0xAA);
        assert_eq!(buf[3], 0xBB);
    }

    #[test]
    fn test_patch_set_revert_all() {
        let mut buf = vec![0xAAu8, 0x01, 0x02, 0xBB];
        let mut ps = HexPatchSet::new();
        ps.add(HexPatch::new(0, vec![0x00], vec![0xAA]));
        ps.add(HexPatch::new(3, vec![0x03], vec![0xBB]));
        ps.revert_all(&mut buf).unwrap();
        assert_eq!(buf[0], 0x00);
        assert_eq!(buf[3], 0x03);
    }

    #[test]
    fn test_patch_set_json_roundtrip() {
        let mut ps = HexPatchSet::new();
        ps.add(HexPatch::new(0, vec![0x00], vec![0xFF]).with_description("nop patch"));
        let json = ps.to_json().unwrap();
        let ps2 = HexPatchSet::from_json(&json).unwrap();
        assert_eq!(ps2.len(), 1);
    }

    // ── CRC functions ─────────────────────────────────────────────────────────

    #[test]
    fn test_crc32_empty() {
        assert_eq!(crc32(&[]), 0x0000_0000);
    }

    #[test]
    fn test_crc32_known() {
        // CRC-32 of b"123456789" is 0xCBF43926
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn test_crc16_ibm_empty() {
        assert_eq!(crc16_ibm(&[]), 0x0000);
    }

    #[test]
    fn test_crc16_ccitt_known() {
        // CRC-16-CCITT of empty is 0xFFFF (initial value with no updates)
        assert_eq!(crc16_ccitt(&[]), 0xFFFF);
    }

    #[test]
    fn test_adler32_empty() {
        // Adler-32 of empty data: a=1, b=0 → 0x00000001
        assert_eq!(adler32(&[]), 0x0000_0001);
    }

    #[test]
    fn test_adler32_known() {
        // Wikipedia: adler32 of "Wikipedia" = 0x11E60398
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }

    #[test]
    fn test_fnv1a32_basic() {
        let h = fnv1a32(b"hello");
        assert_ne!(h, 0);
        assert_eq!(fnv1a32(b"hello"), h); // deterministic
    }

    #[test]
    fn test_fnv1a64_basic() {
        let h = fnv1a64(b"hello");
        assert_ne!(h, 0);
        assert_eq!(fnv1a64(b"hello"), h);
    }

    // ── HexChunk ──────────────────────────────────────────────────────────────

    #[test]
    fn test_chunk_bytes_basic() {
        let data: Vec<u8> = (0..10).collect();
        let chunks = chunk_bytes(&data, 4);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].data, vec![0, 1, 2, 3]);
        assert_eq!(chunks[2].data, vec![8, 9]);
    }

    #[test]
    fn test_chunk_bytes_exact() {
        let data = vec![0u8; 8];
        let chunks = chunk_bytes(&data, 4);
        assert_eq!(chunks.len(), 2);
    }

    #[test]
    fn test_chunk_bytes_zero_size() {
        assert!(chunk_bytes(&[0u8; 10], 0).is_empty());
    }

    // ── extract_strings ───────────────────────────────────────────────────────

    #[test]
    fn test_extract_strings_basic() {
        let data = b"\x00Hello\x00World\x00";
        let strings = extract_strings(data, 4);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].value, "Hello");
        assert_eq!(strings[1].value, "World");
    }

    #[test]
    fn test_extract_strings_min_len() {
        let data = b"AB\x00CDEFGH\x00";
        let strings = extract_strings(data, 4);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "CDEFGH");
    }

    #[test]
    fn test_extract_strings_no_null() {
        let data = b"Hello";
        let strings = extract_strings(data, 3);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "Hello");
    }

    // ── HexLine ───────────────────────────────────────────────────────────────

    #[test]
    fn test_hex_line_render_contains_offset() {
        let line = HexLine::new(0, vec![0x7Fu8, b'E', b'L', b'F'], 16);
        let rendered = line.render();
        assert!(rendered.starts_with("00000000"));
        assert!(rendered.contains("7F"));
    }

    #[test]
    fn test_hex_line_render_ascii() {
        let line = HexLine::new(0, b"Hello".to_vec(), 16);
        let rendered = line.render();
        assert!(rendered.contains("Hello"));
    }

    #[test]
    fn test_render_hex_lines() {
        let data: Vec<u8> = (0u8..32).collect();
        let lines = render_hex_lines(&data, 16);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1].offset, 16);
    }

    // ── bytes_to_hex_string / hex_string_to_bytes ────────────────────────────

    #[test]
    fn test_bytes_to_hex_string() {
        assert_eq!(bytes_to_hex_string(&[0xDE, 0xAD, 0xBE, 0xEF]), "DEADBEEF");
    }

    #[test]
    fn test_hex_string_to_bytes_basic() {
        let b = hex_string_to_bytes("DE AD BE EF").unwrap();
        assert_eq!(b, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_hex_string_to_bytes_odd_length() {
        assert!(hex_string_to_bytes("DEA").is_err());
    }

    #[test]
    fn test_hex_string_to_bytes_invalid_char() {
        assert!(hex_string_to_bytes("ZZ").is_err());
    }

    #[test]
    fn test_roundtrip_hex_string() {
        let data = vec![0x01u8, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let s = bytes_to_hex_string(&data);
        let back = hex_string_to_bytes(&s).unwrap();
        assert_eq!(back, data);
    }

    // ── decode_cstr ───────────────────────────────────────────────────────────

    #[test]
    fn test_decode_cstr_basic() {
        let data = b"hello\x00world";
        assert_eq!(decode_cstr(data), "hello");
    }

    #[test]
    fn test_decode_cstr_no_null() {
        let data = b"hello";
        assert_eq!(decode_cstr(data), "hello");
    }

    #[test]
    fn test_decode_cstr_empty() {
        assert_eq!(decode_cstr(&[]), "");
    }

    // ── decode_utf16le ────────────────────────────────────────────────────────

    #[test]
    fn test_decode_utf16le_basic() {
        let data = [b'H', 0, b'i', 0, 0, 0];
        let s = decode_utf16le(&data).unwrap();
        assert_eq!(s, "Hi");
    }

    #[test]
    fn test_decode_utf16le_odd_length() {
        assert!(decode_utf16le(&[0x01]).is_err());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VirtualAddressMap — maps virtual addresses to file offsets
// ─────────────────────────────────────────────────────────────────────────────

/// A single segment mapping: virtual-address range → file-offset base.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaSegment {
    /// Start virtual address (inclusive).
    pub va_start: u64,
    /// End virtual address (exclusive).
    pub va_end: u64,
    /// File offset corresponding to `va_start`.
    pub file_offset: u64,
    /// Human-readable name (e.g. `.text`).
    pub name: String,
}

impl VaSegment {
    /// Create a new segment.
    #[must_use]
    pub fn new(name: impl Into<String>, va_start: u64, va_end: u64, file_offset: u64) -> Self {
        Self {
            va_start,
            va_end,
            file_offset,
            name: name.into(),
        }
    }

    /// Returns `true` if `va` falls within `[va_start, va_end)`.
    #[must_use]
    pub const fn contains_va(&self, va: u64) -> bool {
        va >= self.va_start && va < self.va_end
    }

    /// Convert a virtual address to a file offset.
    ///
    /// Returns `None` if `va` is outside this segment.
    #[must_use]
    pub const fn va_to_offset(&self, va: u64) -> Option<u64> {
        if self.contains_va(va) {
            Some(self.file_offset + (va - self.va_start))
        } else {
            None
        }
    }

    /// Convert a file offset to a virtual address.
    ///
    /// Returns `None` if the offset is outside this segment's file range.
    #[must_use]
    pub const fn offset_to_va(&self, offset: u64) -> Option<u64> {
        let seg_len = self.va_end - self.va_start;
        if offset >= self.file_offset && offset < self.file_offset + seg_len {
            Some(self.va_start + (offset - self.file_offset))
        } else {
            None
        }
    }

    /// Length of the segment in bytes.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.va_end - self.va_start
    }

    /// Returns `true` if the segment has zero length.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.va_start >= self.va_end
    }
}

/// Map of virtual-address segments for translating addresses ↔ file offsets.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VirtualAddressMap {
    segments: Vec<VaSegment>,
}

impl VirtualAddressMap {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a segment.
    pub fn add_segment(&mut self, seg: VaSegment) {
        self.segments.push(seg);
        self.segments.sort_by_key(|s| s.va_start);
    }

    /// Translate a virtual address to a file offset.
    ///
    /// Returns `None` if no segment covers `va`.
    #[must_use]
    pub fn va_to_offset(&self, va: u64) -> Option<u64> {
        for seg in &self.segments {
            if let Some(off) = seg.va_to_offset(va) {
                return Some(off);
            }
        }
        None
    }

    /// Translate a file offset to a virtual address.
    ///
    /// Returns `None` if no segment covers the offset.
    #[must_use]
    pub fn offset_to_va(&self, offset: u64) -> Option<u64> {
        for seg in &self.segments {
            if let Some(va) = seg.offset_to_va(offset) {
                return Some(va);
            }
        }
        None
    }

    /// Find the segment containing a virtual address.
    #[must_use]
    pub fn segment_for_va(&self, va: u64) -> Option<&VaSegment> {
        self.segments.iter().find(|s| s.contains_va(va))
    }

    /// All segments, sorted by VA start.
    #[must_use]
    pub fn segments(&self) -> &[VaSegment] {
        &self.segments
    }

    /// Number of segments.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.segments.len()
    }

    /// Returns `true` if there are no segments.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Remove a segment by name. Returns `true` if found and removed.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.segments.len();
        self.segments.retain(|s| s.name != name);
        self.segments.len() < before
    }

    /// Check for VA-range overlaps between any two segments.
    #[must_use]
    pub fn has_overlaps(&self) -> bool {
        for i in 0..self.segments.len() {
            for j in (i + 1)..self.segments.len() {
                let a = &self.segments[i];
                let b = &self.segments[j];
                if a.va_start < b.va_end && b.va_start < a.va_end {
                    return true;
                }
            }
        }
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SplitView — side-by-side diff of two buffers
// ─────────────────────────────────────────────────────────────────────────────

/// Status of a byte position in a side-by-side comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SplitStatus {
    /// Bytes are identical.
    Same,
    /// Bytes differ.
    Different,
    /// Present in left only (right is shorter).
    LeftOnly,
    /// Present in right only (left is shorter).
    RightOnly,
}

/// One row of a side-by-side hex split view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitRow {
    /// Byte offset.
    pub offset: usize,
    /// Left buffer bytes (up to columns wide).
    pub left: Vec<u8>,
    /// Right buffer bytes (up to columns wide).
    pub right: Vec<u8>,
    /// Per-column status.
    pub status: Vec<SplitStatus>,
}

/// Produce a side-by-side split-diff view of two buffers.
///
/// # Panics
/// Panics if `columns` is zero.
#[must_use]
pub fn hex_split_view(left: &[u8], right: &[u8], columns: usize) -> Vec<SplitRow> {
    assert!(columns > 0, "columns must be > 0");
    let max_len = left.len().max(right.len());
    let mut rows = Vec::new();
    let mut offset = 0;
    while offset < max_len {
        let end = (offset + columns).min(max_len);
        let l: Vec<u8> = left
            .get(offset..end.min(left.len()))
            .unwrap_or(&[])
            .to_vec();
        let r: Vec<u8> = right
            .get(offset..end.min(right.len()))
            .unwrap_or(&[])
            .to_vec();
        let width = end - offset;
        let mut status = Vec::with_capacity(width);
        for i in 0..width {
            let s = match (l.get(i), r.get(i)) {
                (Some(a), Some(b)) => {
                    if a == b {
                        SplitStatus::Same
                    } else {
                        SplitStatus::Different
                    }
                }
                (Some(_), None) => SplitStatus::LeftOnly,
                (None, Some(_)) => SplitStatus::RightOnly,
                (None, None) => SplitStatus::Same,
            };
            status.push(s);
        }
        rows.push(SplitRow {
            offset,
            left: l,
            right: r,
            status,
        });
        offset += columns;
    }
    rows
}

/// Count differences between two buffers at the byte level.
#[must_use]
pub fn count_diff_bytes(left: &[u8], right: &[u8]) -> usize {
    let common = left.len().min(right.len());
    let diffs: usize = left[..common]
        .iter()
        .zip(right[..common].iter())
        .filter(|(a, b)| a != b)
        .count();
    diffs + left.len().abs_diff(right.len())
}

// ─────────────────────────────────────────────────────────────────────────────
// Rgb / HexPalette
// ─────────────────────────────────────────────────────────────────────────────

/// Colour palette mode for byte-value colouring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaletteMode {
    /// No colouring.
    None,
    /// Colour by printability: null/ctrl/printable/high.
    Printability,
    /// Colour by entropy contribution.
    Entropy,
    /// Sequential gradient: 0x00 = darkest, 0xFF = brightest.
    Gradient,
}

/// RGB colour (0–255 each channel).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Rgb {
    /// Create from components.
    #[must_use]
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    /// Blend this colour towards `other` by factor `t` (0.0–1.0).
    #[must_use]
    pub fn blend(&self, other: Self, t: f32) -> Self {
        let t = t.clamp(0.0, 1.0);
        Self {
            r: (f32::from(other.r) - f32::from(self.r)).mul_add(t, f32::from(self.r)) as u8,
            g: (f32::from(other.g) - f32::from(self.g)).mul_add(t, f32::from(self.g)) as u8,
            b: (f32::from(other.b) - f32::from(self.b)).mul_add(t, f32::from(self.b)) as u8,
        }
    }

    /// Convert to a CSS hex string like `#RRGGBB`.
    #[must_use]
    pub fn to_css(&self) -> String {
        format!("#{:02X}{:02X}{:02X}", self.r, self.g, self.b)
    }
}

/// Assign a colour to each byte value under a given palette mode.
///
/// Returns a 256-element array indexed by byte value.
#[must_use]
pub fn byte_palette(mode: PaletteMode) -> Box<[Rgb; 256]> {
    let mut out = Box::new([Rgb::new(0, 0, 0); 256]);
    match mode {
        PaletteMode::None => {
            for entry in out.iter_mut() {
                *entry = Rgb::new(200, 200, 200);
            }
        }
        PaletteMode::Printability => {
            for i in 0u16..256 {
                let b = i as u8;
                out[i as usize] = match b {
                    0 => Rgb::new(80, 80, 200),
                    1..=31 | 127 => Rgb::new(200, 100, 80),
                    32..=126 => Rgb::new(80, 200, 80),
                    _ => Rgb::new(200, 160, 80),
                };
            }
        }
        PaletteMode::Gradient => {
            for i in 0u16..256 {
                let v = i as u8;
                out[i as usize] = Rgb::new(v, v, v);
            }
        }
        PaletteMode::Entropy => {
            for entry in out.iter_mut() {
                *entry = Rgb::new(80, 120, 200);
            }
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// SearchHistory
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum entries in the search history.
pub const SEARCH_HISTORY_MAX: usize = 64;

/// A ring buffer of recent search terms.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SearchHistory {
    entries: Vec<String>,
}

impl SearchHistory {
    /// Create an empty history.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a new term. Deduplicates and maintains `SEARCH_HISTORY_MAX` cap.
    pub fn push(&mut self, term: impl Into<String>) {
        let term = term.into();
        self.entries.retain(|e| e != &term);
        self.entries.push(term);
        if self.entries.len() > SEARCH_HISTORY_MAX {
            self.entries.remove(0);
        }
    }

    /// Most-recent term first.
    pub fn recent(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().rev().map(String::as_str)
    }

    /// Number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the history is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Returns `true` if `term` exists in the history.
    #[must_use]
    pub fn contains(&self, term: &str) -> bool {
        self.entries.iter().any(|e| e == term)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sliding-window analysis
// ─────────────────────────────────────────────────────────────────────────────

/// Sliding-window entropy profile over a byte slice.
///
/// Each value is the Shannon entropy (bits) of the window starting at the
/// corresponding position.
///
/// # Panics
/// Panics if `window` or `step` is zero.
#[must_use]
pub fn sliding_entropy(data: &[u8], window: usize, step: usize) -> Vec<f64> {
    assert!(window > 0, "window must be > 0");
    assert!(step > 0, "step must be > 0");
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + window <= data.len() {
        let e = ByteFrequency::compute(&data[pos..pos + window]).entropy();
        out.push(e);
        pos += step;
    }
    out
}

/// Sliding-window byte-count profile.
///
/// # Panics
/// Panics if `window` or `step` is zero.
#[must_use]
pub fn sliding_count(
    data: &[u8],
    window: usize,
    step: usize,
    pred: impl Fn(u8) -> bool,
) -> Vec<usize> {
    assert!(window > 0, "window must be > 0");
    assert!(step > 0, "step must be > 0");
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + window <= data.len() {
        let count = data[pos..pos + window].iter().filter(|&&b| pred(b)).count();
        out.push(count);
        pos += step;
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// OffsetFormatter
// ─────────────────────────────────────────────────────────────────────────────

/// Numeric base for offset display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OffsetBase {
    /// Decimal.
    Dec,
    /// Hexadecimal (lower-case).
    HexLower,
    /// Hexadecimal (upper-case).
    HexUpper,
    /// Octal.
    Oct,
}

/// Format an offset according to the requested base and minimum width.
#[must_use]
pub fn format_offset(offset: u64, base: OffsetBase, width: usize) -> String {
    match base {
        OffsetBase::Dec => format!("{offset:0>width$}"),
        OffsetBase::HexLower => format!("{offset:0>width$x}"),
        OffsetBase::HexUpper => format!("{offset:0>width$X}"),
        OffsetBase::Oct => format!("{offset:0>width$o}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ByteRange — inclusive byte range utilities
// ─────────────────────────────────────────────────────────────────────────────

/// An inclusive byte range `[start, end]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteRange {
    pub start: usize,
    pub end: usize,
}

impl ByteRange {
    /// Create a new inclusive range.
    ///
    /// # Panics
    /// Panics if `start > end`.
    #[must_use]
    pub fn new(start: usize, end: usize) -> Self {
        assert!(start <= end, "ByteRange: start > end");
        Self { start, end }
    }

    /// Number of bytes covered (inclusive).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end - self.start + 1
    }

    /// Returns `true` when [`len`](Self::len) is zero.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns `true` if `offset` is within `[start, end]`.
    #[must_use]
    pub const fn contains(&self, offset: usize) -> bool {
        offset >= self.start && offset <= self.end
    }

    /// Returns `true` if `other` overlaps with `self`.
    #[must_use]
    pub const fn overlaps(&self, other: &Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    /// Returns `true` if `other` is fully within `self`.
    #[must_use]
    pub const fn contains_range(&self, other: &Self) -> bool {
        other.start >= self.start && other.end <= self.end
    }

    /// Convert to an exclusive `std::ops::Range<usize>`.
    #[must_use]
    pub const fn to_exclusive(&self) -> Range<usize> {
        self.start..self.end + 1
    }

    /// Create from an exclusive `Range<usize>`.
    ///
    /// # Panics
    /// Panics if `r` is empty.
    #[must_use]
    pub fn from_exclusive(r: Range<usize>) -> Self {
        assert!(!r.is_empty(), "ByteRange: empty exclusive range");
        Self::new(r.start, r.end - 1)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexViewSnapshot
// ─────────────────────────────────────────────────────────────────────────────

/// Serialisable snapshot capturing current view position and selections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexViewSnapshot {
    /// Byte offset at the top of the viewport.
    pub scroll_offset: usize,
    /// Currently selected range (if any).
    pub selection: Option<(usize, usize)>,
    /// Cursor byte offset.
    pub cursor: usize,
    /// Columns per row.
    pub columns: usize,
    /// Total buffer length at snapshot time.
    pub buffer_len: usize,
}

impl HexViewSnapshot {
    /// Create a snapshot.
    #[must_use]
    pub const fn new(
        scroll_offset: usize,
        selection: Option<(usize, usize)>,
        cursor: usize,
        columns: usize,
        buffer_len: usize,
    ) -> Self {
        Self {
            scroll_offset,
            selection,
            cursor,
            columns,
            buffer_len,
        }
    }

    /// Returns `true` if the cursor is within the viewport.
    #[must_use]
    pub const fn cursor_visible(&self, viewport_rows: usize) -> bool {
        let top = self.scroll_offset;
        let bottom = top + viewport_rows * self.columns;
        self.cursor >= top && self.cursor < bottom
    }

    /// Row the cursor is on.
    #[must_use]
    pub const fn cursor_row(&self) -> usize {
        self.cursor / self.columns
    }

    /// Column the cursor is on.
    #[must_use]
    pub const fn cursor_col(&self) -> usize {
        self.cursor % self.columns
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IntelHexRecord
// ─────────────────────────────────────────────────────────────────────────────

/// A record parsed from an Intel HEX file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelHexRecord {
    /// Byte count field.
    pub byte_count: u8,
    /// Address field.
    pub address: u16,
    /// Record type (0 = data, 1 = EOF, etc.).
    pub record_type: u8,
    /// Data bytes.
    pub data: Vec<u8>,
    /// Checksum byte.
    pub checksum: u8,
}

impl IntelHexRecord {
    /// Compute the expected checksum for this record.
    #[must_use]
    pub fn computed_checksum(&self) -> u8 {
        let mut sum: u8 = self.byte_count;
        sum = sum.wrapping_add((self.address >> 8) as u8);
        sum = sum.wrapping_add((self.address & 0xFF) as u8);
        sum = sum.wrapping_add(self.record_type);
        for &d in &self.data {
            sum = sum.wrapping_add(d);
        }
        (!sum).wrapping_add(1)
    }

    /// Returns `true` if the stored checksum matches the computed one.
    #[must_use]
    pub fn is_checksum_valid(&self) -> bool {
        self.checksum == self.computed_checksum()
    }

    /// Parse one Intel HEX line (without the leading `:`).
    ///
    /// # Errors
    /// Returns `HexError::Encoding` if the line is malformed.
    pub fn parse(line: &str) -> Result<Self, HexError> {
        let line = line.trim_start_matches(':');
        let bytes = hex_string_to_bytes(line)
            .map_err(|_| HexError::Encoding("invalid Intel HEX".into()))?;
        if bytes.len() < 5 {
            return Err(HexError::Encoding("Intel HEX record too short".into()));
        }
        let byte_count = bytes[0];
        let address = (u16::from(bytes[1]) << 8) | u16::from(bytes[2]);
        let record_type = bytes[3];
        let data = bytes[4..4 + byte_count as usize].to_vec();
        let checksum = *bytes.last().unwrap();
        Ok(Self {
            byte_count,
            address,
            record_type,
            data,
            checksum,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Byte transform helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Invert all bits in a byte slice.
pub fn invert_bytes(data: &mut [u8]) {
    for b in data.iter_mut() {
        *b = !*b;
    }
}

/// Rotate each byte left by `amount` bits.
pub fn rotate_bytes_left(data: &mut [u8], amount: u32) {
    let amount = amount % 8;
    for b in data.iter_mut() {
        *b = b.rotate_left(amount);
    }
}

/// Rotate each byte right by `amount` bits.
pub fn rotate_bytes_right(data: &mut [u8], amount: u32) {
    let amount = amount % 8;
    for b in data.iter_mut() {
        *b = b.rotate_right(amount);
    }
}

/// Apply a substitution box to each byte.
///
/// # Panics
/// Panics if `sbox.len() != 256`.
pub fn apply_sbox(data: &mut [u8], sbox: &[u8]) {
    assert_eq!(sbox.len(), 256, "sbox must have exactly 256 entries");
    for b in data.iter_mut() {
        *b = sbox[*b as usize];
    }
}

/// Apply a Caesar-style byte shift (wrapping).
pub fn byte_shift(data: &mut [u8], shift: u8) {
    for b in data.iter_mut() {
        *b = b.wrapping_add(shift);
    }
}

/// Reverse the byte shift.
pub fn byte_unshift(data: &mut [u8], shift: u8) {
    for b in data.iter_mut() {
        *b = b.wrapping_sub(shift);
    }
}

/// XOR every byte with `key`, repeating the key.
///
/// # Panics
/// Panics if `key` is empty.
pub fn xor_key(data: &mut [u8], key: &[u8]) {
    assert!(!key.is_empty(), "xor_key: key must not be empty");
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key[i % key.len()];
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hex dump parser
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed line from a hex dump string.
#[derive(Debug, Clone)]
pub struct ParsedHexDumpLine {
    /// Offset on this line.
    pub offset: u64,
    /// Bytes on this line.
    pub bytes: Vec<u8>,
    /// ASCII representation (printable only, rest replaced by `.`).
    pub ascii: String,
}

/// Parse a hex dump in the format `XXXXXXXX  XX XX XX … |ascii…|`.
///
/// Lines that don't match are skipped.
#[must_use]
pub fn parse_hex_dump(dump: &str) -> Vec<ParsedHexDumpLine> {
    let mut out = Vec::new();
    for line in dump.lines() {
        let line = line.trim();
        let Some(space) = line.find("  ") else {
            continue;
        };
        let offset_str = &line[..space];
        let Ok(offset) = u64::from_str_radix(offset_str.trim_start_matches("0x"), 16) else {
            continue;
        };
        let rest = &line[space..];
        let hex_part = if let Some(pipe) = rest.find('|') {
            &rest[..pipe]
        } else {
            rest
        };
        let bytes: Vec<u8> = hex_part
            .split_whitespace()
            .filter_map(|tok| u8::from_str_radix(tok, 16).ok())
            .collect();
        let ascii: String = bytes
            .iter()
            .map(|&b| {
                if (32..127).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        out.push(ParsedHexDumpLine {
            offset,
            bytes,
            ascii,
        });
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Byte-class summary helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Count null, printable, control, and high bytes.
///
/// Returns `(nulls, printable, control, high)`.
#[must_use]
pub fn byte_class_summary(data: &[u8]) -> (usize, usize, usize, usize) {
    let mut nulls = 0usize;
    let mut printable = 0usize;
    let mut control = 0usize;
    let mut high = 0usize;
    for &b in data {
        match b {
            0 => nulls += 1,
            32..=126 => printable += 1,
            1..=31 | 127 => control += 1,
            _ => high += 1,
        }
    }
    (nulls, printable, control, high)
}

/// Returns `true` if the slice appears to be ASCII text (tab, LF, CR, and 32–126).
#[must_use]
pub fn is_ascii_text(data: &[u8]) -> bool {
    data.iter().all(|&b| matches!(b, 9 | 10 | 13 | 32..=126))
}

/// Returns `true` if the slice is valid UTF-8.
#[must_use]
pub const fn is_utf8_text(data: &[u8]) -> bool {
    std::str::from_utf8(data).is_ok()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for extended functionality
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests_extra {
    use super::*;

    // ── VirtualAddressMap ─────────────────────────────────────────────────────

    #[test]
    fn test_va_segment_contains() {
        let seg = VaSegment::new(".text", 0x1000, 0x2000, 0x400);
        assert!(seg.contains_va(0x1000));
        assert!(seg.contains_va(0x1FFF));
        assert!(!seg.contains_va(0x2000));
        assert!(!seg.contains_va(0x0FFF));
    }

    #[test]
    fn test_va_to_offset() {
        let seg = VaSegment::new(".text", 0x1000, 0x2000, 0x400);
        assert_eq!(seg.va_to_offset(0x1000), Some(0x400));
        assert_eq!(seg.va_to_offset(0x1100), Some(0x500));
        assert_eq!(seg.va_to_offset(0x2000), None);
    }

    #[test]
    fn test_offset_to_va() {
        let seg = VaSegment::new(".text", 0x1000, 0x2000, 0x400);
        assert_eq!(seg.offset_to_va(0x400), Some(0x1000));
        assert_eq!(seg.offset_to_va(0x500), Some(0x1100));
        assert_eq!(seg.offset_to_va(0x1400), None);
    }

    #[test]
    fn test_va_map_roundtrip() {
        let mut m = VirtualAddressMap::new();
        m.add_segment(VaSegment::new(".text", 0x1000, 0x2000, 0x400));
        m.add_segment(VaSegment::new(".data", 0x3000, 0x4000, 0x1400));
        assert_eq!(m.va_to_offset(0x1500), Some(0x900));
        assert_eq!(m.offset_to_va(0x900), Some(0x1500));
        assert_eq!(m.va_to_offset(0x3800), Some(0x1C00));
    }

    #[test]
    fn test_va_map_no_overlap() {
        let mut m = VirtualAddressMap::new();
        m.add_segment(VaSegment::new("a", 0x1000, 0x2000, 0));
        m.add_segment(VaSegment::new("b", 0x3000, 0x4000, 0x1000));
        assert!(!m.has_overlaps());
    }

    #[test]
    fn test_va_map_overlap_detected() {
        let mut m = VirtualAddressMap::new();
        m.add_segment(VaSegment::new("a", 0x1000, 0x2000, 0));
        m.add_segment(VaSegment::new("b", 0x1800, 0x3000, 0x1000));
        assert!(m.has_overlaps());
    }

    #[test]
    fn test_va_map_remove() {
        let mut m = VirtualAddressMap::new();
        m.add_segment(VaSegment::new("x", 0, 0x100, 0));
        assert_eq!(m.len(), 1);
        assert!(m.remove("x"));
        assert!(m.is_empty());
    }

    #[test]
    fn test_va_segment_len() {
        let seg = VaSegment::new("s", 0x1000, 0x1010, 0);
        assert_eq!(seg.len(), 0x10);
        assert!(!seg.is_empty());
    }

    // ── SplitView ─────────────────────────────────────────────────────────────

    #[test]
    fn test_split_view_identical() {
        let data = vec![0u8, 1, 2, 3];
        let rows = hex_split_view(&data, &data, 4);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].status.iter().all(|s| *s == SplitStatus::Same));
    }

    #[test]
    fn test_split_view_different() {
        let left = vec![0u8, 1, 2, 3];
        let right = vec![0u8, 1, 99, 3];
        let rows = hex_split_view(&left, &right, 4);
        assert_eq!(rows[0].status[2], SplitStatus::Different);
    }

    #[test]
    fn test_split_view_left_only() {
        let left = vec![1u8, 2, 3, 4];
        let right = vec![1u8, 2];
        let rows = hex_split_view(&left, &right, 4);
        assert_eq!(rows[0].status[2], SplitStatus::LeftOnly);
        assert_eq!(rows[0].status[3], SplitStatus::LeftOnly);
    }

    #[test]
    fn test_split_view_right_only() {
        let left: Vec<u8> = vec![1, 2];
        let right: Vec<u8> = vec![1, 2, 3, 4];
        let rows = hex_split_view(&left, &right, 4);
        assert_eq!(rows[0].status[2], SplitStatus::RightOnly);
    }

    #[test]
    fn test_count_diff_bytes() {
        assert_eq!(count_diff_bytes(&[1, 2, 3], &[1, 2, 3]), 0);
        assert_eq!(count_diff_bytes(&[1, 2, 3], &[1, 99, 3]), 1);
        assert_eq!(count_diff_bytes(&[1, 2, 3], &[1, 2]), 1);
        assert_eq!(count_diff_bytes(&[], &[1]), 1);
    }

    // ── Rgb / Palette ─────────────────────────────────────────────────────────

    #[test]
    fn test_rgb_blend() {
        let black = Rgb::new(0, 0, 0);
        let white = Rgb::new(255, 255, 255);
        let mid = black.blend(white, 0.5);
        assert!(mid.r > 100 && mid.r < 200);
    }

    #[test]
    fn test_rgb_to_css() {
        assert_eq!(Rgb::new(255, 0, 128).to_css(), "#FF0080");
    }

    #[test]
    fn test_gradient_palette_endpoints() {
        let p = byte_palette(PaletteMode::Gradient);
        assert_eq!(p[0], Rgb::new(0, 0, 0));
        assert_eq!(p[255], Rgb::new(255, 255, 255));
    }

    #[test]
    fn test_printability_palette_null_blue() {
        let p = byte_palette(PaletteMode::Printability);
        assert!(p[0].b > p[0].r);
    }

    // ── SearchHistory ─────────────────────────────────────────────────────────

    #[test]
    fn test_search_history_push_dedup() {
        let mut h = SearchHistory::new();
        h.push("hello");
        h.push("world");
        h.push("hello");
        assert_eq!(h.len(), 2);
        assert_eq!(h.recent().next(), Some("hello"));
    }

    #[test]
    fn test_search_history_cap() {
        let mut h = SearchHistory::new();
        for i in 0..=SEARCH_HISTORY_MAX {
            h.push(format!("term{i}"));
        }
        assert_eq!(h.len(), SEARCH_HISTORY_MAX);
    }

    #[test]
    fn test_search_history_contains() {
        let mut h = SearchHistory::new();
        h.push("needle");
        assert!(h.contains("needle"));
        assert!(!h.contains("haystack"));
    }

    #[test]
    fn test_search_history_clear() {
        let mut h = SearchHistory::new();
        h.push("a");
        h.clear();
        assert!(h.is_empty());
    }

    // ── Sliding entropy ───────────────────────────────────────────────────────

    #[test]
    fn test_sliding_entropy_uniform() {
        let data: Vec<u8> = (0..=255u8).collect();
        let profile = sliding_entropy(&data, 256, 256);
        assert_eq!(profile.len(), 1);
        assert!((profile[0] - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_sliding_entropy_constant() {
        let data = vec![0xABu8; 256];
        let profile = sliding_entropy(&data, 64, 64);
        for v in &profile {
            assert!(*v < 0.001);
        }
    }

    #[test]
    fn test_sliding_count() {
        let data: Vec<u8> = (0..16).collect();
        let counts = sliding_count(&data, 8, 4, |b| b < 8);
        assert_eq!(counts[0], 8);
        assert_eq!(counts[1], 4);
        assert_eq!(counts[2], 0);
    }

    // ── OffsetFormatter ───────────────────────────────────────────────────────

    #[test]
    fn test_format_offset_hex_upper() {
        assert_eq!(format_offset(0x1A2B, OffsetBase::HexUpper, 8), "00001A2B");
    }

    #[test]
    fn test_format_offset_hex_lower() {
        assert_eq!(format_offset(0x1a2b, OffsetBase::HexLower, 4), "1a2b");
    }

    #[test]
    fn test_format_offset_dec() {
        assert_eq!(format_offset(42, OffsetBase::Dec, 5), "00042");
    }

    #[test]
    fn test_format_offset_oct() {
        assert_eq!(format_offset(8, OffsetBase::Oct, 4), "0010");
    }

    // ── ByteRange ─────────────────────────────────────────────────────────────

    #[test]
    fn test_byte_range_len() {
        let r = ByteRange::new(3, 7);
        assert_eq!(r.len(), 5);
    }

    #[test]
    fn test_byte_range_contains() {
        let r = ByteRange::new(10, 20);
        assert!(r.contains(10));
        assert!(r.contains(20));
        assert!(!r.contains(9));
        assert!(!r.contains(21));
    }

    #[test]
    fn test_byte_range_overlaps() {
        let a = ByteRange::new(0, 10);
        let b = ByteRange::new(5, 15);
        let c = ByteRange::new(11, 20);
        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c));
    }

    #[test]
    fn test_byte_range_exclusive_roundtrip() {
        let r = ByteRange::new(5, 9);
        let ex = r.to_exclusive();
        let back = ByteRange::from_exclusive(ex);
        assert_eq!(back.start, r.start);
        assert_eq!(back.end, r.end);
    }

    #[test]
    fn test_byte_range_contains_range() {
        let outer = ByteRange::new(0, 100);
        let inner = ByteRange::new(10, 50);
        let outside = ByteRange::new(90, 110);
        assert!(outer.contains_range(&inner));
        assert!(!outer.contains_range(&outside));
    }

    // ── HexViewSnapshot ───────────────────────────────────────────────────────

    #[test]
    fn test_snapshot_cursor_visible() {
        let snap = HexViewSnapshot::new(0, None, 32, 16, 512);
        assert!(snap.cursor_visible(3));
        assert!(!snap.cursor_visible(2));
    }

    #[test]
    fn test_snapshot_cursor_row_col() {
        let snap = HexViewSnapshot::new(0, None, 35, 16, 512);
        assert_eq!(snap.cursor_row(), 2);
        assert_eq!(snap.cursor_col(), 3);
    }

    // ── IntelHexRecord ────────────────────────────────────────────────────────

    #[test]
    fn test_intel_hex_checksum() {
        // :0B0010006164647265737320676170A7
        let rec = IntelHexRecord::parse("0B0010006164647265737320676170A7").unwrap();
        assert!(rec.is_checksum_valid());
    }

    #[test]
    fn test_intel_hex_eof() {
        // :00000001FF
        let rec = IntelHexRecord::parse("00000001FF").unwrap();
        assert_eq!(rec.record_type, 1);
        assert!(rec.data.is_empty());
        assert!(rec.is_checksum_valid());
    }

    // ── Byte transforms ───────────────────────────────────────────────────────

    #[test]
    fn test_invert_bytes() {
        let mut data = vec![0xFFu8, 0x00, 0xAB];
        invert_bytes(&mut data);
        assert_eq!(data, vec![0x00, 0xFF, 0x54]);
    }

    #[test]
    fn test_rotate_left() {
        let mut data = vec![0b1000_0001u8];
        rotate_bytes_left(&mut data, 1);
        assert_eq!(data[0], 0b0000_0011);
    }

    #[test]
    fn test_rotate_right() {
        let mut data = vec![0b0000_0011u8];
        rotate_bytes_right(&mut data, 1);
        assert_eq!(data[0], 0b1000_0001);
    }

    #[test]
    fn test_xor_key_roundtrip() {
        let original = b"Hello, world!".to_vec();
        let mut data = original.clone();
        xor_key(&mut data, b"key");
        xor_key(&mut data, b"key");
        assert_eq!(data, original);
    }

    #[test]
    fn test_byte_shift_roundtrip() {
        let original = vec![10u8, 20, 200];
        let mut data = original.clone();
        byte_shift(&mut data, 42);
        byte_unshift(&mut data, 42);
        assert_eq!(data, original);
    }

    #[test]
    fn test_apply_sbox() {
        let sbox: Vec<u8> = (0..=255u8).rev().collect();
        let mut data = vec![0u8, 1, 255];
        apply_sbox(&mut data, &sbox);
        assert_eq!(data, vec![255, 254, 0]);
    }

    // ── Hex dump parser ───────────────────────────────────────────────────────

    #[test]
    fn test_parse_hex_dump_basic() {
        let dump = "00000000  48 65 6C 6C 6F  |Hello|";
        let rows = parse_hex_dump(dump);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].offset, 0);
        assert_eq!(rows[0].bytes, b"Hello");
    }

    #[test]
    fn test_parse_hex_dump_multi_row() {
        let dump = "00000000  41 42 43\n00000003  44 45 46";
        let rows = parse_hex_dump(dump);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].offset, 3);
    }

    #[test]
    fn test_parse_hex_dump_ascii_repr() {
        let dump = "00000000  41 00 42  |A.B|";
        let rows = parse_hex_dump(dump);
        assert_eq!(rows[0].ascii, "A.B");
    }

    // ── byte_class_summary ────────────────────────────────────────────────────

    #[test]
    fn test_byte_class_summary_all_printable() {
        let data = b"Hello";
        let (nulls, print, ctrl, high) = byte_class_summary(data);
        assert_eq!(nulls, 0);
        assert_eq!(print, 5);
        assert_eq!(ctrl, 0);
        assert_eq!(high, 0);
    }

    #[test]
    fn test_byte_class_summary_mixed() {
        let data = &[0u8, 0x41, 0x01, 0x80];
        let (n, p, c, h) = byte_class_summary(data);
        assert_eq!(n, 1);
        assert_eq!(p, 1);
        assert_eq!(c, 1);
        assert_eq!(h, 1);
    }

    #[test]
    fn test_is_ascii_text_true() {
        assert!(is_ascii_text(b"Hello\nWorld\r\n"));
    }

    #[test]
    fn test_is_ascii_text_false() {
        assert!(!is_ascii_text(b"\x00\x01Hello"));
    }

    #[test]
    fn test_is_utf8_text_valid() {
        assert!(is_utf8_text("héllo".as_bytes()));
    }

    #[test]
    fn test_is_utf8_text_invalid() {
        assert!(!is_utf8_text(&[0xFF, 0xFE]));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexDiffView  (byte-slice diff + ASCII-art renderer)
// ─────────────────────────────────────────────────────────────────────────────

/// A byte-range within a slice (half-open, `start..start+len`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct U8Range {
    pub start: u64,
    pub len: u64,
}

impl U8Range {
    #[must_use]
    pub const fn new(start: u64, len: u64) -> Self {
        Self { start, len }
    }

    #[must_use]
    pub const fn end(&self) -> u64 {
        self.start + self.len
    }
}

/// Result of diffing two raw byte slices.
///
/// This is distinct from [`HexDiff`] (which operates on [`HexBuffer`]s and
/// returns [`DiffRegion`] objects); `ByteDiff` is a lightweight value type
/// intended for the `HexDiffView` renderer.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ByteDiff {
    /// Offsets (relative to the shorter slice) where `a[i] != b[i]`.
    pub changed_offsets: Vec<u64>,
    /// Ranges present in `b` but absent in `a` (tail of `b` when `b` is longer).
    pub added: Vec<U8Range>,
    /// Ranges present in `a` but absent in `b` (tail of `a` when `a` is longer).
    pub removed: Vec<U8Range>,
}

/// Computes a byte-level diff between two slices.
///
/// Bytes in the overlapping region are compared one-by-one and differing
/// positions are recorded in `changed_offsets`.  If the slices have different
/// lengths the trailing bytes of the longer slice are recorded as
/// `added` / `removed`.
#[must_use]
pub fn slice_diff(a: &[u8], b: &[u8]) -> ByteDiff {
    let overlap = a.len().min(b.len());
    let mut changed_offsets: Vec<u64> = Vec::new();

    for i in 0..overlap {
        if a[i] != b[i] {
            changed_offsets.push(i as u64);
        }
    }

    let mut added: Vec<U8Range> = Vec::new();
    let mut removed: Vec<U8Range> = Vec::new();

    match b.len().cmp(&a.len()) {
        std::cmp::Ordering::Greater => {
            let extra_start = overlap as u64;
            let extra_len = (b.len() - overlap) as u64;
            added.push(U8Range::new(extra_start, extra_len));
        }
        std::cmp::Ordering::Less => {
            let extra_start = overlap as u64;
            let extra_len = (a.len() - overlap) as u64;
            removed.push(U8Range::new(extra_start, extra_len));
        }
        std::cmp::Ordering::Equal => {}
    }

    ByteDiff {
        changed_offsets,
        added,
        removed,
    }
}

/// Renders an ASCII-art side-by-side hex diff of `a` vs `b`.
///
/// Each row shows 16 bytes from both slices.  Bytes that differ are
/// highlighted with `[` `]` brackets.  A `*` marker in the second column
/// flags rows that contain at least one differing byte.
#[must_use]
pub fn render_diff(diff_result: &ByteDiff, a: &[u8], b: &[u8]) -> String {
    const COLS: usize = 16;

    let total_rows = {
        let max_len = a.len().max(b.len());
        max_len.div_ceil(COLS)
    };

    // Build a fast lookup set of changed offsets.
    let changed: std::collections::HashSet<u64> =
        diff_result.changed_offsets.iter().copied().collect();

    let mut out = String::new();

    // Header
    out.push_str(&format!(
        "{:<10}  {:<47}  {:<47}\n",
        "Offset",
        "── A ──────────────────────────────────────────",
        "── B ──────────────────────────────────────────"
    ));
    out.push_str(&format!("{}\n", "─".repeat(110)));

    for row in 0..total_rows {
        let base = row * COLS;
        let row_base = base as u64;

        // Collect up to COLS bytes for each side, padding with Option::None.
        let a_bytes: Vec<Option<u8>> = (0..COLS).map(|i| a.get(base + i).copied()).collect();
        let b_bytes: Vec<Option<u8>> = (0..COLS).map(|i| b.get(base + i).copied()).collect();

        // Determine whether any byte in this row differs.
        let row_has_diff = (0..COLS).any(|i| {
            let off = row_base + i as u64;
            let a_val = a_bytes[i];
            let b_val = b_bytes[i];
            if a_val.is_none() && b_val.is_none() {
                return false;
            }
            a_val != b_val || changed.contains(&off)
        });

        // Always print the row; mark changed bytes with brackets.
        let fmt_side = |bytes: &[Option<u8>], is_b: bool| -> String {
            let mut s = String::new();
            for (i, &byte_opt) in bytes.iter().enumerate() {
                let off = row_base + i as u64;
                let is_changed = changed.contains(&off)
                    || (is_b
                        && diff_result
                            .added
                            .iter()
                            .any(|r| off >= r.start && off < r.end()))
                    || (!is_b
                        && diff_result
                            .removed
                            .iter()
                            .any(|r| off >= r.start && off < r.end()));

                match byte_opt {
                    Some(b) => {
                        if is_changed {
                            s.push_str(&format!("[{b:02X}]"));
                        } else {
                            s.push_str(&format!(" {b:02X} "));
                        }
                    }
                    None => s.push_str("    "),
                }
                if i == 7 {
                    s.push(' ');
                }
            }
            s
        };

        let a_str = fmt_side(&a_bytes, false);
        let b_str = fmt_side(&b_bytes, true);

        let marker = if row_has_diff { "*" } else { " " };
        out.push_str(&format!(
            "{:08X} {}  {}{}  {}\n",
            base, marker, a_str, "", b_str
        ));
    }

    // Summary footer
    out.push_str(&format!("{}\n", "─".repeat(110)));
    out.push_str(&format!(
        "Changed bytes: {}  Added ranges: {}  Removed ranges: {}\n",
        diff_result.changed_offsets.len(),
        diff_result.added.len(),
        diff_result.removed.len(),
    ));

    out
}

// ─────────────────────────────────────────────────────────────────────────────
// HexSearchEngine
// ─────────────────────────────────────────────────────────────────────────────

/// Multi-mode hex search engine.
///
/// All methods return a `Vec<u64>` of byte offsets where the pattern starts.
pub struct HexSearchEngine;

impl HexSearchEngine {
    /// Exact byte-sequence search using the KMP algorithm.
    ///
    /// Returns every (possibly overlapping) start offset where `pattern`
    /// appears in `data`.
    #[must_use]
    pub fn search_exact(data: &[u8], pattern: &[u8]) -> Vec<u64> {
        if pattern.is_empty() || data.len() < pattern.len() {
            return Vec::new();
        }
        kmp_search(data, pattern)
            .into_iter()
            .map(|o| o as u64)
            .collect()
    }

    /// Masked (wildcard) byte search.
    ///
    /// `mask[i] == 0xFF` means the byte at position `i` must equal
    /// `pattern[i]` exactly.  `mask[i] == 0x00` means any byte is accepted
    /// at that position.  Intermediate mask values perform a bitwise AND
    /// before comparing (`(data[off+i] & mask[i]) == (pattern[i] & mask[i])`).
    ///
    /// `pattern` and `mask` must have the same length; if they differ the
    /// shorter length is used.
    #[must_use]
    pub fn search_wildcard(data: &[u8], pattern: &[u8], mask: &[u8]) -> Vec<u64> {
        let pat_len = pattern.len().min(mask.len());
        if pat_len == 0 || data.len() < pat_len {
            return Vec::new();
        }
        let mut results = Vec::new();
        'outer: for start in 0..=(data.len() - pat_len) {
            for i in 0..pat_len {
                let m = mask[i];
                if (data[start + i] & m) != (pattern[i] & m) {
                    continue 'outer;
                }
            }
            results.push(start as u64);
        }
        results
    }

    /// Hex-regex search supporting nibble-level wildcards.
    ///
    /// The `hex_regex` string is a space-separated sequence of tokens.
    /// Each token is one of:
    /// - `XX`  — exact byte (two hex digits, e.g. `4F`)
    /// - `X?`  — high nibble fixed, low nibble wildcard (e.g. `4?`)
    /// - `?X`  — high nibble wildcard, low nibble fixed (e.g. `?F`)
    /// - `??`  — full wildcard (any byte)
    ///
    /// Returns `Err` if any token is syntactically invalid.
    ///
    /// # Errors
    /// Returns `HexError::Regex` for malformed tokens.
    pub fn search_regex_hex(data: &[u8], hex_regex: &str) -> Result<Vec<u64>, HexError> {
        // Parse tokens into (hi_mask, hi_val, lo_mask, lo_val) nibble constraints.
        #[derive(Clone, Copy)]
        struct NibblePair {
            hi_mask: u8,
            hi_val: u8,
            lo_mask: u8,
            lo_val: u8,
        }

        let tokens: Vec<&str> = hex_regex.split_whitespace().collect();
        if tokens.is_empty() {
            return Ok(Vec::new());
        }

        let mut pat: Vec<NibblePair> = Vec::with_capacity(tokens.len());
        for tok in &tokens {
            let bytes = tok.as_bytes();
            if bytes.len() != 2 {
                return Err(HexError::Regex(format!(
                    "hex_regex token must be 2 chars, got: {tok}"
                )));
            }
            let (hi_mask, hi_val) = if bytes[0] == b'?' {
                (0x00u8, 0x00u8)
            } else {
                let v = hex_nibble_val(bytes[0]).map_err(|_| {
                    HexError::Regex(format!(
                        "invalid nibble '{}' in token {tok}",
                        bytes[0] as char
                    ))
                })?;
                (0xF0, v << 4)
            };
            let (lo_mask, lo_val) = if bytes[1] == b'?' {
                (0x00u8, 0x00u8)
            } else {
                let v = hex_nibble_val(bytes[1]).map_err(|_| {
                    HexError::Regex(format!(
                        "invalid nibble '{}' in token {tok}",
                        bytes[1] as char
                    ))
                })?;
                (0x0F, v)
            };
            pat.push(NibblePair {
                hi_mask,
                hi_val,
                lo_mask,
                lo_val,
            });
        }

        let pat_len = pat.len();
        if data.len() < pat_len {
            return Ok(Vec::new());
        }

        let mut results = Vec::new();
        'outer: for start in 0..=(data.len() - pat_len) {
            for (i, p) in pat.iter().enumerate() {
                let b = data[start + i];
                let hi = b & 0xF0;
                let lo = b & 0x0F;
                if (hi & p.hi_mask) != (p.hi_val & p.hi_mask) {
                    continue 'outer;
                }
                if (lo & p.lo_mask) != (p.lo_val & p.lo_mask) {
                    continue 'outer;
                }
            }
            results.push(start as u64);
        }
        Ok(results)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexAnnotationLayer
// ─────────────────────────────────────────────────────────────────────────────

/// A unique identifier for an annotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AnnotationId(pub u64);

/// A named, coloured region overlaid on the raw byte view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub id: AnnotationId,
    /// Byte offset where the annotation begins.
    pub offset: u64,
    /// Number of bytes covered.
    pub length: u64,
    /// Human-readable label.
    pub name: String,
    /// A colour index or packed RGB value; interpretation is up to the renderer.
    pub color: u8,
}

impl Annotation {
    /// Return `true` if `offset` falls within this annotation.
    #[must_use]
    pub const fn contains(&self, offset: u64) -> bool {
        offset >= self.offset && offset < self.offset + self.length
    }
}

/// An ordered, indexed layer of byte-range annotations.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HexAnnotationLayer {
    annotations: Vec<Annotation>,
    next_id: u64,
}

impl HexAnnotationLayer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new annotation and return its unique id.
    pub fn add_annotation(
        &mut self,
        offset: u64,
        length: u64,
        name: &str,
        color: u8,
    ) -> AnnotationId {
        let id = AnnotationId(self.next_id);
        self.next_id += 1;
        self.annotations.push(Annotation {
            id,
            offset,
            length,
            name: name.to_owned(),
            color,
        });
        id
    }

    /// Remove the annotation identified by `id`.  No-op if not found.
    pub fn remove_annotation(&mut self, id: AnnotationId) {
        self.annotations.retain(|a| a.id != id);
    }

    /// Return all annotations that cover `offset` (i.e., `offset` is inside
    /// the annotation's `[offset, offset+length)` range).
    #[must_use]
    pub fn annotations_at(&self, offset: u64) -> Vec<&Annotation> {
        self.annotations
            .iter()
            .filter(|a| a.contains(offset))
            .collect()
    }

    /// Return an immutable view of all annotations.
    #[must_use]
    pub fn all(&self) -> &[Annotation] {
        &self.annotations
    }

    /// Render `data` as a hex dump with annotation labels shown inline.
    ///
    /// Annotated bytes are surrounded with `<name:` and `>` markers; the
    /// offset column, hex columns, and ASCII column follow the standard
    /// 16-bytes-per-row layout.
    #[must_use]
    pub fn render_with_annotations(data: &[u8], annotations: &[Annotation]) -> String {
        const COLS: usize = 16;
        let rows = data.len().div_ceil(COLS);
        let mut out = String::new();

        for row in 0..rows {
            let base = row * COLS;
            let end = (base + COLS).min(data.len());
            let chunk = &data[base..end];

            // Offset column
            out.push_str(&format!("{base:08X}  "));

            // Hex bytes with annotation brackets
            for (i, &b) in chunk.iter().enumerate() {
                let abs_off = (base + i) as u64;
                // Find the first annotation covering this offset for labelling.
                let ann = annotations.iter().find(|a| a.contains(abs_off));

                // Opening bracket on the first byte of an annotation.
                let is_ann_start = ann.is_some_and(|a| a.offset == abs_off);
                // Closing bracket on the last byte of an annotation.
                let is_ann_end =
                    ann.is_some_and(|a| abs_off == a.offset + a.length.saturating_sub(1));

                if is_ann_start
                    && let Some(a) = ann {
                        out.push_str(&format!("<{}:", a.name));
                    }
                out.push_str(&format!("{b:02X}"));
                if is_ann_end {
                    out.push('>');
                }
                out.push(' ');

                if i == 7 {
                    out.push(' ');
                }
            }

            // Pad short rows so the ASCII column lines up.
            let padding = COLS - chunk.len();
            for i in 0..padding {
                out.push_str("   ");
                if i + chunk.len() == 7 {
                    out.push(' ');
                }
            }

            // ASCII column
            out.push_str(" |");
            for &b in chunk {
                out.push(if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                });
            }
            out.push_str("|\n");
        }

        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for HexDiffView, HexSearchEngine, HexAnnotationLayer
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests_new_hex {
    use super::*;

    // ── slice_diff / render_diff ──────────────────────────────────────────────

    #[test]
    fn test_diff_identical() {
        let d = slice_diff(b"Hello", b"Hello");
        assert!(d.changed_offsets.is_empty());
        assert!(d.added.is_empty());
        assert!(d.removed.is_empty());
    }

    #[test]
    fn test_diff_single_change() {
        let a = b"Hello";
        let b_data = b"Hxllo";
        let d = slice_diff(a, b_data);
        assert_eq!(d.changed_offsets, vec![1u64]);
        assert!(d.added.is_empty());
        assert!(d.removed.is_empty());
    }

    #[test]
    fn test_diff_b_longer() {
        let a = b"Hi";
        let b_data = b"Hi!!";
        let d = slice_diff(a, b_data);
        assert!(d.changed_offsets.is_empty());
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.added[0].start, 2);
        assert_eq!(d.added[0].len, 2);
        assert!(d.removed.is_empty());
    }

    #[test]
    fn test_diff_a_longer() {
        let a = b"Hi!!";
        let b_data = b"Hi";
        let d = slice_diff(a, b_data);
        assert!(d.changed_offsets.is_empty());
        assert!(d.added.is_empty());
        assert_eq!(d.removed.len(), 1);
        assert_eq!(d.removed[0].start, 2);
        assert_eq!(d.removed[0].len, 2);
    }

    #[test]
    fn test_render_diff_smoke() {
        let a = b"AAAA";
        let b_data = b"ABAA";
        let d = slice_diff(a, b_data);
        let rendered = render_diff(&d, a, b_data);
        assert!(rendered.contains('*'));
        assert!(rendered.contains("Changed bytes: 1"));
    }

    // ── HexSearchEngine ───────────────────────────────────────────────────────

    #[test]
    fn test_search_exact_found() {
        let data = b"Hello, world!";
        let offsets = HexSearchEngine::search_exact(data, b"world");
        assert_eq!(offsets, vec![7u64]);
    }

    #[test]
    fn test_search_exact_not_found() {
        let data = b"Hello";
        assert!(HexSearchEngine::search_exact(data, b"xyz").is_empty());
    }

    #[test]
    fn test_search_exact_overlapping() {
        let data = b"AAAA";
        let offsets = HexSearchEngine::search_exact(data, b"AA");
        // KMP finds overlapping: positions 0, 1, 2
        assert_eq!(offsets, vec![0, 1, 2]);
    }

    #[test]
    fn test_search_exact_empty_pattern() {
        let data = b"Hello";
        assert!(HexSearchEngine::search_exact(data, b"").is_empty());
    }

    #[test]
    fn test_search_wildcard_full_match() {
        let data = &[0x01u8, 0x02, 0x03];
        let pattern = &[0x01u8, 0x00, 0x03];
        let mask = &[0xFFu8, 0x00, 0xFF];
        let offsets = HexSearchEngine::search_wildcard(data, pattern, mask);
        assert_eq!(offsets, vec![0u64]);
    }

    #[test]
    fn test_search_wildcard_no_match() {
        let data = &[0x01u8, 0x02, 0x04];
        let pattern = &[0x01u8, 0x00, 0x03];
        let mask = &[0xFFu8, 0x00, 0xFF];
        let offsets = HexSearchEngine::search_wildcard(data, pattern, mask);
        assert!(offsets.is_empty());
    }

    #[test]
    fn test_search_wildcard_partial_nibble() {
        // Match high nibble of byte 1: must be 0x20..=0x2F
        let data = &[0xAAu8, 0x2Bu8, 0xBBu8];
        let pattern = &[0xAAu8, 0x20u8, 0xBBu8];
        let mask = &[0xFFu8, 0xF0u8, 0xFFu8];
        let offsets = HexSearchEngine::search_wildcard(data, pattern, mask);
        assert_eq!(offsets, vec![0u64]);
    }

    #[test]
    fn test_search_regex_hex_exact() {
        let data = b"\x48\x65\x6C\x6C\x6F";
        let offsets = HexSearchEngine::search_regex_hex(data, "48 65 6C 6C 6F").unwrap();
        assert_eq!(offsets, vec![0u64]);
    }

    #[test]
    fn test_search_regex_hex_wildcard_nibble() {
        // pattern "4?" matches any byte 0x40..=0x4F
        let data = &[0x41u8, 0x42, 0x43];
        let offsets = HexSearchEngine::search_regex_hex(data, "4?").unwrap();
        assert_eq!(offsets, vec![0u64, 1, 2]);
    }

    #[test]
    fn test_search_regex_hex_full_wildcard() {
        let data = b"AB";
        let offsets = HexSearchEngine::search_regex_hex(data, "??").unwrap();
        assert_eq!(offsets, vec![0u64, 1]);
    }

    #[test]
    fn test_search_regex_hex_invalid_token() {
        let data = b"AB";
        let result = HexSearchEngine::search_regex_hex(data, "XYZ");
        assert!(result.is_err());
    }

    #[test]
    fn test_search_regex_hex_no_match() {
        let data = &[0x50u8, 0x51];
        let offsets = HexSearchEngine::search_regex_hex(data, "4?").unwrap();
        assert!(offsets.is_empty());
    }

    // ── HexAnnotationLayer ────────────────────────────────────────────────────

    #[test]
    fn test_add_and_retrieve_annotation() {
        let mut layer = HexAnnotationLayer::new();
        let id = layer.add_annotation(0, 4, "header", 1);
        let at0 = layer.annotations_at(0);
        assert_eq!(at0.len(), 1);
        assert_eq!(at0[0].id, id);
        assert_eq!(at0[0].name, "header");
    }

    #[test]
    fn test_annotation_boundary() {
        let mut layer = HexAnnotationLayer::new();
        layer.add_annotation(2, 4, "mid", 2); // covers offsets 2,3,4,5
        assert!(layer.annotations_at(1).is_empty());
        assert_eq!(layer.annotations_at(2).len(), 1);
        assert_eq!(layer.annotations_at(5).len(), 1);
        assert!(layer.annotations_at(6).is_empty());
    }

    #[test]
    fn test_remove_annotation() {
        let mut layer = HexAnnotationLayer::new();
        let id = layer.add_annotation(0, 4, "x", 0);
        layer.remove_annotation(id);
        assert!(layer.annotations_at(0).is_empty());
    }

    #[test]
    fn test_overlapping_annotations() {
        let mut layer = HexAnnotationLayer::new();
        layer.add_annotation(0, 8, "outer", 1);
        layer.add_annotation(2, 2, "inner", 2);
        let at2 = layer.annotations_at(2);
        assert_eq!(at2.len(), 2);
    }

    #[test]
    fn test_render_with_annotations_smoke() {
        let data = b"Hello, world!   ";
        let mut layer = HexAnnotationLayer::new();
        let ann = layer.add_annotation(0, 5, "greeting", 3);
        let rendered = HexAnnotationLayer::render_with_annotations(data, layer.all());
        assert!(rendered.contains("greeting"));
        let _ = ann; // suppress unused warning
    }

    #[test]
    fn test_render_with_annotations_no_annotations() {
        let data = b"ABCD";
        let rendered = HexAnnotationLayer::render_with_annotations(data, &[]);
        assert!(rendered.contains("41"));
        assert!(rendered.contains("42"));
    }
}
