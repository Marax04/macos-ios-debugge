//! Hex patch manager.
//!
//! Tracks byte-level patches over a binary blob, computes diffs against the
//! original bytes, and can persist / restore patch sets.
//!
//! # Key types
//!
//! * [`HexPatchManager`] — owns the original buffer and the patch registry.
//! * [`Patch`] — a named, annotated set of [`PatchEntry`] records.
//! * [`PatchEntry`] — a single contiguous byte replacement.
//! * Free functions [`diff_original`] / [`apply_to_file`].

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::Path;

// ── PatchEntry ────────────────────────────────────────────────────────────────

/// A single contiguous byte replacement at a given offset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchEntry {
    /// Byte offset within the buffer.
    pub offset: usize,
    /// The original bytes at this offset (populated when the patch is applied).
    pub original: Vec<u8>,
    /// The replacement bytes.
    pub patched: Vec<u8>,
    /// Optional human-readable comment.
    pub comment: Option<String>,
}

impl PatchEntry {
    /// Create a new entry with no original bytes recorded yet.
    #[must_use]
    pub const fn new(offset: usize, patched: Vec<u8>) -> Self {
        Self { offset, original: Vec::new(), patched, comment: None }
    }

    /// Create a fully-specified entry.
    #[must_use]
    pub const fn with_original(offset: usize, original: Vec<u8>, patched: Vec<u8>) -> Self {
        Self { offset, original, patched, comment: None }
    }

    /// Length of the patch (in bytes).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.patched.len()
    }

    /// Returns `true` when no bytes are changed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patched.is_empty()
    }

    /// Whether this entry actually changes the bytes (original != patched).
    #[must_use]
    pub fn is_noop(&self) -> bool {
        !self.original.is_empty() && self.original == self.patched
    }

    /// Last byte offset (exclusive) that this entry covers.
    #[must_use]
    pub const fn end_offset(&self) -> usize {
        self.offset.saturating_add(self.patched.len())
    }

    /// Returns `true` if this entry overlaps the given range `[start, end)`.
    #[must_use]
    pub const fn overlaps(&self, start: usize, end: usize) -> bool {
        self.offset < end && self.end_offset() > start
    }

    /// Hex string of the patched bytes.
    #[must_use]
    pub fn patched_hex(&self) -> String {
        bytes_to_hex(&self.patched)
    }

    /// Hex string of the original bytes.
    #[must_use]
    pub fn original_hex(&self) -> String {
        bytes_to_hex(&self.original)
    }
}

impl fmt::Display for PatchEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "offset={:#010x} original=[{}] patched=[{}]",
            self.offset,
            self.original_hex(),
            self.patched_hex()
        )?;
        if let Some(c) = &self.comment {
            write!(f, " // {c}")?;
        }
        Ok(())
    }
}

// ── Patch ─────────────────────────────────────────────────────────────────────

/// A named set of [`PatchEntry`] records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Patch {
    /// Unique patch name.
    pub name: String,
    /// Optional long description.
    pub description: Option<String>,
    /// Whether this patch is currently applied to the buffer.
    pub applied: bool,
    /// The individual byte replacements.
    pub entries: Vec<PatchEntry>,
}

impl Patch {
    /// Create a new empty patch.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), description: None, applied: false, entries: Vec::new() }
    }

    /// Attach a description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Add a single entry.
    pub fn add_entry(&mut self, entry: PatchEntry) {
        self.entries.push(entry);
    }

    /// Total bytes changed by this patch.
    #[must_use]
    pub fn byte_count(&self) -> usize {
        self.entries.iter().map(PatchEntry::len).sum()
    }

    /// Check whether any two entries overlap in offset range.
    #[must_use]
    pub fn has_overlapping_entries(&self) -> bool {
        let n = self.entries.len();
        for i in 0..n {
            for j in (i + 1)..n {
                let a = &self.entries[i];
                let b = &self.entries[j];
                if a.overlaps(b.offset, b.end_offset()) {
                    return true;
                }
            }
        }
        false
    }
}

// ── PatchError ────────────────────────────────────────────────────────────────

/// Errors produced by [`HexPatchManager`].
#[derive(Debug, thiserror::Error)]
pub enum PatchError {
    #[error("patch not found: {0}")]
    NotFound(String),
    #[error("patch already applied: {0}")]
    AlreadyApplied(String),
    #[error("patch not applied: {0}")]
    NotApplied(String),
    #[error("patch out of bounds: offset={offset}, len={len}, buffer_size={buf_size}")]
    OutOfBounds { offset: usize, len: usize, buf_size: usize },
    #[error("overlapping patch entries in patch {0}")]
    OverlappingEntries(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(String),
}

// ── HexPatchManager ───────────────────────────────────────────────────────────

/// Manages byte-level patches over a binary buffer.
///
/// Keeps a snapshot of the original bytes so any number of patches can be
/// applied and reverted without data loss.
pub struct HexPatchManager {
    /// Mutable working copy of the binary.
    buffer: Vec<u8>,
    /// Immutable snapshot of the original bytes.
    original: Vec<u8>,
    /// Named patches indexed by name.
    patches: HashMap<String, Patch>,
    /// Insertion order for deterministic iteration.
    patch_order: Vec<String>,
}

impl HexPatchManager {
    /// Create a manager from an existing buffer.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        let original = data.clone();
        Self { buffer: data, original, patches: HashMap::new(), patch_order: Vec::new() }
    }

    /// Create a manager for a zero-filled buffer of `size` bytes.
    #[must_use]
    pub fn zeroed(size: usize) -> Self {
        Self::new(vec![0u8; size])
    }

    /// Load a binary file into a new manager.
    ///
    /// # Errors
    ///
    /// Returns [`PatchError`] if reading the file fails.
    pub fn from_file(path: &Path) -> Result<Self, PatchError> {
        let data = std::fs::read(path)?;
        Ok(Self::new(data))
    }

    // ── Buffer access ─────────────────────────────────────────────────────────

    /// Current (possibly patched) buffer contents.
    #[must_use]
    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    /// Original unmodified buffer.
    #[must_use]
    pub fn original(&self) -> &[u8] {
        &self.original
    }

    /// Buffer length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.buffer.len()
    }

    /// True when the buffer is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Read bytes from the current (patched) buffer.
    #[must_use]
    pub fn read_bytes(&self, offset: usize, len: usize) -> Option<&[u8]> {
        let end = offset.checked_add(len)?;
        if end > self.buffer.len() {
            return None;
        }
        Some(&self.buffer[offset..end])
    }

    // ── Patch registration ─────────────────────────────────────────────────────

    /// Register a patch (does not apply it yet).
    ///
    /// # Errors
    ///
    /// Returns [`PatchError::OverlappingEntries`] or [`PatchError::OutOfBounds`] on invalid patches.
    pub fn register(&mut self, patch: Patch) -> Result<(), PatchError> {
        if patch.has_overlapping_entries() {
            return Err(PatchError::OverlappingEntries(patch.name));
        }
        for entry in &patch.entries {
            let end = entry.offset.saturating_add(entry.patched.len());
            if end > self.buffer.len() {
                return Err(PatchError::OutOfBounds {
                    offset: entry.offset,
                    len: entry.patched.len(),
                    buf_size: self.buffer.len(),
                });
            }
        }
        if !self.patches.contains_key(&patch.name) {
            self.patch_order.push(patch.name.clone());
        }
        self.patches.insert(patch.name.clone(), patch);
        Ok(())
    }

    /// Remove a registered patch.  It must not be applied.
    ///
    /// # Errors
    ///
    /// Returns [`PatchError::NotFound`] if no patch with `name` exists, or
    /// [`PatchError::AlreadyApplied`] if the patch is currently applied.
    pub fn remove(&mut self, name: &str) -> Result<(), PatchError> {
        let patch = self.patches.get(name).ok_or_else(|| PatchError::NotFound(name.to_owned()))?;
        if patch.applied {
            return Err(PatchError::AlreadyApplied(name.to_owned()));
        }
        self.patches.remove(name);
        self.patch_order.retain(|n| n != name);
        Ok(())
    }

    // ── Apply / revert ────────────────────────────────────────────────────────

    /// Apply a registered patch to the buffer.
    ///
    /// # Errors
    ///
    /// Returns [`PatchError::NotFound`], [`PatchError::AlreadyApplied`], or
    /// [`PatchError::OutOfBounds`] on failure.
    pub fn apply(&mut self, name: &str) -> Result<(), PatchError> {
        let patch =
            self.patches.get_mut(name).ok_or_else(|| PatchError::NotFound(name.to_owned()))?;
        if patch.applied {
            return Err(PatchError::AlreadyApplied(name.to_owned()));
        }
        let buf = &mut self.buffer;
        for entry in &mut patch.entries {
            let end = entry.offset.checked_add(entry.patched.len())
                .filter(|&e| e <= buf.len())
                .ok_or(PatchError::OutOfBounds {
                    offset: entry.offset,
                    len: entry.patched.len(),
                    buf_size: buf.len(),
                })?;
            entry.original = buf[entry.offset..end].to_vec();
            buf[entry.offset..end].copy_from_slice(&entry.patched);
        }
        patch.applied = true;
        Ok(())
    }

    /// Revert a previously applied patch.
    ///
    /// # Errors
    ///
    /// Returns [`PatchError::NotFound`] or [`PatchError::NotApplied`] on failure.
    pub fn revert(&mut self, name: &str) -> Result<(), PatchError> {
        let patch =
            self.patches.get_mut(name).ok_or_else(|| PatchError::NotFound(name.to_owned()))?;
        if !patch.applied {
            return Err(PatchError::NotApplied(name.to_owned()));
        }
        let buf = &mut self.buffer;
        for entry in &mut patch.entries {
            let end = entry.offset.checked_add(entry.patched.len())
                .filter(|&e| e <= buf.len())
                .ok_or(PatchError::OutOfBounds {
                    offset: entry.offset,
                    len: entry.patched.len(),
                    buf_size: buf.len(),
                })?;
            buf[entry.offset..end].copy_from_slice(&entry.original);
        }
        patch.applied = false;
        Ok(())
    }

    /// Apply all registered patches in insertion order.
    pub fn apply_all(&mut self) -> Vec<Result<(), PatchError>> {
        let names: Vec<String> = self.patch_order.clone();
        names.iter().map(|n| self.apply(n)).collect()
    }

    /// Revert all applied patches in reverse insertion order.
    pub fn revert_all(&mut self) -> Vec<Result<(), PatchError>> {
        let names: Vec<String> = self.patch_order.iter().cloned().rev().collect();
        names.iter().map(|n| self.revert(n)).collect()
    }

    // ── Diff ──────────────────────────────────────────────────────────────────

    /// Compute byte-level differences between the original and current buffer.
    ///
    /// Returns a list of `(offset, original_byte, patched_byte)` tuples.
    #[must_use]
    pub fn diff(&self) -> Vec<(usize, u8, u8)> {
        diff_buffers(&self.original, &self.buffer)
    }

    /// Contiguous diff runs (more useful for display).
    #[must_use]
    pub fn diff_runs(&self) -> Vec<DiffRun> {
        diff_runs(&self.original, &self.buffer)
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    /// Write the current (patched) buffer to a file.
    ///
    /// # Errors
    ///
    /// Returns [`PatchError`] if writing to the file fails.
    pub fn write_to_file(&self, path: &Path) -> Result<(), PatchError> {
        std::fs::write(path, &self.buffer)?;
        Ok(())
    }

    /// Export patch metadata to JSON.
    ///
    /// # Errors
    ///
    /// Returns [`PatchError::Serialization`] if JSON serialization fails.
    pub fn export_patches_json(&self) -> Result<String, PatchError> {
        let patches: Vec<&Patch> =
            self.patch_order.iter().filter_map(|n| self.patches.get(n)).collect();
        serde_json::to_string_pretty(&patches)
            .map_err(|e| PatchError::Serialization(e.to_string()))
    }

    /// List all registered patches with their applied status.
    #[must_use]
    pub fn list_patches(&self) -> Vec<PatchSummary> {
        self.patch_order
            .iter()
            .filter_map(|n| self.patches.get(n))
            .map(|p| PatchSummary {
                name: p.name.clone(),
                applied: p.applied,
                entry_count: p.entries.len(),
                byte_count: p.byte_count(),
                description: p.description.clone(),
            })
            .collect()
    }

    /// Look up a patch by name.
    #[must_use]
    pub fn get_patch(&self, name: &str) -> Option<&Patch> {
        self.patches.get(name)
    }
}

// ── PatchSummary ──────────────────────────────────────────────────────────────

/// Lightweight summary of a registered patch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchSummary {
    pub name: String,
    pub applied: bool,
    pub entry_count: usize,
    pub byte_count: usize,
    pub description: Option<String>,
}

// ── DiffRun ───────────────────────────────────────────────────────────────────

/// A contiguous run of changed bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffRun {
    pub offset: usize,
    pub original: Vec<u8>,
    pub patched: Vec<u8>,
}

impl DiffRun {
    #[must_use]
    pub const fn len(&self) -> usize {
        self.patched.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patched.is_empty()
    }
}

impl fmt::Display for DiffRun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#010x}: [{}] → [{}]",
            self.offset,
            bytes_to_hex(&self.original),
            bytes_to_hex(&self.patched)
        )
    }
}

// ── Free functions ────────────────────────────────────────────────────────────

/// Compute byte differences between `original` and `patched`.
///
/// Returns `(offset, orig_byte, new_byte)` for every position that differs.
#[must_use]
pub fn diff_original(original: &[u8], patched: &[u8]) -> Vec<(usize, u8, u8)> {
    diff_buffers(original, patched)
}

/// Write `data` to `path`, creating or truncating the file.
///
/// # Errors
///
/// Returns an [`std::io::Error`] if the file cannot be written.
pub fn apply_to_file(data: &[u8], path: &Path) -> std::io::Result<()> {
    std::fs::write(path, data)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn diff_buffers(original: &[u8], patched: &[u8]) -> Vec<(usize, u8, u8)> {
    let len = original.len().min(patched.len());
    let mut diffs = Vec::new();
    for i in 0..len {
        if original[i] != patched[i] {
            diffs.push((i, original[i], patched[i]));
        }
    }
    diffs
}

fn diff_runs(original: &[u8], patched: &[u8]) -> Vec<DiffRun> {
    let diffs = diff_buffers(original, patched);
    if diffs.is_empty() {
        return Vec::new();
    }
    let mut runs: Vec<DiffRun> = Vec::new();
    let mut current = DiffRun {
        offset: diffs[0].0,
        original: vec![diffs[0].1],
        patched: vec![diffs[0].2],
    };
    for &(offset, orig, pat) in &diffs[1..] {
        if offset == current.offset + current.patched.len() {
            current.original.push(orig);
            current.patched.push(pat);
        } else {
            runs.push(current.clone());
            current = DiffRun { offset, original: vec![orig], patched: vec![pat] };
        }
    }
    runs.push(current);
    runs
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager() -> HexPatchManager {
        HexPatchManager::new(vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
    }

    fn simple_patch(name: &str, offset: usize, bytes: Vec<u8>) -> Patch {
        let mut p = Patch::new(name);
        p.add_entry(PatchEntry::new(offset, bytes));
        p
    }

    #[test]
    fn test_apply_patch() {
        let mut mgr = make_manager();
        let patch = simple_patch("p1", 2, vec![0xFF, 0xFE]);
        mgr.register(patch).unwrap();
        mgr.apply("p1").unwrap();
        assert_eq!(mgr.buffer()[2], 0xFF);
        assert_eq!(mgr.buffer()[3], 0xFE);
    }

    #[test]
    fn test_revert_patch() {
        let mut mgr = make_manager();
        let patch = simple_patch("p1", 2, vec![0xFF]);
        mgr.register(patch).unwrap();
        mgr.apply("p1").unwrap();
        mgr.revert("p1").unwrap();
        assert_eq!(mgr.buffer()[2], 0x02);
    }

    #[test]
    fn test_apply_already_applied() {
        let mut mgr = make_manager();
        let patch = simple_patch("p1", 0, vec![0xAA]);
        mgr.register(patch).unwrap();
        mgr.apply("p1").unwrap();
        assert!(matches!(mgr.apply("p1"), Err(PatchError::AlreadyApplied(_))));
    }

    #[test]
    fn test_revert_not_applied() {
        let mut mgr = make_manager();
        let patch = simple_patch("p1", 0, vec![0xAA]);
        mgr.register(patch).unwrap();
        assert!(matches!(mgr.revert("p1"), Err(PatchError::NotApplied(_))));
    }

    #[test]
    fn test_patch_not_found() {
        let mut mgr = make_manager();
        assert!(matches!(mgr.apply("nope"), Err(PatchError::NotFound(_))));
    }

    #[test]
    fn test_out_of_bounds() {
        let mut mgr = make_manager();
        let patch = simple_patch("p1", 7, vec![0x00, 0x00]); // overruns by 1
        assert!(matches!(mgr.register(patch), Err(PatchError::OutOfBounds { .. })));
    }

    #[test]
    fn test_diff() {
        let mut mgr = make_manager();
        let patch = simple_patch("p1", 0, vec![0xFF]);
        mgr.register(patch).unwrap();
        mgr.apply("p1").unwrap();
        let d = mgr.diff();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0], (0, 0x00, 0xFF));
    }

    #[test]
    fn test_diff_original_fn() {
        let orig = vec![1u8, 2, 3];
        let patched = vec![1u8, 9, 3];
        let diffs = diff_original(&orig, &patched);
        assert_eq!(diffs, vec![(1, 2, 9)]);
    }

    #[test]
    fn test_diff_runs() {
        let mut mgr = HexPatchManager::new(vec![0; 6]);
        let mut p = Patch::new("p");
        p.add_entry(PatchEntry::new(0, vec![0x01, 0x02])); // run 1
        p.add_entry(PatchEntry::new(4, vec![0x03]));        // run 2
        mgr.register(p).unwrap();
        mgr.apply("p").unwrap();
        let runs = mgr.diff_runs();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].offset, 0);
        assert_eq!(runs[1].offset, 4);
    }

    #[test]
    fn test_apply_all_revert_all() {
        let mut mgr = make_manager();
        let p1 = simple_patch("p1", 0, vec![0xAA]);
        let p2 = simple_patch("p2", 1, vec![0xBB]);
        mgr.register(p1).unwrap();
        mgr.register(p2).unwrap();
        let results = mgr.apply_all();
        assert!(results.iter().all(|r| r.is_ok()));
        let results2 = mgr.revert_all();
        assert!(results2.iter().all(|r| r.is_ok()));
        assert_eq!(mgr.buffer(), mgr.original());
    }

    #[test]
    fn test_overlapping_entries_rejected() {
        let mut p = Patch::new("p");
        p.add_entry(PatchEntry::new(0, vec![0x01, 0x02]));
        p.add_entry(PatchEntry::new(1, vec![0x03]));
        assert!(p.has_overlapping_entries());
        let mut mgr = make_manager();
        assert!(matches!(mgr.register(p), Err(PatchError::OverlappingEntries(_))));
    }

    #[test]
    fn test_remove_patch() {
        let mut mgr = make_manager();
        let p = simple_patch("p1", 0, vec![0xFF]);
        mgr.register(p).unwrap();
        mgr.remove("p1").unwrap();
        assert!(mgr.get_patch("p1").is_none());
    }

    #[test]
    fn test_list_patches() {
        let mut mgr = make_manager();
        let p = simple_patch("p1", 0, vec![0xFF]);
        mgr.register(p).unwrap();
        let list = mgr.list_patches();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "p1");
        assert!(!list[0].applied);
    }

    #[test]
    fn test_export_patches_json() {
        let mut mgr = make_manager();
        let p = simple_patch("p1", 0, vec![0xAA]);
        mgr.register(p).unwrap();
        let json = mgr.export_patches_json().unwrap();
        assert!(json.contains("p1"));
    }

    #[test]
    fn test_read_bytes() {
        let mgr = make_manager();
        let bytes = mgr.read_bytes(2, 3).unwrap();
        assert_eq!(bytes, &[0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_read_bytes_out_of_bounds() {
        let mgr = make_manager();
        assert!(mgr.read_bytes(6, 4).is_none());
    }

    #[test]
    fn test_patch_entry_display() {
        let e = PatchEntry::with_original(4, vec![0x01], vec![0xFF]);
        let s = e.to_string();
        assert!(s.contains("0x00000004"));
    }

    #[test]
    fn test_diff_run_display() {
        let run = DiffRun { offset: 0, original: vec![0x00], patched: vec![0xFF] };
        let s = run.to_string();
        assert!(s.contains("ff"));
    }

    #[test]
    fn test_bytes_to_hex() {
        assert_eq!(bytes_to_hex(&[0xDE, 0xAD, 0xBE, 0xEF]), "de ad be ef");
    }

    #[test]
    fn test_patch_byte_count() {
        let mut p = Patch::new("p");
        p.add_entry(PatchEntry::new(0, vec![1, 2, 3]));
        p.add_entry(PatchEntry::new(4, vec![4, 5]));
        assert_eq!(p.byte_count(), 5);
    }
}
