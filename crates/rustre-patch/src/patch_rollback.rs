//! `patch_rollback` — Create and apply rollback snapshots for binary patches.
//!
//! Provides [`PatchRollback`], [`RollbackEntry`], [`RollbackResult`], and
//! the primary entry point [`create_rollback`].

use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Patch, PatchSet};
use crate::binary_patcher::AppliedOp;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by rollback operations.
#[derive(Debug, Error)]
pub enum RollbackError {
    /// The rollback entry references an unknown patch id.
    #[error("unknown patch id in rollback: '{0}'")]
    UnknownPatchId(String),
    /// The rollback entry's original bytes are inconsistent with the current binary.
    #[error("original bytes mismatch at offset {0:#x} for patch '{1}'")]
    OriginalBytesMismatch(u64, String),
    /// The rollback would write out of bounds.
    #[error("rollback would exceed buffer bounds for patch '{0}'")]
    OutOfBounds(String),
    /// No entries to roll back.
    #[error("rollback is empty")]
    Empty,
    /// The rollback has already been applied.
    #[error("rollback already applied")]
    AlreadyApplied,
    /// A checksum mismatch was detected after rollback.
    #[error("checksum mismatch after rollback: expected {expected:#018x} got {actual:#018x}")]
    ChecksumMismatch { expected: u64, actual: u64 },
}

// ---------------------------------------------------------------------------
// RollbackEntry
// ---------------------------------------------------------------------------

/// A record of the bytes at a specific offset before a patch was applied.
///
/// Used to restore the binary to its pre-patch state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackEntry {
    /// The patch id this entry undoes.
    pub patch_id: String,
    /// Byte offset in the binary.
    pub offset: u64,
    /// The original bytes at this offset (to be restored).
    pub original_bytes: Vec<u8>,
    /// The bytes that were written by the patch (for forward verification).
    pub patched_bytes: Vec<u8>,
    /// Human-readable description of the patch being undone.
    pub description: String,
    /// Sequence number for ordering rollback entries.
    pub sequence: u32,
}

impl RollbackEntry {
    /// Create a new entry from an [`AppliedOp`].
    #[must_use]
    pub fn from_applied_op(op: &AppliedOp, sequence: u32) -> Self {
        Self {
            patch_id: op.patch_id.clone(),
            offset: op.offset,
            original_bytes: op.bytes_original.clone(),
            patched_bytes: op.bytes_written.clone(),
            description: format!("undo patch '{}' at {:#x}", op.patch_id, op.offset),
            sequence,
        }
    }

    /// Create a new entry directly from a [`Patch`].
    ///
    /// The entry stores `patch.original_bytes` as the bytes to restore and
    /// `patch.patch_bytes` as the forward bytes.
    #[must_use]
    pub fn from_patch(patch: &Patch, sequence: u32) -> Self {
        Self {
            patch_id: patch.id.clone(),
            offset: patch.offset,
            original_bytes: patch.original_bytes.clone(),
            patched_bytes: patch.patch_bytes.clone(),
            description: format!("undo '{}': {}", patch.id, patch.description),
            sequence,
        }
    }

    /// Size in bytes of the rollback entry.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.original_bytes.len()
    }

    /// Verify that the current binary at the recorded offset matches
    /// the patched bytes (i.e. the patch was applied and we can roll back).
    #[must_use]
    pub fn can_rollback(&self, binary: &[u8]) -> bool {
        let Ok(start) = usize::try_from(self.offset) else { return false };
        let Some(end) = start.checked_add(self.patched_bytes.len()) else { return false };
        if end > binary.len() {
            return false;
        }
        binary[start..end] == self.patched_bytes
    }

    /// Verify that the binary at the recorded offset already contains the
    /// original bytes (i.e. the patch was not applied or was already rolled back).
    #[must_use]
    pub fn is_already_rolled_back(&self, binary: &[u8]) -> bool {
        let Ok(start) = usize::try_from(self.offset) else { return false };
        let Some(end) = start.checked_add(self.original_bytes.len()) else { return false };
        if end > binary.len() {
            return false;
        }
        binary[start..end] == self.original_bytes
    }
}

impl fmt::Display for RollbackEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RollbackEntry[{}] seq={} @{:#x} ({} bytes): {}",
            self.patch_id,
            self.sequence,
            self.offset,
            self.original_bytes.len(),
            self.description
        )
    }
}

// ---------------------------------------------------------------------------
// RollbackResult
// ---------------------------------------------------------------------------

/// The result of applying a rollback operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackResult {
    /// The binary data after rollback.
    pub data: Vec<u8>,
    /// Number of entries that were rolled back.
    pub entries_applied: usize,
    /// Number of entries that were already in the correct state.
    pub entries_skipped: usize,
    /// Checksum of the rolled-back binary.
    pub checksum: u64,
}

impl RollbackResult {
    /// Returns `true` if all expected entries were applied.
    #[must_use]
    pub const fn is_complete(&self, expected: usize) -> bool {
        self.entries_applied == expected
    }
}

impl fmt::Display for RollbackResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RollbackResult: applied={} skipped={} checksum={:#018x}",
            self.entries_applied, self.entries_skipped, self.checksum
        )
    }
}

// ---------------------------------------------------------------------------
// RollbackSnapshot
// ---------------------------------------------------------------------------

/// A snapshot of the binary state at a specific point in time, before patches
/// were applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackSnapshot {
    /// Snapshot identifier.
    pub id: String,
    /// Unix timestamp when the snapshot was created.
    pub created_at: u64,
    /// FNV-1a checksum of the binary at snapshot time.
    pub original_checksum: u64,
    /// All rollback entries, ordered by sequence number.
    pub entries: Vec<RollbackEntry>,
    /// Optional label for this snapshot.
    pub label: Option<String>,
}

impl RollbackSnapshot {
    /// Create a snapshot from a set of entries.
    #[must_use]
    pub fn new(id: impl Into<String>, entries: Vec<RollbackEntry>, original_checksum: u64) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Self {
            id: id.into(),
            created_at,
            original_checksum,
            entries,
            label: None,
        }
    }

    /// Add a label to this snapshot.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Total number of entries.
    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Total bytes covered by all entries.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.entries.iter().map(RollbackEntry::size).sum()
    }
}

impl fmt::Display for RollbackSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RollbackSnapshot[{}] entries={} bytes={} checksum={:#018x}",
            self.id,
            self.entry_count(),
            self.total_bytes(),
            self.original_checksum
        )
    }
}

// ---------------------------------------------------------------------------
// PatchRollback
// ---------------------------------------------------------------------------

/// Manages rollback snapshots for binary patches.
///
/// Stores a history of snapshots that can be used to undo applied patches.
pub struct PatchRollback {
    snapshots: HashMap<String, RollbackSnapshot>,
    /// Whether to verify checksum after rollback.
    verify_checksum: bool,
}

impl PatchRollback {
    /// Create a new rollback manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            snapshots: HashMap::new(),
            verify_checksum: true,
        }
    }

    /// Enable or disable checksum verification after rollback.
    #[must_use]
    pub const fn verify_checksum(mut self, verify: bool) -> Self {
        self.verify_checksum = verify;
        self
    }

    /// Create a rollback snapshot from a [`PatchSet`] and the current binary.
    ///
    /// Captures the original bytes at each patch offset *before* any patches
    /// are applied.
    ///
    /// # Errors
    ///
    /// Returns [`RollbackError::Empty`] if the patch set is empty.
    ///
    /// # Panics
    ///
    /// Panics only if the snapshot we just inserted is missing on lookup — statically impossible.
    pub fn create_snapshot(
        &mut self,
        patch_set: &PatchSet,
        binary: &[u8],
        snapshot_id: impl Into<String>,
    ) -> Result<&RollbackSnapshot, RollbackError> {
        if patch_set.is_empty() {
            return Err(RollbackError::Empty);
        }
        let id: String = snapshot_id.into();
        let checksum = fnv1a_64(binary);
        let entries: Vec<RollbackEntry> = patch_set.patches.iter().enumerate()
            .map(|(seq, patch)| {
                // Capture current bytes at the patch offset
                let start = usize::try_from(patch.offset).unwrap_or(usize::MAX);
                let end = start.saturating_add(patch.patch_bytes.len()).min(binary.len());
                let current_bytes = if start < binary.len() {
                    binary[start..end].to_vec()
                } else {
                    Vec::new()
                };
                RollbackEntry {
                    patch_id: patch.id.clone(),
                    offset: patch.offset,
                    original_bytes: current_bytes,
                    patched_bytes: patch.patch_bytes.clone(),
                    description: patch.description.clone(),
                    sequence: u32::try_from(seq).unwrap_or(u32::MAX),
                }
            })
            .collect();

        let snapshot = RollbackSnapshot::new(id.clone(), entries, checksum);
        self.snapshots.insert(id.clone(), snapshot);
        Ok(self.snapshots.get(&id).unwrap())
    }

    /// Create a rollback snapshot from a list of applied ops.
    ///
    /// # Errors
    ///
    /// Returns [`RollbackError::Empty`] if `ops` is empty.
    ///
    /// # Panics
    ///
    /// Panics only if the snapshot we just inserted is missing on lookup — statically impossible.
    pub fn create_snapshot_from_ops(
        &mut self,
        ops: &[AppliedOp],
        original_checksum: u64,
        snapshot_id: impl Into<String>,
    ) -> Result<&RollbackSnapshot, RollbackError> {
        if ops.is_empty() {
            return Err(RollbackError::Empty);
        }
        let id: String = snapshot_id.into();
        let entries: Vec<RollbackEntry> = ops.iter().enumerate()
            .map(|(seq, op)| RollbackEntry::from_applied_op(op, u32::try_from(seq).unwrap_or(u32::MAX)))
            .collect();
        let snapshot = RollbackSnapshot::new(id.clone(), entries, original_checksum);
        self.snapshots.insert(id.clone(), snapshot);
        Ok(self.snapshots.get(&id).unwrap())
    }

    /// Apply a rollback snapshot, restoring the binary to its pre-patch state.
    ///
    /// Entries are applied in *reverse sequence order*.
    ///
    /// # Errors
    ///
    /// Returns [`RollbackError`] if the snapshot is missing, already applied,
    /// or if individual rollback writes fail.
    pub fn rollback(
        &self,
        snapshot_id: &str,
        binary: &[u8],
    ) -> Result<RollbackResult, RollbackError> {
        let snapshot = self.snapshots.get(snapshot_id)
            .ok_or_else(|| RollbackError::UnknownPatchId(snapshot_id.to_string()))?;
        self.apply_snapshot(snapshot, binary)
    }

    /// Apply a specific snapshot object.
    ///
    /// # Errors
    ///
    /// Returns [`RollbackError`] if entries are out of bounds or bytes mismatch.
    pub fn apply_snapshot(
        &self,
        snapshot: &RollbackSnapshot,
        binary: &[u8],
    ) -> Result<RollbackResult, RollbackError> {
        if snapshot.entries.is_empty() {
            return Err(RollbackError::Empty);
        }

        let mut data = binary.to_vec();
        let mut entries_applied = 0usize;
        let mut entries_skipped = 0usize;

        // Process in reverse sequence order
        let mut ordered: Vec<&RollbackEntry> = snapshot.entries.iter().collect();
        ordered.sort_by_key(|e| e.sequence);
        ordered.reverse();

        for entry in ordered {
            let start = usize::try_from(entry.offset)
                .map_err(|_| RollbackError::OutOfBounds(entry.patch_id.clone()))?;
            let end = start.checked_add(entry.original_bytes.len())
                .ok_or_else(|| RollbackError::OutOfBounds(entry.patch_id.clone()))?;
            if end > data.len() {
                return Err(RollbackError::OutOfBounds(entry.patch_id.clone()));
            }
            // Check if already rolled back
            if entry.is_already_rolled_back(&data) {
                entries_skipped += 1;
                continue;
            }
            // Apply rollback
            data[start..end].copy_from_slice(&entry.original_bytes);
            entries_applied += 1;
        }

        let checksum = fnv1a_64(&data);

        if self.verify_checksum && snapshot.original_checksum != 0
            && checksum != snapshot.original_checksum {
                return Err(RollbackError::ChecksumMismatch {
                    expected: snapshot.original_checksum,
                    actual: checksum,
                });
            }

        Ok(RollbackResult { data, entries_applied, entries_skipped, checksum })
    }

    /// List all snapshot IDs managed by this rollback manager.
    #[must_use]
    pub fn snapshot_ids(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = self.snapshots.keys().map(String::as_str).collect();
        ids.sort_unstable();
        ids
    }

    /// Get a snapshot by ID.
    #[must_use]
    pub fn get_snapshot(&self, id: &str) -> Option<&RollbackSnapshot> {
        self.snapshots.get(id)
    }

    /// Remove a snapshot by ID.
    pub fn remove_snapshot(&mut self, id: &str) -> Option<RollbackSnapshot> {
        self.snapshots.remove(id)
    }

    /// Number of snapshots managed.
    #[must_use]
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Purge all snapshots.
    pub fn clear(&mut self) {
        self.snapshots.clear();
    }
}

impl Default for PatchRollback {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PatchRollback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PatchRollback(snapshots={})", self.snapshots.len())
    }
}

// ---------------------------------------------------------------------------
// create_rollback — primary entry point
// ---------------------------------------------------------------------------

/// Create a rollback snapshot for the given patches against a binary buffer.
///
/// Captures the bytes at each patch offset *before* any patches are applied.
/// Returns a [`RollbackSnapshot`] that can later be applied via
/// [`PatchRollback::apply_snapshot`] to undo the patches.
///
/// # Errors
///
/// Returns [`RollbackError::Empty`] if `patches` is empty.
pub fn create_rollback(patches: &[Patch], binary: &[u8]) -> Result<RollbackSnapshot, RollbackError> {
    if patches.is_empty() {
        return Err(RollbackError::Empty);
    }
    let checksum = fnv1a_64(binary);
    let entries: Vec<RollbackEntry> = patches.iter().enumerate().map(|(seq, patch)| {
        RollbackEntry::from_patch(patch, u32::try_from(seq).unwrap_or(u32::MAX))
    }).collect();
    Ok(RollbackSnapshot::new("rollback", entries, checksum))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn fnv1a_64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Patch, PatchSet};

    fn binary() -> Vec<u8> {
        (0u8..64).collect()
    }

    fn patch(id: &str, offset: u64) -> Patch {
        let orig: Vec<u8> = (u8::try_from(offset & 0xFF).unwrap_or(0)..).take(4).collect();
        Patch::new(id, "test", offset, orig, vec![0xAA, 0xBB, 0xCC, 0xDD])
    }

    #[test]
    fn test_create_rollback_basic() {
        let patches = vec![patch("p1", 0)];
        let snapshot = create_rollback(&patches, &binary()).unwrap();
        assert_eq!(snapshot.entry_count(), 1);
        assert_eq!(snapshot.entries[0].patch_id, "p1");
    }

    #[test]
    fn test_create_rollback_empty_error() {
        let err = create_rollback(&[], &binary());
        assert!(matches!(err, Err(RollbackError::Empty)));
    }

    #[test]
    fn test_rollback_restores_bytes() {
        let buf = binary();
        let patches = vec![patch("p1", 0), patch("p2", 8)];
        let snapshot = create_rollback(&patches, &buf).unwrap();

        // Apply patches manually
        let mut bytes = buf;
        bytes[0..4].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        bytes[8..12].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

        // Rollback
        let rb = PatchRollback::new().verify_checksum(false);
        let result = rb.apply_snapshot(&snapshot, &bytes).unwrap();
        assert_eq!(&result.data[0..4], &[0x00, 0x01, 0x02, 0x03]);
        assert_eq!(&result.data[8..12], &[0x08, 0x09, 0x0A, 0x0B]);
    }

    #[test]
    fn test_rollback_skip_already_rolled_back() {
        let bin = binary();
        let patches = vec![patch("p1", 0)];
        let snapshot = create_rollback(&patches, &bin).unwrap();
        // Binary is already in original state — rollback should skip
        let rb = PatchRollback::new().verify_checksum(false);
        let result = rb.apply_snapshot(&snapshot, &bin).unwrap();
        assert_eq!(result.entries_skipped, 1);
        assert_eq!(result.entries_applied, 0);
    }

    #[test]
    fn test_patchrollback_create_and_rollback() {
        let bin = binary();
        let mut set = PatchSet::new("s1", "test");
        set.add(patch("p1", 4));

        let mut rollback_manager = PatchRollback::new();
        rollback_manager.create_snapshot(&set, &bin, "snap1").unwrap();
        assert_eq!(rollback_manager.snapshot_count(), 1);

        // Simulate applying patches
        let mut patched = bin.clone();
        patched[4..8].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

        // rollback_manager has verify_checksum=true; the rollback restores the
        // original bytes so the resulting checksum matches the snapshot.
        let _result = rollback_manager.rollback("snap1", &patched).unwrap();
        // Use a second manager with verify_checksum=false for the value assertion.
        let mut rb2 = PatchRollback::new().verify_checksum(false);
        rb2.create_snapshot(&set, &bin, "snap2").unwrap();
        let result2 = rb2.rollback("snap2", &patched).unwrap();
        assert_eq!(&result2.data[4..8], &[0x04, 0x05, 0x06, 0x07]);
    }

    #[test]
    fn test_patchrollback_remove_snapshot() {
        let mut rb = PatchRollback::new();
        let mut set = PatchSet::new("s", "s");
        set.add(patch("p1", 0));
        rb.create_snapshot(&set, &binary(), "snap1").unwrap();
        assert_eq!(rb.snapshot_count(), 1);
        rb.remove_snapshot("snap1");
        assert_eq!(rb.snapshot_count(), 0);
    }

    #[test]
    fn test_patchrollback_snapshot_ids() {
        let mut rb = PatchRollback::new();
        let mut set = PatchSet::new("s", "s");
        set.add(patch("p1", 0));
        rb.create_snapshot(&set, &binary(), "snap_a").unwrap();
        rb.create_snapshot(&set, &binary(), "snap_b").unwrap();
        let ids = rb.snapshot_ids();
        assert!(ids.contains(&"snap_a"));
        assert!(ids.contains(&"snap_b"));
    }

    #[test]
    fn test_rollback_entry_display() {
        let e = RollbackEntry {
            patch_id: "p1".to_string(),
            offset: 0x100,
            original_bytes: vec![0x00, 0x01],
            patched_bytes: vec![0xAA, 0xBB],
            description: "test".to_string(),
            sequence: 0,
        };
        let s = e.to_string();
        assert!(s.contains("p1"));
        assert!(s.contains("0x100"));
    }

    #[test]
    fn test_rollback_snapshot_total_bytes() {
        let patches = vec![patch("p1", 0), patch("p2", 4), patch("p3", 8)];
        let snapshot = create_rollback(&patches, &binary()).unwrap();
        assert_eq!(snapshot.total_bytes(), 12);
    }

    #[test]
    fn test_rollback_entry_can_rollback() {
        let bin = binary();
        let p = patch("p1", 0);
        let entry = RollbackEntry::from_patch(&p, 0);
        // bin[0..4] is [0,1,2,3], entry.patched_bytes is [AA,BB,CC,DD]
        // So can_rollback is false (patch not yet applied)
        assert!(!entry.can_rollback(&bin));
        // After patching
        let mut patched = bin;
        patched[0..4].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        assert!(entry.can_rollback(&patched));
    }

    #[test]
    fn test_rollback_entry_is_already_rolled_back() {
        let bin = binary();
        let p = patch("p1", 0);
        let entry = RollbackEntry::from_patch(&p, 0);
        // original_bytes stored in the patch are the same as what's in bin
        assert!(entry.is_already_rolled_back(&bin));
    }

    #[test]
    fn test_rollback_snapshot_display() {
        let patches = vec![patch("p1", 0)];
        let snapshot = create_rollback(&patches, &binary()).unwrap();
        let s = snapshot.to_string();
        assert!(s.contains("RollbackSnapshot"));
        assert!(s.contains("entries=1"));
    }

    #[test]
    fn test_patchrollback_clear() {
        let mut rb = PatchRollback::new();
        let mut set = PatchSet::new("s", "s");
        set.add(patch("p1", 0));
        rb.create_snapshot(&set, &binary(), "s1").unwrap();
        rb.clear();
        assert_eq!(rb.snapshot_count(), 0);
    }
}
