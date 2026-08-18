//! `pe_patcher` — Apply patches to PE binary data.
//!
//! # Key types
//! * [`PePatcher`]     — main facade; owns the buffer and patch list.
//! * [`PatchEntry`]    — a single patch (NOP, JMP, or raw bytes).
//! * [`NopPatch`]      — fill a region with x86 `0x90` NOPs.
//! * [`JmpPatch`]      — write a relative `E9` near-jump.
//! * [`BytePatch`]     — overwrite bytes with an arbitrary payload.
//! * [`PatchList`]     — ordered collection of patches.
//! * [`PatchApplier`]  — stateless applier; applies a `PatchList` to a buffer.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PatchError {
    #[error("patch out of bounds: offset={offset} len={len} file_size={file_size}")]
    OutOfBounds {
        offset: usize,
        len: usize,
        file_size: usize,
    },
    #[error("patch '{0}' overlaps with existing patch '{1}'")]
    Overlap(String, String),
    #[error("patch '{0}' not found")]
    NotFound(String),
    #[error(
        "jump target {target:#x} too far from source {src_addr:#x} for near jump (delta={delta})"
    )]
    JumpTooFar {
        src_addr: usize,
        target: usize,
        delta: i64,
    },
    #[error("empty patch payload")]
    EmptyPayload,
    #[error("invalid PE buffer: {0}")]
    InvalidPe(String),
    #[error("patch list is empty")]
    EmptyPatchList,
}

pub type PatchResult<T> = Result<T, PatchError>;

// ---------------------------------------------------------------------------
// NopPatch
// ---------------------------------------------------------------------------

/// Fill `len` bytes starting at `offset` with x86 NOP (`0x90`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NopPatch {
    pub offset: usize,
    pub len: usize,
}

impl NopPatch {
    #[must_use]
    pub const fn new(offset: usize, len: usize) -> Self {
        Self { offset, len }
    }

    /// Apply to `buf`, returning the overwritten bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PatchError::OutOfBounds`] if the patch range exceeds the buffer.
    pub fn apply(&self, buf: &mut [u8]) -> PatchResult<Vec<u8>> {
        if self.offset + self.len > buf.len() {
            return Err(PatchError::OutOfBounds {
                offset: self.offset,
                len: self.len,
                file_size: buf.len(),
            });
        }
        let orig = buf[self.offset..self.offset + self.len].to_vec();
        buf[self.offset..self.offset + self.len].fill(0x90);
        Ok(orig)
    }

    #[must_use]
    pub const fn byte_count(&self) -> usize {
        self.len
    }
}

// ---------------------------------------------------------------------------
// JmpPatch
// ---------------------------------------------------------------------------

/// Write a relative near-jump (E9 xx xx xx xx) at `source` pointing to `target`.
///
/// `source` is the address at which the 5-byte `E9` opcode is written;
/// the displacement is `target - (source + 5)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JmpPatch {
    /// File offset where the jump is written.
    pub source_offset: usize,
    /// Target file offset (virtual-address–like in a flat mapping).
    pub target_offset: usize,
    /// If non-zero, pad remaining bytes after the 5-byte jump with NOPs.
    pub total_len: usize,
}

impl JmpPatch {
    #[must_use]
    pub const fn new(source_offset: usize, target_offset: usize) -> Self {
        Self {
            source_offset,
            target_offset,
            total_len: 5,
        }
    }

    #[must_use]
    pub fn with_padding(mut self, total_len: usize) -> Self {
        self.total_len = total_len.max(5);
        self
    }

    /// Apply to `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`PatchError`] if bounds are exceeded or jump distance overflows i32.
    pub fn apply(&self, buf: &mut [u8]) -> PatchResult<Vec<u8>> {
        let end = self.source_offset + self.total_len;
        if end > buf.len() {
            return Err(PatchError::OutOfBounds {
                offset: self.source_offset,
                len: self.total_len,
                file_size: buf.len(),
            });
        }
        let delta = i64::try_from(self.target_offset).unwrap_or(i64::MAX)
            - (i64::try_from(self.source_offset).unwrap_or(i64::MAX) + 5);
        if delta > i64::from(i32::MAX) || delta < i64::from(i32::MIN) {
            return Err(PatchError::JumpTooFar {
                src_addr: self.source_offset,
                target: self.target_offset,
                delta,
            });
        }
        let orig = buf[self.source_offset..end].to_vec();
        buf[self.source_offset] = 0xE9;
        let disp = i32::try_from(delta).unwrap_or(i32::MAX);
        buf[self.source_offset + 1..self.source_offset + 5].copy_from_slice(&disp.to_le_bytes());
        // NOP pad remainder.
        for i in 5..self.total_len {
            buf[self.source_offset + i] = 0x90;
        }
        Ok(orig)
    }

    /// Compute the displacement without applying.
    #[must_use]
    pub fn displacement(&self) -> i64 {
        i64::try_from(self.target_offset).unwrap_or(i64::MAX)
            - (i64::try_from(self.source_offset).unwrap_or(i64::MAX) + 5)
    }
}

// ---------------------------------------------------------------------------
// BytePatch
// ---------------------------------------------------------------------------

/// Overwrite bytes at `offset` with an arbitrary payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BytePatch {
    pub offset: usize,
    pub payload: Vec<u8>,
}

impl BytePatch {
    #[must_use]
    pub const fn new(offset: usize, payload: Vec<u8>) -> Self {
        Self { offset, payload }
    }

    /// Length of the payload.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.payload.len()
    }

    /// Returns `true` if the payload is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }

    /// Apply to `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`PatchError`] if the payload is empty or exceeds buffer bounds.
    pub fn apply(&self, buf: &mut [u8]) -> PatchResult<Vec<u8>> {
        if self.payload.is_empty() {
            return Err(PatchError::EmptyPayload);
        }
        let end = self.offset + self.payload.len();
        if end > buf.len() {
            return Err(PatchError::OutOfBounds {
                offset: self.offset,
                len: self.payload.len(),
                file_size: buf.len(),
            });
        }
        let orig = buf[self.offset..end].to_vec();
        buf[self.offset..end].copy_from_slice(&self.payload);
        Ok(orig)
    }
}

// ---------------------------------------------------------------------------
// PatchEntry
// ---------------------------------------------------------------------------

/// A tagged union of all patch kinds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatchKind {
    Nop(NopPatch),
    Jmp(JmpPatch),
    Bytes(BytePatch),
}

impl PatchKind {
    #[must_use]
    pub const fn offset(&self) -> usize {
        match self {
            Self::Nop(p) => p.offset,
            Self::Jmp(p) => p.source_offset,
            Self::Bytes(p) => p.offset,
        }
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        match self {
            Self::Nop(p) => p.len,
            Self::Jmp(p) => p.total_len,
            Self::Bytes(p) => p.payload.len(),
        }
    }

    /// Returns `true` if this patch occupies zero bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub const fn end(&self) -> usize {
        self.offset() + self.len()
    }
}

/// A named patch entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchEntry {
    pub name: String,
    pub kind: PatchKind,
    pub description: Option<String>,
    pub enabled: bool,
    /// Original bytes saved before the patch was applied.
    pub original_bytes: Option<Vec<u8>>,
}

impl PatchEntry {
    pub fn nop(name: impl Into<String>, offset: usize, len: usize) -> Self {
        Self {
            name: name.into(),
            kind: PatchKind::Nop(NopPatch::new(offset, len)),
            description: None,
            enabled: true,
            original_bytes: None,
        }
    }

    pub fn jmp(name: impl Into<String>, source: usize, target: usize) -> Self {
        Self {
            name: name.into(),
            kind: PatchKind::Jmp(JmpPatch::new(source, target)),
            description: None,
            enabled: true,
            original_bytes: None,
        }
    }

    pub fn bytes(name: impl Into<String>, offset: usize, payload: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            kind: PatchKind::Bytes(BytePatch::new(offset, payload)),
            description: None,
            enabled: true,
            original_bytes: None,
        }
    }

    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    #[must_use]
    pub const fn offset(&self) -> usize {
        self.kind.offset()
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.kind.len()
    }

    /// Returns `true` if this patch occupies zero bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.kind.is_empty()
    }

    /// Apply to `buf`, saving original bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PatchError`] if the underlying patch fails.
    pub fn apply(&mut self, buf: &mut [u8]) -> PatchResult<()> {
        if !self.enabled {
            return Ok(());
        }
        let orig = match &self.kind {
            PatchKind::Nop(p) => p.apply(buf)?,
            PatchKind::Jmp(p) => p.apply(buf)?,
            PatchKind::Bytes(p) => p.apply(buf)?,
        };
        self.original_bytes = Some(orig);
        Ok(())
    }

    /// Revert the patch (restore original bytes).
    ///
    /// # Errors
    ///
    /// Returns [`PatchError`] if no original bytes were saved or bounds exceeded.
    pub fn revert(&self, buf: &mut [u8]) -> PatchResult<()> {
        let orig = self
            .original_bytes
            .as_ref()
            .ok_or_else(|| PatchError::NotFound(self.name.clone()))?;
        let offset = self.kind.offset();
        let end = offset + orig.len();
        if end > buf.len() {
            return Err(PatchError::OutOfBounds {
                offset,
                len: orig.len(),
                file_size: buf.len(),
            });
        }
        buf[offset..end].copy_from_slice(orig);
        Ok(())
    }
}

impl fmt::Display for PatchEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] off={:#x} len={}",
            self.name,
            self.kind.offset(),
            self.kind.len()
        )?;
        if let Some(d) = &self.description {
            write!(f, " // {d}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PatchList
// ---------------------------------------------------------------------------

/// Ordered, named collection of patches.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatchList {
    patches: Vec<PatchEntry>,
}

impl PatchList {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a patch. Returns an error if it would overlap an existing patch.
    ///
    /// # Errors
    ///
    /// Returns [`PatchError::Overlap`] when the new patch overlaps an existing entry.
    pub fn add(&mut self, entry: PatchEntry) -> PatchResult<()> {
        for existing in &self.patches {
            let new_start = entry.kind.offset();
            let new_end = new_start + entry.kind.len();
            let ex_start = existing.kind.offset();
            let ex_end = ex_start + existing.kind.len();
            if new_start < ex_end && new_end > ex_start {
                return Err(PatchError::Overlap(entry.name, existing.name.clone()));
            }
        }
        self.patches.push(entry);
        Ok(())
    }

    /// Remove a patch by name.
    ///
    /// # Errors
    ///
    /// Returns [`PatchError::NotFound`] if no patch with `name` exists.
    pub fn remove(&mut self, name: &str) -> PatchResult<PatchEntry> {
        let pos = self
            .patches
            .iter()
            .position(|p| p.name == name)
            .ok_or_else(|| PatchError::NotFound(name.into()))?;
        Ok(self.patches.remove(pos))
    }

    /// Find a patch by name.
    ///
    /// # Errors
    ///
    /// Returns [`PatchError::NotFound`] if no patch with `name` exists.
    pub fn get(&self, name: &str) -> PatchResult<&PatchEntry> {
        self.patches
            .iter()
            .find(|p| p.name == name)
            .ok_or_else(|| PatchError::NotFound(name.into()))
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.patches.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &PatchEntry> {
        self.patches.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut PatchEntry> {
        self.patches.iter_mut()
    }

    /// Sort patches by offset (ascending).
    pub fn sort_by_offset(&mut self) {
        self.patches.sort_by_key(|p| p.kind.offset());
    }
}

// ---------------------------------------------------------------------------
// PatchApplier
// ---------------------------------------------------------------------------

/// Statistics about a patch application run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApplyStats {
    pub applied: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
}

impl ApplyStats {
    /// True if no errors occurred.
    #[must_use]
    pub const fn success(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Stateless helper that applies a `PatchList` to a mutable byte buffer.
#[derive(Debug, Clone, Default)]
pub struct PatchApplier;

impl PatchApplier {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Apply all patches in `list` to `buf`. Skips disabled patches.
    /// Continues on error (records errors in `ApplyStats`).
    pub fn apply_all(&self, list: &mut PatchList, buf: &mut [u8]) -> ApplyStats {
        let mut stats = ApplyStats::default();
        for entry in list.iter_mut() {
            if !entry.enabled {
                stats.skipped += 1;
                continue;
            }
            match entry.apply(buf) {
                Ok(()) => stats.applied += 1,
                Err(e) => stats.errors.push(format!("{}: {e}", entry.name)),
            }
        }
        stats
    }

    /// Revert all patches that have saved originals.
    pub fn revert_all(&self, list: &PatchList, buf: &mut [u8]) -> ApplyStats {
        let mut stats = ApplyStats::default();
        for entry in list.iter() {
            if entry.original_bytes.is_none() {
                stats.skipped += 1;
                continue;
            }
            match entry.revert(buf) {
                Ok(()) => stats.applied += 1,
                Err(e) => stats.errors.push(format!("{}: {e}", entry.name)),
            }
        }
        stats
    }
}

// ---------------------------------------------------------------------------
// PePatcher — main facade
// ---------------------------------------------------------------------------

/// Main facade: owns a PE buffer and a `PatchList`.
#[derive(Debug, Serialize, Deserialize)]
pub struct PePatcher {
    pub buffer: Vec<u8>,
    pub patches: PatchList,
    /// Map of patch name → applied offset (for bookkeeping).
    applied_map: HashMap<String, usize>,
}

impl PePatcher {
    /// Create from a PE file buffer.
    #[must_use]
    pub fn new(buffer: Vec<u8>) -> Self {
        Self {
            buffer,
            patches: PatchList::new(),
            applied_map: HashMap::new(),
        }
    }

    /// Add a NOP patch.
    ///
    /// # Errors
    ///
    /// Returns [`PatchError::Overlap`] if the patch overlaps an existing one.
    pub fn nop(&mut self, name: impl Into<String>, offset: usize, len: usize) -> PatchResult<()> {
        self.patches.add(PatchEntry::nop(name, offset, len))
    }

    /// Add a jump patch.
    ///
    /// # Errors
    ///
    /// Returns [`PatchError::Overlap`] if the patch overlaps an existing one.
    pub fn jmp(
        &mut self,
        name: impl Into<String>,
        source: usize,
        target: usize,
    ) -> PatchResult<()> {
        self.patches.add(PatchEntry::jmp(name, source, target))
    }

    /// Add a raw-bytes patch.
    ///
    /// # Errors
    ///
    /// Returns [`PatchError::Overlap`] if the patch overlaps an existing one.
    pub fn patch_bytes(
        &mut self,
        name: impl Into<String>,
        offset: usize,
        payload: Vec<u8>,
    ) -> PatchResult<()> {
        self.patches.add(PatchEntry::bytes(name, offset, payload))
    }

    /// Apply all pending patches.
    pub fn apply(&mut self) -> ApplyStats {
        let buf = &mut self.buffer;
        let applier = PatchApplier::new();
        let stats = applier.apply_all(&mut self.patches, buf);
        for entry in self.patches.iter() {
            if entry.original_bytes.is_some() {
                self.applied_map
                    .insert(entry.name.clone(), entry.kind.offset());
            }
        }
        stats
    }

    /// Revert all patches.
    pub fn revert(&mut self) -> ApplyStats {
        let buf = &mut self.buffer;
        let applier = PatchApplier::new();
        let stats = applier.revert_all(&self.patches, buf);
        self.applied_map.clear();
        stats
    }

    /// Get the patched buffer.
    #[must_use]
    pub fn patched_buffer(&self) -> &[u8] {
        &self.buffer
    }

    /// Number of patches registered.
    #[must_use]
    pub const fn patch_count(&self) -> usize {
        self.patches.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- NopPatch ---

    #[test]
    fn nop_patch_fills_with_90() {
        let mut buf = vec![0u8; 16];
        let p = NopPatch::new(4, 4);
        p.apply(&mut buf).unwrap();
        assert_eq!(&buf[4..8], &[0x90, 0x90, 0x90, 0x90]);
    }

    #[test]
    fn nop_patch_returns_original() {
        let mut buf = vec![0xAAu8; 8];
        let p = NopPatch::new(0, 4);
        let orig = p.apply(&mut buf).unwrap();
        assert_eq!(orig, vec![0xAA; 4]);
    }

    #[test]
    fn nop_patch_out_of_bounds() {
        let mut buf = vec![0u8; 4];
        let p = NopPatch::new(2, 4);
        assert!(matches!(
            p.apply(&mut buf),
            Err(PatchError::OutOfBounds { .. })
        ));
    }

    #[test]
    fn nop_patch_byte_count() {
        assert_eq!(NopPatch::new(0, 8).byte_count(), 8);
    }

    // --- JmpPatch ---

    #[test]
    fn jmp_patch_writes_e9() {
        let mut buf = vec![0u8; 16];
        let p = JmpPatch::new(0, 10);
        p.apply(&mut buf).unwrap();
        assert_eq!(buf[0], 0xE9);
    }

    #[test]
    fn jmp_patch_displacement_forward() {
        let p = JmpPatch::new(0, 10);
        // delta = 10 - (0 + 5) = 5
        assert_eq!(p.displacement(), 5);
    }

    #[test]
    fn jmp_patch_displacement_backward() {
        let p = JmpPatch::new(10, 0);
        // delta = 0 - (10 + 5) = -15
        assert_eq!(p.displacement(), -15);
    }

    #[test]
    fn jmp_patch_too_far() {
        let mut buf = vec![0u8; 16];
        let p = JmpPatch {
            source_offset: 0,
            target_offset: usize::MAX / 2,
            total_len: 5,
        };
        assert!(matches!(
            p.apply(&mut buf),
            Err(PatchError::JumpTooFar { .. })
        ));
    }

    #[test]
    fn jmp_patch_with_padding() {
        let mut buf = vec![0u8; 16];
        let p = JmpPatch::new(0, 10).with_padding(8);
        p.apply(&mut buf).unwrap();
        assert_eq!(buf[5], 0x90);
        assert_eq!(buf[6], 0x90);
        assert_eq!(buf[7], 0x90);
    }

    #[test]
    fn jmp_patch_out_of_bounds() {
        let mut buf = vec![0u8; 3];
        let p = JmpPatch::new(0, 10);
        assert!(p.apply(&mut buf).is_err());
    }

    // --- BytePatch ---

    #[test]
    fn byte_patch_applies_payload() {
        let mut buf = vec![0u8; 8];
        let p = BytePatch::new(2, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        p.apply(&mut buf).unwrap();
        assert_eq!(&buf[2..6], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn byte_patch_empty_payload_error() {
        let mut buf = vec![0u8; 8];
        let p = BytePatch::new(0, vec![]);
        assert!(matches!(p.apply(&mut buf), Err(PatchError::EmptyPayload)));
    }

    #[test]
    fn byte_patch_out_of_bounds() {
        let mut buf = vec![0u8; 4];
        let p = BytePatch::new(2, vec![1, 2, 3, 4]);
        assert!(p.apply(&mut buf).is_err());
    }

    #[test]
    fn byte_patch_returns_original() {
        let mut buf = vec![0xFFu8; 4];
        let p = BytePatch::new(0, vec![0x00; 4]);
        let orig = p.apply(&mut buf).unwrap();
        assert_eq!(orig, vec![0xFF; 4]);
    }

    // --- PatchEntry ---

    #[test]
    fn patch_entry_nop_display() {
        let e = PatchEntry::nop("test_nop", 0x1000, 4);
        let s = format!("{e}");
        assert!(s.contains("test_nop"));
    }

    #[test]
    fn patch_entry_revert_restores() {
        let mut buf = vec![0xAAu8; 8];
        let mut e = PatchEntry::nop("x", 0, 4);
        e.apply(&mut buf).unwrap();
        assert_eq!(&buf[0..4], &[0x90; 4]);
        e.revert(&mut buf).unwrap();
        assert_eq!(&buf[0..4], &[0xAA; 4]);
    }

    #[test]
    fn patch_entry_disabled_skipped() {
        let mut buf = vec![0xAAu8; 8];
        let mut e = PatchEntry::nop("x", 0, 4);
        e.enabled = false;
        e.apply(&mut buf).unwrap();
        assert_eq!(buf[0], 0xAA); // unchanged
    }

    // --- PatchList ---

    #[test]
    fn patch_list_add_and_get() {
        let mut list = PatchList::new();
        list.add(PatchEntry::nop("a", 0, 4)).unwrap();
        assert!(list.get("a").is_ok());
    }

    #[test]
    fn patch_list_overlap_error() {
        let mut list = PatchList::new();
        list.add(PatchEntry::nop("a", 0, 8)).unwrap();
        let r = list.add(PatchEntry::nop("b", 4, 4));
        assert!(matches!(r, Err(PatchError::Overlap(_, _))));
    }

    #[test]
    fn patch_list_remove() {
        let mut list = PatchList::new();
        list.add(PatchEntry::nop("a", 0, 4)).unwrap();
        list.remove("a").unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn patch_list_remove_not_found() {
        let mut list = PatchList::new();
        assert!(matches!(list.remove("x"), Err(PatchError::NotFound(_))));
    }

    #[test]
    fn patch_list_sort_by_offset() {
        let mut list = PatchList::new();
        list.add(PatchEntry::nop("b", 8, 4)).unwrap();
        list.add(PatchEntry::nop("a", 0, 4)).unwrap();
        list.sort_by_offset();
        let first = list.iter().next().unwrap();
        assert_eq!(first.name, "a");
    }

    // --- PatchApplier ---

    #[test]
    fn applier_applies_all() {
        let mut buf = vec![0u8; 16];
        let mut list = PatchList::new();
        list.add(PatchEntry::nop("n1", 0, 4)).unwrap();
        list.add(PatchEntry::nop("n2", 8, 4)).unwrap();
        let applier = PatchApplier::new();
        let stats = applier.apply_all(&mut list, &mut buf);
        assert_eq!(stats.applied, 2);
        assert!(stats.success());
    }

    #[test]
    fn applier_records_errors() {
        let mut buf = vec![0u8; 4];
        let mut list = PatchList::new();
        list.add(PatchEntry::nop("bad", 2, 8)).unwrap(); // out of bounds
        let applier = PatchApplier::new();
        let stats = applier.apply_all(&mut list, &mut buf);
        assert!(!stats.success());
        assert_eq!(stats.errors.len(), 1);
    }

    #[test]
    fn applier_revert_all() {
        let mut buf = vec![0xAAu8; 16];
        let mut list = PatchList::new();
        list.add(PatchEntry::nop("n", 0, 8)).unwrap();
        let applier = PatchApplier::new();
        applier.apply_all(&mut list, &mut buf);
        applier.revert_all(&list, &mut buf);
        assert_eq!(buf[0], 0xAA);
    }

    // --- PePatcher ---

    #[test]
    fn pe_patcher_nop() {
        let buf = vec![0xCCu8; 32];
        let mut p = PePatcher::new(buf);
        p.nop("fill", 0, 16).unwrap();
        let stats = p.apply();
        assert_eq!(stats.applied, 1);
        assert_eq!(p.patched_buffer()[0], 0x90);
    }

    #[test]
    fn pe_patcher_jmp() {
        let buf = vec![0u8; 64];
        let mut p = PePatcher::new(buf);
        p.jmp("skip", 0, 32).unwrap();
        let stats = p.apply();
        assert!(stats.success());
        assert_eq!(p.patched_buffer()[0], 0xE9);
    }

    #[test]
    fn pe_patcher_bytes() {
        let buf = vec![0u8; 16];
        let mut p = PePatcher::new(buf);
        p.patch_bytes("hdr", 0, vec![0x4D, 0x5A]).unwrap();
        p.apply();
        assert_eq!(p.patched_buffer()[0], 0x4D);
        assert_eq!(p.patched_buffer()[1], 0x5A);
    }

    #[test]
    fn pe_patcher_patch_count() {
        let mut p = PePatcher::new(vec![0u8; 64]);
        p.nop("a", 0, 4).unwrap();
        p.nop("b", 8, 4).unwrap();
        assert_eq!(p.patch_count(), 2);
    }

    #[test]
    fn pe_patcher_revert() {
        let orig_buf = vec![0xAAu8; 32];
        let mut p = PePatcher::new(orig_buf);
        p.nop("x", 0, 8).unwrap();
        p.apply();
        p.revert();
        assert_eq!(p.patched_buffer()[0], 0xAA);
    }

    #[test]
    fn apply_stats_success() {
        let s = ApplyStats {
            applied: 5,
            skipped: 1,
            errors: vec![],
        };
        assert!(s.success());
    }

    #[test]
    fn apply_stats_failure() {
        let s = ApplyStats {
            applied: 0,
            skipped: 0,
            errors: vec!["err".into()],
        };
        assert!(!s.success());
    }

    #[test]
    fn patch_kind_end() {
        let k = PatchKind::Nop(NopPatch::new(10, 6));
        assert_eq!(k.end(), 16);
    }

    #[test]
    fn jmp_patch_exact_boundary() {
        let mut buf = vec![0u8; 5];
        // source=0, target=5 → delta = 5-(0+5)=0
        let p = JmpPatch::new(0, 5);
        p.apply(&mut buf).unwrap();
        assert_eq!(buf[0], 0xE9);
        // displacement 0 → bytes 00 00 00 00
        assert_eq!(&buf[1..5], &[0, 0, 0, 0]);
    }

    #[test]
    fn nop_patch_full_buffer() {
        let mut buf = vec![0xCCu8; 64];
        let p = NopPatch::new(0, 64);
        p.apply(&mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0x90));
    }

    #[test]
    fn byte_patch_multiple_locations() {
        let mut buf = vec![0u8; 16];
        let p1 = BytePatch::new(0, vec![0xDE, 0xAD]);
        let p2 = BytePatch::new(8, vec![0xBE, 0xEF]);
        p1.apply(&mut buf).unwrap();
        p2.apply(&mut buf).unwrap();
        assert_eq!(&buf[0..2], &[0xDE, 0xAD]);
        assert_eq!(&buf[8..10], &[0xBE, 0xEF]);
    }

    #[test]
    fn patch_entry_with_description() {
        let e = PatchEntry::nop("x", 0, 4).with_description("nop sled");
        assert_eq!(e.description.as_deref(), Some("nop sled"));
    }

    #[test]
    fn patch_entry_jmp_display() {
        let e = PatchEntry::jmp("skip", 0x1000, 0x2000);
        let s = format!("{e}");
        assert!(s.contains("skip"));
    }

    #[test]
    fn patch_list_len() {
        let mut list = PatchList::new();
        list.add(PatchEntry::nop("a", 0, 4)).unwrap();
        list.add(PatchEntry::nop("b", 8, 4)).unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn patch_list_get_not_found() {
        let list = PatchList::new();
        assert!(matches!(list.get("x"), Err(PatchError::NotFound(_))));
    }

    #[test]
    fn applier_skip_disabled() {
        let mut buf = vec![0xAAu8; 8];
        let mut list = PatchList::new();
        let mut e = PatchEntry::nop("n", 0, 4);
        e.enabled = false;
        list.add(e).unwrap();
        let applier = PatchApplier::new();
        let stats = applier.apply_all(&mut list, &mut buf);
        assert_eq!(stats.skipped, 1);
        assert_eq!(stats.applied, 0);
        assert_eq!(buf[0], 0xAA); // unchanged
    }

    #[test]
    fn pe_patcher_overlap_prevents_add() {
        let mut p = PePatcher::new(vec![0u8; 64]);
        p.nop("a", 0, 8).unwrap();
        assert!(p.patch_bytes("b", 4, vec![0x01]).is_err());
    }

    #[test]
    fn jmp_patch_negative_displacement_encoded() {
        let mut buf = vec![0u8; 32];
        let p = JmpPatch::new(20, 0); // backward jump
        p.apply(&mut buf).unwrap();
        let disp = i32::from_le_bytes(buf[21..25].try_into().unwrap());
        assert_eq!(disp, -25); // 0 - (20 + 5) = -25
    }

    #[test]
    fn patch_kind_len_jmp() {
        let k = PatchKind::Jmp(JmpPatch::new(0, 10).with_padding(8));
        assert_eq!(k.len(), 8);
    }

    #[test]
    fn patch_kind_offset_bytes() {
        let k = PatchKind::Bytes(BytePatch::new(0x4000, vec![1, 2, 3]));
        assert_eq!(k.offset(), 0x4000);
    }
}
