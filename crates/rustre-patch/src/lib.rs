//! `rustre-patch`
//!
//! Binary patching layer for `RustRE` — validate, apply, and roll back patches
//! to binary files and in-memory byte buffers.

pub mod patch_validator;
pub mod binary_patcher;
pub mod patch_rollback;
pub mod code_cave;
pub mod hot_patch;
pub mod binary_diff;
pub mod pe_security;

pub use patch_validator::{PatchValidator, ValidationError, validate_patch};
pub use binary_patcher::{
    BinaryPatcher, PatchOp, PatchOptions, PatchResult, apply_patches,
    ValidateBefore, FailFast, MarkApplied, SortByOffset, ForceApply,
    VaPatchError, VaPatchOutcome, PeSectionMap,
    parse_hex_bytes, pe_va_to_file_offset, assemble_simple,
    patch_bytes_at_va, patch_nop_range_at_va, patch_xor_region_at_va,
    patch_asm_at_va,
};
pub use patch_rollback::{PatchRollback, RollbackEntry, RollbackResult, create_rollback};
pub use code_cave::{
    BinaryFormat, CavePathError, CaveError, CodeCave, CodeCaveScanner, find_code_caves,
    find_code_caves_from_path,
};
pub use pe_security::{
    PeFlags, PeSecuritySummary, SecurityError, SecurityPathError, pe_security_summary,
    pe_security_summary_from_path,
    PeFlagToggle, PeSecuritySetOutcome, pe_security_set_from_path, compute_pe_checksum,
};
pub use hot_patch::{
    HotPatchError, HotPatcher, InMemoryWriter, LivePatch, RuntimeMemoryWriter,
};
pub use binary_diff::{
    BinaryDelta, DiffError, DiffOp, DiffOptions, build_delta, diff, patch,
};

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Core patch types shared across sub-modules
// ---------------------------------------------------------------------------

/// A single patch record targeting a specific byte range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Patch {
    /// Unique identifier for this patch.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Byte offset within the target binary.
    pub offset: u64,
    /// Original bytes expected at the offset (for validation).
    pub original_bytes: Vec<u8>,
    /// Replacement bytes to write.
    pub patch_bytes: Vec<u8>,
    /// Whether the patch is currently applied.
    pub applied: bool,
}

impl Patch {
    /// Create a new unapplied patch.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        offset: u64,
        original_bytes: Vec<u8>,
        patch_bytes: Vec<u8>,
    ) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            offset,
            original_bytes,
            patch_bytes,
            applied: false,
        }
    }

    /// Size of the patch in bytes.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.patch_bytes.len()
    }

    /// Returns `true` if the original and patch bytes have compatible lengths.
    #[must_use]
    pub const fn is_same_size(&self) -> bool {
        self.original_bytes.len() == self.patch_bytes.len()
    }
}

impl fmt::Display for Patch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Patch[{}] @{:#x} ({} bytes) [{}]",
            self.id,
            self.offset,
            self.size(),
            if self.applied { "applied" } else { "pending" }
        )
    }
}

/// A collection of patches that form a logical unit (e.g. a fix, a crack).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatchSet {
    /// Set identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Ordered list of patches in this set.
    pub patches: Vec<Patch>,
    /// Version of the binary this patch set targets.
    pub target_version: Option<String>,
}

impl PatchSet {
    /// Create a new empty patch set.
    #[must_use]
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            patches: Vec::new(),
            target_version: None,
        }
    }

    /// Add a patch to the set.
    pub fn add(&mut self, patch: Patch) {
        self.patches.push(patch);
    }

    /// Total number of patches.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.patches.len()
    }

    /// Returns `true` if the set contains no patches.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }

    /// Total bytes modified if all patches are applied.
    #[must_use]
    pub fn total_bytes_modified(&self) -> usize {
        self.patches.iter().map(Patch::size).sum()
    }
}

impl fmt::Display for PatchSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PatchSet[{}] '{}' ({} patches, {} bytes)",
            self.id, self.name, self.len(), self.total_bytes_modified()
        )
    }
}
