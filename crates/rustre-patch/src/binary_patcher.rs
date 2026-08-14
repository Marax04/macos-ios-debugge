//! `binary_patcher` — Apply binary patches to byte buffers.
//!
//! Provides [`BinaryPatcher`], [`PatchOp`], [`PatchResult`], and
//! the primary entry point [`apply_patches`].

use std::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Patch, PatchSet};
use crate::patch_validator::{PatchValidator, ValidationReport};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by binary patching operations.
#[derive(Debug, Error)]
pub enum PatcherError {
    /// Validation failed before applying.
    #[error("validation failed: {0} errors")]
    ValidationFailed(usize),
    /// Patch could not be applied (e.g. offset out of bounds).
    #[error("patch '{0}' could not be applied: {1}")]
    ApplicationFailed(String, String),
    /// The patch set is empty.
    #[error("patch set is empty")]
    EmptyPatchSet,
    /// A write to the target buffer failed.
    #[error("write failed at offset {0:#x}: {1}")]
    WriteFailed(u64, String),
    /// The output buffer length does not match the input after a resize operation.
    #[error("buffer size mismatch after patch")]
    BufferSizeMismatch,
}

// ---------------------------------------------------------------------------
// PatchOp
// ---------------------------------------------------------------------------

/// The type of a single patch operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PatchOp {
    /// Overwrite bytes at a fixed offset.
    Overwrite,
    /// Insert bytes at an offset, expanding the buffer.
    Insert,
    /// Remove bytes at an offset, shrinking the buffer.
    Remove,
    /// No-op: skip without writing.
    Nop,
}

impl PatchOp {
    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Overwrite => "overwrite",
            Self::Insert => "insert",
            Self::Remove => "remove",
            Self::Nop => "nop",
        }
    }

    /// Returns `true` if this op modifies the buffer length.
    #[must_use]
    pub const fn changes_size(self) -> bool {
        matches!(self, Self::Insert | Self::Remove)
    }
}

impl fmt::Display for PatchOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// AppliedOp
// ---------------------------------------------------------------------------

/// Record of a single patch operation that was applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedOp {
    /// The patch id.
    pub patch_id: String,
    /// The operation kind.
    pub op: PatchOp,
    /// Byte offset where the operation was applied.
    pub offset: u64,
    /// Bytes that were written.
    pub bytes_written: Vec<u8>,
    /// Bytes that were overwritten (for rollback).
    pub bytes_original: Vec<u8>,
}

impl fmt::Display for AppliedOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AppliedOp[{}] {} @{:#x} ({} bytes)",
            self.patch_id,
            self.op,
            self.offset,
            self.bytes_written.len()
        )
    }
}

// ---------------------------------------------------------------------------
// PatchResult
// ---------------------------------------------------------------------------

/// The result of applying one or more patches to a binary buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchResult {
    /// The patched binary data.
    pub data: Vec<u8>,
    /// Total number of patches applied.
    pub patches_applied: usize,
    /// Total bytes modified.
    pub bytes_modified: usize,
    /// Ordered log of individual operations.
    pub ops: Vec<AppliedOp>,
    /// Validation report (if validation was run).
    pub validation: Option<ValidationReport>,
}

impl PatchResult {
    /// Returns `true` if all requested patches were applied.
    #[must_use]
    pub const fn is_complete(&self, expected: usize) -> bool {
        self.patches_applied == expected
    }

    /// Get a specific applied op by patch id.
    #[must_use]
    pub fn find_op(&self, patch_id: &str) -> Option<&AppliedOp> {
        self.ops.iter().find(|o| o.patch_id == patch_id)
    }
}

impl fmt::Display for PatchResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PatchResult: applied={} bytes_modified={} data_len={}",
            self.patches_applied, self.bytes_modified, self.data.len()
        )
    }
}

// ---------------------------------------------------------------------------
// PatchOptions
// ---------------------------------------------------------------------------

/// Whether to run validation before applying patches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidateBefore {
    /// Validate patch set before applying (default).
    Yes,
    /// Skip pre-apply validation.
    No,
}

/// Whether to stop at the first failed patch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailFast {
    /// Return an error immediately on the first failure.
    Yes,
    /// Accumulate failures and continue (default).
    No,
}

/// Whether to mark patches as applied after writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkApplied {
    /// Set the `applied` flag on each patch after writing.
    Yes,
    /// Leave patch refs immutable (default).
    No,
}

/// Whether to sort patches by offset before applying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortByOffset {
    /// Sort by offset to prevent ordering bugs (default).
    Yes,
    /// Apply in the order given.
    No,
}

/// Whether to allow patches that don't match original bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForceApply {
    /// Force patching even when original bytes differ (dangerous).
    Yes,
    /// Reject patches whose original bytes don't match (default).
    No,
}

/// Options controlling how patches are applied.
#[derive(Debug, Clone)]
pub struct PatchOptions {
    /// Run validation before applying (default: `ValidateBefore::Yes`).
    pub validate_before: ValidateBefore,
    /// Stop at the first failed patch (default: `FailFast::No`).
    pub fail_fast: FailFast,
    /// Mark patches as applied after writing (default: `MarkApplied::No`).
    pub mark_applied: MarkApplied,
    /// Whether to sort patches by offset before applying (default: `SortByOffset::Yes`).
    pub sort_by_offset: SortByOffset,
    /// Whether to allow patches that don't match original bytes (default: `ForceApply::No`).
    pub force: ForceApply,
}

impl Default for PatchOptions {
    fn default() -> Self {
        Self {
            validate_before: ValidateBefore::Yes,
            fail_fast: FailFast::No,
            mark_applied: MarkApplied::No,
            sort_by_offset: SortByOffset::Yes,
            force: ForceApply::No,
        }
    }
}

// ---------------------------------------------------------------------------
// BinaryPatcher
// ---------------------------------------------------------------------------

/// Applies collections of patches to binary data.
pub struct BinaryPatcher {
    options: PatchOptions,
    validator: PatchValidator,
}

impl BinaryPatcher {
    /// Create a new patcher with default options.
    #[must_use]
    pub fn new() -> Self {
        Self {
            options: PatchOptions::default(),
            validator: PatchValidator::new(),
        }
    }

    /// Create a patcher with the given options.
    #[must_use]
    pub fn with_options(options: PatchOptions) -> Self {
        Self { options, validator: PatchValidator::new() }
    }

    /// Set the validator to use before applying.
    #[must_use]
    pub fn with_validator(mut self, v: PatchValidator) -> Self {
        self.validator = v;
        self
    }

    /// Set the fail-fast option.
    #[must_use]
    pub const fn fail_fast(mut self, ff: bool) -> Self {
        self.options.fail_fast = if ff { FailFast::Yes } else { FailFast::No };
        self
    }

    /// Disable pre-application validation.
    #[must_use]
    pub const fn no_validate(mut self) -> Self {
        self.options.validate_before = ValidateBefore::No;
        self
    }

    /// Force patching even if original bytes don't match.
    #[must_use]
    pub const fn force(mut self, force: bool) -> Self {
        self.options.force = if force { ForceApply::Yes } else { ForceApply::No };
        self
    }

    /// Apply a single [`Patch`] to a binary buffer.
    ///
    /// Returns a new buffer with the patch applied.
    ///
    /// # Errors
    ///
    /// Returns [`PatcherError`] if validation fails or the patch cannot be applied.
    pub fn apply_one(&self, patch: &Patch, binary: &[u8]) -> Result<PatchResult, PatcherError> {
        let patches = vec![patch.clone()];
        self.apply_all(&patches, binary)
    }

    /// Apply a [`PatchSet`] to a binary buffer in order.
    ///
    /// # Errors
    ///
    /// Returns [`PatcherError`] if validation fails or a patch cannot be applied.
    pub fn apply_set(&self, patch_set: &PatchSet, binary: &[u8]) -> Result<PatchResult, PatcherError> {
        if patch_set.is_empty() {
            return Err(PatcherError::EmptyPatchSet);
        }
        let patches: Vec<Patch> = patch_set.patches.clone();
        self.apply_all(&patches, binary)
    }

    fn apply_all(&self, patches: &[Patch], binary: &[u8]) -> Result<PatchResult, PatcherError> {
        // Validate first
        let validation = if self.options.validate_before == ValidateBefore::Yes {
            let mut set = crate::PatchSet::new("tmp", "tmp");
            for p in patches {
                set.add(p.clone());
            }
            let report = self.validator.validate_set(&set, binary);
            if !report.is_valid() && self.options.force == ForceApply::No {
                return Err(PatcherError::ValidationFailed(report.error_count()));
            }
            Some(report)
        } else {
            None
        };

        let mut data = binary.to_vec();
        let mut ops: Vec<AppliedOp> = Vec::new();
        let mut patches_applied = 0usize;
        let mut bytes_modified = 0usize;

        // Sort by offset if requested
        let mut sorted: Vec<&Patch> = patches.iter().collect();
        if self.options.sort_by_offset == SortByOffset::Yes {
            sorted.sort_by_key(|p| p.offset);
        }

        for patch in sorted {
            if patch.applied && self.options.force == ForceApply::No {
                continue; // skip already-applied
            }
            let Ok(offset) = usize::try_from(patch.offset) else {
                if self.options.fail_fast == FailFast::Yes {
                    return Err(PatcherError::ApplicationFailed(
                        patch.id.clone(),
                        format!("offset {:#x} exceeds usize::MAX", patch.offset),
                    ));
                }
                continue;
            };
            let len = patch.patch_bytes.len();

            let Some(end) = offset.checked_add(len) else {
                if self.options.fail_fast == FailFast::Yes {
                    return Err(PatcherError::ApplicationFailed(
                        patch.id.clone(),
                        format!("offset {:#x} + {} overflows usize", patch.offset, len),
                    ));
                }
                continue;
            };
            if end > data.len() {
                if self.options.fail_fast == FailFast::Yes {
                    return Err(PatcherError::ApplicationFailed(
                        patch.id.clone(),
                        format!("offset {:#x} + {} exceeds buffer len {}", patch.offset, len, data.len()),
                    ));
                }
                continue;
            }

            let original = data[offset..end].to_vec();
            data[offset..end].copy_from_slice(&patch.patch_bytes);
            bytes_modified += len;
            patches_applied += 1;
            ops.push(AppliedOp {
                patch_id: patch.id.clone(),
                op: PatchOp::Overwrite,
                offset: patch.offset,
                bytes_written: patch.patch_bytes.clone(),
                bytes_original: original,
            });
        }

        Ok(PatchResult {
            data,
            patches_applied,
            bytes_modified,
            ops,
            validation,
        })
    }

    /// Apply patches that insert bytes at a given offset (expanding the buffer).
    ///
    /// Inserts are processed in *reverse offset order* to prevent index shifts.
    ///
    /// # Errors
    ///
    /// Returns [`PatcherError::ApplicationFailed`] if an offset is out of bounds.
    pub fn apply_inserts(
        &self,
        inserts: &[(u64, Vec<u8>)],
        binary: &[u8],
    ) -> Result<Vec<u8>, PatcherError> {
        let mut sorted: Vec<(u64, &Vec<u8>)> = inserts.iter().map(|(o, b)| (*o, b)).collect();
        sorted.sort_by_key(|(o, _)| *o);
        sorted.reverse(); // Process in reverse so earlier inserts don't shift later offsets

        let mut data = binary.to_vec();
        for (offset, bytes) in &sorted {
            let idx = usize::try_from(*offset).unwrap_or(usize::MAX);
            if idx > data.len() {
                return Err(PatcherError::ApplicationFailed(
                    "insert".to_string(),
                    format!("insert offset {:#x} out of bounds (len={})", offset, data.len()),
                ));
            }
            let tail = data.split_off(idx);
            data.extend_from_slice(bytes);
            data.extend(tail);
        }
        Ok(data)
    }

    /// Apply patches that remove byte ranges from the buffer (shrinking it).
    ///
    /// Removals are processed in *reverse offset order*.
    ///
    /// # Errors
    ///
    /// Returns [`PatcherError::ApplicationFailed`] if a range is out of bounds.
    pub fn apply_removals(
        &self,
        removals: &[(u64, usize)],
        binary: &[u8],
    ) -> Result<Vec<u8>, PatcherError> {
        let mut sorted: Vec<(u64, usize)> = removals.to_vec();
        sorted.sort_by_key(|(o, _)| *o);
        sorted.reverse();

        let mut data = binary.to_vec();
        for (offset, len) in &sorted {
            let start = usize::try_from(*offset).unwrap_or(usize::MAX);
            let end = start.saturating_add(*len);
            if end > data.len() {
                return Err(PatcherError::ApplicationFailed(
                    "remove".to_string(),
                    format!("remove range {:#x}..{:#x} out of bounds (len={})", offset, end, data.len()),
                ));
            }
            data.drain(start..end);
        }
        Ok(data)
    }

    /// Compute a checksum (FNV-1a) of the binary after all patches are applied,
    /// without actually storing the result.
    ///
    /// # Errors
    ///
    /// Returns [`PatcherError`] if application fails.
    pub fn checksum_after(&self, patches: &[Patch], binary: &[u8]) -> Result<u64, PatcherError> {
        let result = self.apply_all(patches, binary)?;
        Ok(fnv1a_64(&result.data))
    }
}

impl Default for BinaryPatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for BinaryPatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BinaryPatcher(validate={}, fail_fast={}, force={})",
            matches!(self.options.validate_before, ValidateBefore::Yes),
            matches!(self.options.fail_fast, FailFast::Yes),
            matches!(self.options.force, ForceApply::Yes),
        )
    }
}

// ---------------------------------------------------------------------------
// apply_patches — primary entry point
// ---------------------------------------------------------------------------

/// Apply a slice of patches to a binary buffer.
///
/// Uses default options (validation enabled, sort by offset).
/// Returns a [`PatchResult`] containing the patched data.
///
/// # Errors
///
/// Returns [`PatcherError`] if validation fails or any patch cannot be applied.
pub fn apply_patches(patches: &[Patch], binary: &[u8]) -> Result<PatchResult, PatcherError> {
    if patches.is_empty() {
        return Err(PatcherError::EmptyPatchSet);
    }
    BinaryPatcher::new().apply_all(patches, binary)
}

// ---------------------------------------------------------------------------
// VA-aware patch writers (PE on disk, dry-run + backup)
// ---------------------------------------------------------------------------

/// Errors produced by VA-aware on-disk patching helpers.
#[derive(Debug, Error)]
pub enum VaPatchError {
    /// I/O failure reading or writing the target file.
    #[error("io error on {path}: {source}")]
    Io {
        /// Affected path.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Buffer too small / not a valid PE.
    #[error("not a PE binary or header truncated")]
    NotPe,
    /// VA could not be translated to a file offset.
    #[error("VA {0:#x} not in any section")]
    VaUnmapped(u64),
    /// Write range overruns the file.
    #[error("write range {start:#x}..{end:#x} exceeds file length {len}")]
    Overrun {
        /// Start offset (file).
        start: usize,
        /// End offset (file).
        end: usize,
        /// File length.
        len: usize,
    },
    /// Hex parsing failure.
    #[error("invalid hex byte string: {0}")]
    Hex(String),
    /// Assembler mnemonic not supported by the built-in encoder.
    #[error("unsupported asm mnemonic: {0}")]
    UnsupportedAsm(String),
}

/// Outcome of a VA-aware on-disk patch operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaPatchOutcome {
    /// Resolved file offset that was (or would be) written to.
    pub file_offset: u64,
    /// Number of bytes written.
    pub bytes_written: usize,
    /// Original bytes captured before the write (for rollback).
    pub original_bytes: Vec<u8>,
    /// Bytes that were (or would be) written.
    pub new_bytes: Vec<u8>,
    /// `true` if `dry_run` was set and the file was not modified.
    pub dry_run: bool,
    /// Backup file path written before the change (if any).
    pub backup_path: Option<String>,
    /// Resolved section name (if any) containing the VA.
    pub section: Option<String>,
}

/// Parse a hex byte string (`"90 90"`, `"9090"`, `"0x90,0x90"`) into raw bytes.
///
/// # Errors
///
/// Returns [`VaPatchError::Hex`] if any token is not a 1- or 2-digit hex byte.
pub fn parse_hex_bytes(input: &str) -> Result<Vec<u8>, VaPatchError> {
    // Strip spaces, commas, 0x prefixes
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ',' && *c != '_')
        .collect();
    let stripped = cleaned.replace("0x", "").replace("0X", "");
    if stripped.is_empty() {
        return Ok(Vec::new());
    }
    if !stripped.len().is_multiple_of(2) {
        return Err(VaPatchError::Hex(format!("odd hex length: {}", stripped.len())));
    }
    let mut out = Vec::with_capacity(stripped.len() / 2);
    for chunk in stripped.as_bytes().chunks(2) {
        let s = std::str::from_utf8(chunk).map_err(|e| VaPatchError::Hex(e.to_string()))?;
        let b = u8::from_str_radix(s, 16).map_err(|e| VaPatchError::Hex(e.to_string()))?;
        out.push(b);
    }
    Ok(out)
}

/// Result of a PE VA→file-offset lookup.
#[derive(Debug, Clone)]
pub struct PeSectionMap {
    /// Resolved file offset.
    pub file_offset: u64,
    /// Section name (if any).
    pub section: Option<String>,
    /// Image base from optional header.
    pub image_base: u64,
}

/// Translate a virtual address to a file offset using a PE on-disk buffer.
///
/// Walks DOS + PE + section headers manually — no third-party PE crate so this
/// stays consistent with [`crate::pe_security`].
///
/// # Errors
///
/// Returns [`VaPatchError::NotPe`] if the header is invalid or
/// [`VaPatchError::VaUnmapped`] if no section contains the VA.
pub fn pe_va_to_file_offset(data: &[u8], va: u64) -> Result<PeSectionMap, VaPatchError> {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return Err(VaPatchError::NotPe);
    }
    let e_lfanew =
        u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(VaPatchError::NotPe);
    }
    let coff = e_lfanew + 4;
    let num_sections =
        u16::from_le_bytes([data[coff + 2], data[coff + 3]]) as usize;
    let size_opt = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
    let opt = e_lfanew + 24;
    if opt + 2 > data.len() {
        return Err(VaPatchError::NotPe);
    }
    let opt_magic = u16::from_le_bytes([data[opt], data[opt + 1]]);
    let image_base = match opt_magic {
        0x10b => u64::from(u32::from_le_bytes([
            data[opt + 28], data[opt + 29], data[opt + 30], data[opt + 31],
        ])),
        0x20b => u64::from_le_bytes([
            data[opt + 24], data[opt + 25], data[opt + 26], data[opt + 27],
            data[opt + 28], data[opt + 29], data[opt + 30], data[opt + 31],
        ]),
        _ => return Err(VaPatchError::NotPe),
    };
    let sect_start = opt + size_opt;
    let rva = va.saturating_sub(image_base);
    let rva32 = u32::try_from(rva).map_err(|_| VaPatchError::VaUnmapped(va))?;
    for i in 0..num_sections {
        let off = sect_start + i * 40;
        if off + 40 > data.len() {
            break;
        }
        let name_bytes = &data[off..off + 8];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let section_name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();
        let virt_size = u32::from_le_bytes([data[off + 8], data[off + 9], data[off + 10], data[off + 11]]);
        let virt_addr = u32::from_le_bytes([data[off + 12], data[off + 13], data[off + 14], data[off + 15]]);
        let raw_size = u32::from_le_bytes([data[off + 16], data[off + 17], data[off + 18], data[off + 19]]);
        let raw_ptr = u32::from_le_bytes([data[off + 20], data[off + 21], data[off + 22], data[off + 23]]);
        let span = virt_size.max(raw_size);
        if rva32 >= virt_addr && rva32 < virt_addr.saturating_add(span) {
            let delta = rva32 - virt_addr;
            return Ok(PeSectionMap {
                file_offset: u64::from(raw_ptr) + u64::from(delta),
                section: Some(section_name),
                image_base,
            });
        }
    }
    Err(VaPatchError::VaUnmapped(va))
}

fn read_file(path: &str) -> Result<Vec<u8>, VaPatchError> {
    std::fs::read(path).map_err(|e| VaPatchError::Io {
        path: path.to_string(),
        source: e,
    })
}

fn write_file(path: &str, data: &[u8]) -> Result<(), VaPatchError> {
    std::fs::write(path, data).map_err(|e| VaPatchError::Io {
        path: path.to_string(),
        source: e,
    })
}

fn write_backup(path: &str, data: &[u8]) -> Result<String, VaPatchError> {
    let backup = format!("{path}.rustre.bak");
    write_file(&backup, data)?;
    Ok(backup)
}

fn commit_write(
    path: &str,
    original: &[u8],
    new_data: &[u8],
    file_offset: usize,
    new_bytes: &[u8],
    dry_run: bool,
    backup: bool,
    section: Option<String>,
) -> Result<VaPatchOutcome, VaPatchError> {
    let captured = original
        .get(file_offset..file_offset + new_bytes.len())
        .ok_or(VaPatchError::Overrun {
            start: file_offset,
            end: file_offset + new_bytes.len(),
            len: original.len(),
        })?
        .to_vec();
    let mut backup_path = None;
    if !dry_run {
        if backup {
            backup_path = Some(write_backup(path, original)?);
        }
        write_file(path, new_data)?;
    }
    Ok(VaPatchOutcome {
        file_offset: file_offset as u64,
        bytes_written: new_bytes.len(),
        original_bytes: captured,
        new_bytes: new_bytes.to_vec(),
        dry_run,
        backup_path,
        section,
    })
}

/// Write raw bytes at a VA in a PE file on disk.
///
/// # Errors
///
/// See [`VaPatchError`].
pub fn patch_bytes_at_va(
    path: &str,
    va: u64,
    bytes: &[u8],
    dry_run: bool,
    backup: bool,
) -> Result<VaPatchOutcome, VaPatchError> {
    let original = read_file(path)?;
    let map = pe_va_to_file_offset(&original, va)?;
    let file_offset = map.file_offset as usize;
    let end = file_offset.saturating_add(bytes.len());
    if end > original.len() {
        return Err(VaPatchError::Overrun {
            start: file_offset,
            end,
            len: original.len(),
        });
    }
    let mut new_data = original.clone();
    new_data[file_offset..end].copy_from_slice(bytes);
    commit_write(
        path,
        &original,
        &new_data,
        file_offset,
        bytes,
        dry_run,
        backup,
        map.section,
    )
}

/// Fill a VA range with `0x90` (NOP) bytes in a PE file on disk.
///
/// # Errors
///
/// See [`VaPatchError`].
pub fn patch_nop_range_at_va(
    path: &str,
    va: u64,
    length: usize,
    dry_run: bool,
    backup: bool,
) -> Result<VaPatchOutcome, VaPatchError> {
    let nops = vec![0x90u8; length];
    patch_bytes_at_va(path, va, &nops, dry_run, backup)
}

/// XOR-encode/decode `length` bytes at `va` with `key` in a PE file on disk.
///
/// The operation is symmetric: calling it twice with the same key restores
/// the original bytes.
///
/// # Errors
///
/// See [`VaPatchError`]. Returns [`VaPatchError::Hex`] if `key` is empty.
pub fn patch_xor_region_at_va(
    path: &str,
    va: u64,
    length: usize,
    key: &[u8],
    dry_run: bool,
    backup: bool,
) -> Result<VaPatchOutcome, VaPatchError> {
    if key.is_empty() {
        return Err(VaPatchError::Hex("xor key must be non-empty".into()));
    }
    let original = read_file(path)?;
    let map = pe_va_to_file_offset(&original, va)?;
    let file_offset = map.file_offset as usize;
    let end = file_offset.saturating_add(length);
    if end > original.len() {
        return Err(VaPatchError::Overrun {
            start: file_offset,
            end,
            len: original.len(),
        });
    }
    let mut new_data = original.clone();
    for (i, b) in new_data[file_offset..end].iter_mut().enumerate() {
        *b ^= key[i % key.len()];
    }
    let patched_slice = new_data[file_offset..end].to_vec();
    commit_write(
        path,
        &original,
        &new_data,
        file_offset,
        &patched_slice,
        dry_run,
        backup,
        map.section,
    )
}

/// Assemble a single x86/x64 instruction mnemonic to bytes and write at `va`.
///
/// Supports a focused set of common patching mnemonics: `nop`, `ret`,
/// `int3`, `ud2`, `hlt`, `cli`, `sti`, `nop <n>` (repeated nop), and
/// `bytes <hex>` for raw hex passthrough. This matches the most common
/// IDA `patch_asm` use cases (stub-out / no-op / breakpoint) without
/// dragging in a full assembler dependency.
///
/// # Errors
///
/// See [`VaPatchError`]; returns [`VaPatchError::UnsupportedAsm`] for
/// unrecognised mnemonics.
pub fn patch_asm_at_va(
    path: &str,
    va: u64,
    asm: &str,
    dry_run: bool,
    backup: bool,
) -> Result<VaPatchOutcome, VaPatchError> {
    let bytes = assemble_simple(asm)?;
    patch_bytes_at_va(path, va, &bytes, dry_run, backup)
}

/// Encode a small set of single-instruction mnemonics to bytes.
///
/// # Errors
///
/// Returns [`VaPatchError::UnsupportedAsm`] if the mnemonic is not in the
/// built-in table, or [`VaPatchError::Hex`] for malformed `bytes` payloads.
pub fn assemble_simple(asm: &str) -> Result<Vec<u8>, VaPatchError> {
    let lower = asm.trim().to_ascii_lowercase();
    // Normalise operand whitespace: collapse runs of whitespace and ensure a
    // single space follows each comma, so callers may write `xor eax,eax`,
    // `xor  eax , eax`, or `xor eax, eax` interchangeably.
    let mut normalised = String::with_capacity(lower.len());
    let mut prev_space = false;
    for ch in lower.chars() {
        if ch == ',' {
            // Drop any trailing space we just emitted, then emit ", ".
            if normalised.ends_with(' ') {
                normalised.pop();
            }
            normalised.push(',');
            normalised.push(' ');
            prev_space = true;
        } else if ch.is_whitespace() {
            if !prev_space && !normalised.is_empty() {
                normalised.push(' ');
                prev_space = true;
            }
        } else {
            normalised.push(ch);
            prev_space = false;
        }
    }
    let trimmed = normalised.trim().to_string();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if let Some(rest) = trimmed.strip_prefix("bytes ") {
        return parse_hex_bytes(rest);
    }
    if let Some(rest) = trimmed.strip_prefix("nop ") {
        let n: usize = rest
            .trim()
            .parse()
            .map_err(|_| VaPatchError::UnsupportedAsm(asm.to_string()))?;
        return Ok(vec![0x90u8; n]);
    }
    let bytes: Vec<u8> = match trimmed.as_str() {
        "nop" => vec![0x90],
        "ret" => vec![0xc3],
        "retn" => vec![0xc3],
        "ret far" | "retf" => vec![0xcb],
        "int3" => vec![0xcc],
        "ud2" => vec![0x0f, 0x0b],
        "hlt" => vec![0xf4],
        "cli" => vec![0xfa],
        "sti" => vec![0xfb],
        "leave" => vec![0xc9],
        "cdq" => vec![0x99],
        "syscall" => vec![0x0f, 0x05],
        "sysret" => vec![0x0f, 0x07],
        "pushfd" | "pushfq" => vec![0x9c],
        "popfd" | "popfq" => vec![0x9d],
        "xor eax, eax" => vec![0x31, 0xc0],
        "xor rax, rax" => vec![0x48, 0x31, 0xc0],
        "mov eax, 0" => vec![0xb8, 0, 0, 0, 0],
        "mov eax, 1" => vec![0xb8, 1, 0, 0, 0],
        _ => return Err(VaPatchError::UnsupportedAsm(asm.to_string())),
    };
    Ok(bytes)
}

#[cfg(test)]
mod va_patch_tests {
    use super::*;

    fn make_pe_with_text() -> (Vec<u8>, u64) {
        // Minimal PE32+ with one .text section: image_base=0x140000000, va=0x140001000 -> file_offset=0x200
        let mut buf = vec![0u8; 0x400];
        buf[0..2].copy_from_slice(b"MZ");
        let e_lfanew = 0x80u32;
        buf[0x3c..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        let pe = e_lfanew as usize;
        buf[pe..pe + 4].copy_from_slice(b"PE\0\0");
        // num_sections=1
        buf[pe + 6..pe + 8].copy_from_slice(&1u16.to_le_bytes());
        // size_of_optional_header=240
        buf[pe + 20..pe + 22].copy_from_slice(&240u16.to_le_bytes());
        let opt = pe + 24;
        buf[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        // ImageBase (PE32+) at opt+24, 8 bytes
        buf[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        let sect = opt + 240;
        buf[sect..sect + 5].copy_from_slice(b".text");
        buf[sect + 8..sect + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // virt_size
        buf[sect + 12..sect + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // virt_addr
        buf[sect + 16..sect + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw_size
        buf[sect + 20..sect + 24].copy_from_slice(&0x200u32.to_le_bytes()); // raw_ptr
        (buf, 0x1_4000_1000)
    }

    #[test]
    fn parse_hex_simple() {
        assert_eq!(parse_hex_bytes("90 90").unwrap(), vec![0x90, 0x90]);
        assert_eq!(parse_hex_bytes("0x90,0x90").unwrap(), vec![0x90, 0x90]);
        assert_eq!(parse_hex_bytes("9090").unwrap(), vec![0x90, 0x90]);
    }

    #[test]
    fn assemble_nop_ret() {
        assert_eq!(assemble_simple("nop").unwrap(), vec![0x90]);
        assert_eq!(assemble_simple("ret").unwrap(), vec![0xc3]);
        assert_eq!(assemble_simple("nop 4").unwrap(), vec![0x90; 4]);
        assert_eq!(assemble_simple("bytes 90 90").unwrap(), vec![0x90, 0x90]);
    }

    #[test]
    fn va_to_offset_resolves_text() {
        let (buf, va) = make_pe_with_text();
        let map = pe_va_to_file_offset(&buf, va).unwrap();
        assert_eq!(map.file_offset, 0x200);
        assert_eq!(map.section.as_deref(), Some(".text"));
    }

    #[test]
    fn nop_dry_run_does_not_write() {
        let (buf, va) = make_pe_with_text();
        let dir = std::env::temp_dir();
        let path = dir.join("rustre_patch_va_nop.bin");
        std::fs::write(&path, &buf).unwrap();
        let out = patch_nop_range_at_va(path.to_str().unwrap(), va, 4, true, false).unwrap();
        assert!(out.dry_run);
        let still = std::fs::read(&path).unwrap();
        assert_eq!(still, buf);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn xor_roundtrip_restores_bytes() {
        let (mut buf, va) = make_pe_with_text();
        // seed some payload bytes at va
        buf[0x200..0x208].copy_from_slice(b"ABCDEFGH");
        let dir = std::env::temp_dir();
        let path = dir.join("rustre_patch_va_xor.bin");
        std::fs::write(&path, &buf).unwrap();
        let key = [0x5au8, 0xa5];
        patch_xor_region_at_va(path.to_str().unwrap(), va, 8, &key, false, false).unwrap();
        patch_xor_region_at_va(path.to_str().unwrap(), va, 8, &key, false, false).unwrap();
        let restored = std::fs::read(&path).unwrap();
        assert_eq!(&restored[0x200..0x208], b"ABCDEFGH");
        let _ = std::fs::remove_file(&path);
    }
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

    fn make_binary(len: usize) -> Vec<u8> {
        (0u8..).take(len).collect()
    }

    fn good_patch(id: &str, offset: u64, old: &[u8], new: &[u8]) -> Patch {
        Patch::new(id, "test", offset, old.to_vec(), new.to_vec())
    }

    #[test]
    fn test_apply_patches_single() {
        let binary = make_binary(16);
        let patch = good_patch("p1", 0, &[0x00, 0x01, 0x02, 0x03], &[0xAA, 0xBB, 0xCC, 0xDD]);
        let result = apply_patches(&[patch], &binary).unwrap();
        assert_eq!(&result.data[0..4], &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(result.patches_applied, 1);
        assert_eq!(result.bytes_modified, 4);
    }

    #[test]
    fn test_apply_patches_empty_error() {
        let err = apply_patches(&[], &make_binary(16));
        assert!(matches!(err, Err(PatcherError::EmptyPatchSet)));
    }

    #[test]
    fn test_apply_patches_multiple() {
        let binary = make_binary(32);
        let p1 = good_patch("p1", 0, &[0x00, 0x01], &[0xAA, 0xBB]);
        let p2 = good_patch("p2", 10, &[0x0A, 0x0B], &[0xCC, 0xDD]);
        let result = apply_patches(&[p1, p2], &binary).unwrap();
        assert_eq!(result.patches_applied, 2);
        assert_eq!(&result.data[0..2], &[0xAA, 0xBB]);
        assert_eq!(&result.data[10..12], &[0xCC, 0xDD]);
    }

    #[test]
    fn test_apply_validation_failure() {
        let binary = make_binary(16);
        // Original bytes don't match
        let p = good_patch("p1", 0, &[0xFF, 0xFF], &[0xAA, 0xBB]);
        let err = apply_patches(&[p], &binary);
        assert!(matches!(err, Err(PatcherError::ValidationFailed(_))));
    }

    #[test]
    fn test_apply_force_bypasses_validation() {
        let binary = make_binary(16);
        let p = good_patch("p1", 0, &[0xFF, 0xFF], &[0xAA, 0xBB]);
        let patcher = BinaryPatcher::new().force(true);
        let result = patcher.apply_one(&p, &binary).unwrap();
        assert_eq!(&result.data[0..2], &[0xAA, 0xBB]);
    }

    #[test]
    fn test_apply_no_validate() {
        let binary = make_binary(16);
        let p = good_patch("p1", 0, &[0xFF], &[0xAA]);
        let patcher = BinaryPatcher::new().no_validate();
        let result = patcher.apply_one(&p, &binary).unwrap();
        assert_eq!(result.data[0], 0xAA);
    }

    #[test]
    fn test_apply_set() {
        let binary = make_binary(16);
        let mut set = PatchSet::new("s1", "test set");
        set.add(good_patch("p1", 0, &[0x00, 0x01], &[0xAA, 0xBB]));
        set.add(good_patch("p2", 4, &[0x04, 0x05], &[0xCC, 0xDD]));
        let patcher = BinaryPatcher::new();
        let result = patcher.apply_set(&set, &binary).unwrap();
        assert_eq!(result.patches_applied, 2);
    }

    #[test]
    fn test_apply_set_empty_error() {
        let binary = make_binary(16);
        let set = PatchSet::new("empty", "empty");
        let err = BinaryPatcher::new().apply_set(&set, &binary);
        assert!(matches!(err, Err(PatcherError::EmptyPatchSet)));
    }

    #[test]
    fn test_apply_inserts() {
        let binary = vec![0x00, 0x01, 0x02, 0x03];
        let inserts = vec![(2u64, vec![0xAA, 0xBB])];
        let patcher = BinaryPatcher::new();
        let result = patcher.apply_inserts(&inserts, &binary).unwrap();
        assert_eq!(result, vec![0x00, 0x01, 0xAA, 0xBB, 0x02, 0x03]);
    }

    #[test]
    fn test_apply_inserts_out_of_bounds() {
        let binary = vec![0x00, 0x01];
        let inserts = vec![(100u64, vec![0xAA])];
        let patcher = BinaryPatcher::new();
        let err = patcher.apply_inserts(&inserts, &binary);
        assert!(err.is_err());
    }

    #[test]
    fn test_apply_removals() {
        let binary = vec![0x00, 0x01, 0x02, 0x03, 0x04];
        let removals = vec![(1u64, 2)];
        let patcher = BinaryPatcher::new();
        let result = patcher.apply_removals(&removals, &binary).unwrap();
        assert_eq!(result, vec![0x00, 0x03, 0x04]);
    }

    #[test]
    fn test_apply_removals_out_of_bounds() {
        let binary = vec![0x00, 0x01];
        let removals = vec![(0u64, 100)];
        let patcher = BinaryPatcher::new();
        let err = patcher.apply_removals(&removals, &binary);
        assert!(err.is_err());
    }

    #[test]
    fn test_checksum_after() {
        let binary = make_binary(16);
        let p = good_patch("p1", 0, &[0x00, 0x01], &[0xAA, 0xBB]);
        let patcher = BinaryPatcher::new();
        let cs = patcher.checksum_after(&[p], &binary).unwrap();
        assert_ne!(cs, 0);
    }

    #[test]
    fn test_patch_result_find_op() {
        let binary = make_binary(16);
        let p = good_patch("p1", 0, &[0x00, 0x01], &[0xAA, 0xBB]);
        let result = apply_patches(&[p], &binary).unwrap();
        let op = result.find_op("p1").unwrap();
        assert_eq!(op.offset, 0);
        assert_eq!(op.bytes_written, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_applied_op_display() {
        let op = AppliedOp {
            patch_id: "p1".to_string(),
            op: PatchOp::Overwrite,
            offset: 0x100,
            bytes_written: vec![0xAA],
            bytes_original: vec![0x00],
        };
        let s = op.to_string();
        assert!(s.contains("p1"));
        assert!(s.contains("overwrite"));
    }

    #[test]
    fn test_patch_op_display() {
        assert_eq!(PatchOp::Overwrite.to_string(), "overwrite");
        assert_eq!(PatchOp::Insert.to_string(), "insert");
        assert_eq!(PatchOp::Remove.to_string(), "remove");
    }

    #[test]
    fn test_patch_op_changes_size() {
        assert!(PatchOp::Insert.changes_size());
        assert!(PatchOp::Remove.changes_size());
        assert!(!PatchOp::Overwrite.changes_size());
        assert!(!PatchOp::Nop.changes_size());
    }
}
