//! `patch_validator` — Validate patches before application.
//!
//! Provides [`PatchValidator`], [`ValidationError`], and
//! the primary entry point [`validate_patch`].

use std::fmt;
use serde::{Deserialize, Serialize};

use crate::{Patch, PatchSet};

// ---------------------------------------------------------------------------
// ValidationError
// ---------------------------------------------------------------------------

/// A single validation failure for a patch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationError {
    /// The patch offset exceeds the target binary length.
    OffsetOutOfBounds {
        patch_id: String,
        offset: u64,
        binary_len: usize,
    },
    /// The patch would extend beyond the end of the binary.
    ExtendsBeyondEnd {
        patch_id: String,
        offset: u64,
        patch_len: usize,
        binary_len: usize,
    },
    /// The original bytes at the offset do not match those in the patch.
    OriginalBytesMismatch {
        patch_id: String,
        offset: u64,
        expected: Vec<u8>,
        found: Vec<u8>,
    },
    /// The patch has no bytes to write.
    EmptyPatchBytes { patch_id: String },
    /// The patch has an empty id.
    EmptyPatchId,
    /// The original and patch byte lengths differ in a context where they must match.
    LengthMismatch {
        patch_id: String,
        original_len: usize,
        patch_len: usize,
    },
    /// The patch has already been marked as applied.
    AlreadyApplied { patch_id: String },
    /// A patch in the set conflicts with another patch (overlapping ranges).
    OverlappingRanges {
        patch_id_a: String,
        patch_id_b: String,
    },
    /// Custom validation error from a user-supplied validator.
    Custom { patch_id: String, message: String },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OffsetOutOfBounds { patch_id, offset, binary_len } => {
                write!(f, "[{patch_id}] offset {offset:#x} out of bounds (binary len={binary_len})")
            }
            Self::ExtendsBeyondEnd { patch_id, offset, patch_len, binary_len } => {
                write!(f, "[{patch_id}] patch {offset:#x}+{patch_len} extends beyond binary (len={binary_len})")
            }
            Self::OriginalBytesMismatch { patch_id, offset, expected, found } => {
                write!(
                    f,
                    "[{patch_id}] original bytes mismatch at {offset:#x}: expected {expected:?} found {found:?}"
                )
            }
            Self::EmptyPatchBytes { patch_id } => {
                write!(f, "[{patch_id}] patch_bytes is empty")
            }
            Self::EmptyPatchId => write!(f, "patch has empty id"),
            Self::LengthMismatch { patch_id, original_len, patch_len } => {
                write!(f, "[{patch_id}] length mismatch: original={original_len} patch={patch_len}")
            }
            Self::AlreadyApplied { patch_id } => {
                write!(f, "[{patch_id}] patch is already marked applied")
            }
            Self::OverlappingRanges { patch_id_a, patch_id_b } => {
                write!(f, "patches [{patch_id_a}] and [{patch_id_b}] have overlapping byte ranges")
            }
            Self::Custom { patch_id, message } => {
                write!(f, "[{patch_id}] {message}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ValidationReport
// ---------------------------------------------------------------------------

/// The complete report from validating a patch or patch set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    /// All errors found.
    pub errors: Vec<ValidationError>,
    /// Non-fatal warnings.
    pub warnings: Vec<String>,
    /// Total patches checked.
    pub patches_checked: usize,
    /// Patches that passed validation.
    pub patches_valid: usize,
}

impl ValidationReport {
    /// Create an empty report.
    #[must_use]
    pub const fn new(patches_checked: usize) -> Self {
        Self {
            errors: Vec::new(),
            warnings: Vec::new(),
            patches_checked,
            patches_valid: 0,
        }
    }

    /// Returns `true` if no errors were found.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// Number of errors found.
    #[must_use]
    pub const fn error_count(&self) -> usize {
        self.errors.len()
    }

    /// Add an error.
    pub fn add_error(&mut self, e: ValidationError) {
        self.errors.push(e);
    }

    /// Add a warning.
    pub fn add_warning(&mut self, w: String) {
        self.warnings.push(w);
    }
}

impl fmt::Display for ValidationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ValidationReport: checked={} valid={} errors={} warnings={}",
            self.patches_checked,
            self.patches_valid,
            self.errors.len(),
            self.warnings.len()
        )
    }
}

// ---------------------------------------------------------------------------
// ValidatorRule
// ---------------------------------------------------------------------------

/// A single validation rule applied by the validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValidatorRule {
    /// Check that patch offset is within the binary.
    BoundsCheck,
    /// Check that original bytes match the binary at offset.
    OriginalBytesCheck,
    /// Reject empty patch byte arrays.
    NonEmptyPatchBytes,
    /// Reject patches already marked as applied.
    NotAlreadyApplied,
    /// Check for overlapping patch ranges within a set.
    NoOverlappingRanges,
    /// Require same-size patches (original len == patch len).
    SameSizeRequirement,
}

impl ValidatorRule {
    /// Human-readable description.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::BoundsCheck => "offset within binary",
            Self::OriginalBytesCheck => "original bytes match",
            Self::NonEmptyPatchBytes => "patch bytes non-empty",
            Self::NotAlreadyApplied => "not already applied",
            Self::NoOverlappingRanges => "no overlapping ranges",
            Self::SameSizeRequirement => "same-size patch",
        }
    }
}

impl fmt::Display for ValidatorRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

// ---------------------------------------------------------------------------
// PatchValidator
// ---------------------------------------------------------------------------

/// Validates patches against a binary target.
#[derive(Debug, Clone)]
pub struct PatchValidator {
    /// Validation rules to apply.
    rules: Vec<ValidatorRule>,
    /// If true, stop at the first error instead of collecting all.
    fail_fast: bool,
    /// If true, require `original_bytes` length == `patch_bytes` length.
    require_same_size: bool,
}

impl PatchValidator {
    /// Create a validator with all default rules enabled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: vec![
                ValidatorRule::BoundsCheck,
                ValidatorRule::OriginalBytesCheck,
                ValidatorRule::NonEmptyPatchBytes,
                ValidatorRule::NotAlreadyApplied,
                ValidatorRule::NoOverlappingRanges,
            ],
            fail_fast: false,
            require_same_size: false,
        }
    }

    /// Create a validator with only bounds and byte-match checks.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            rules: vec![
                ValidatorRule::BoundsCheck,
                ValidatorRule::OriginalBytesCheck,
                ValidatorRule::NonEmptyPatchBytes,
                ValidatorRule::NotAlreadyApplied,
                ValidatorRule::NoOverlappingRanges,
                ValidatorRule::SameSizeRequirement,
            ],
            fail_fast: false,
            require_same_size: true,
        }
    }

    /// Set fail-fast mode: stop after the first error.
    #[must_use]
    pub const fn fail_fast(mut self, ff: bool) -> Self {
        self.fail_fast = ff;
        self
    }

    /// Require same-size patches.
    #[must_use]
    pub const fn require_same_size(mut self, req: bool) -> Self {
        self.require_same_size = req;
        self
    }

    /// Enable or disable a specific rule.
    #[must_use]
    pub fn set_rule(mut self, rule: ValidatorRule, enabled: bool) -> Self {
        if enabled {
            if !self.rules.contains(&rule) {
                self.rules.push(rule);
            }
        } else {
            self.rules.retain(|r| *r != rule);
        }
        self
    }

    /// Validate a single patch against a binary buffer.
    ///
    /// Returns a [`ValidationReport`] with all errors and warnings.
    #[must_use]
    pub fn validate_one(&self, patch: &Patch, binary: &[u8]) -> ValidationReport {
        let mut report = ValidationReport::new(1);
        self.check_patch(patch, binary, &mut report);
        if report.errors.is_empty() {
            report.patches_valid = 1;
        }
        report
    }

    /// Validate all patches in a [`PatchSet`] against a binary buffer.
    #[must_use]
    pub fn validate_set(&self, patch_set: &PatchSet, binary: &[u8]) -> ValidationReport {
        let mut report = ValidationReport::new(patch_set.len());
        // Per-patch checks
        for patch in &patch_set.patches {
            self.check_patch(patch, binary, &mut report);
            if self.fail_fast && !report.errors.is_empty() {
                return report;
            }
        }
        // Inter-patch checks
        if self.rules.contains(&ValidatorRule::NoOverlappingRanges) {
            self.check_overlaps(&patch_set.patches, &mut report);
        }
        report.patches_valid = patch_set.len().saturating_sub(report.error_count());
        report
    }

    fn check_patch(&self, patch: &Patch, binary: &[u8], report: &mut ValidationReport) {
        if patch.id.is_empty() {
            report.add_error(ValidationError::EmptyPatchId);
            if self.fail_fast { return; }
        }

        if self.rules.contains(&ValidatorRule::NonEmptyPatchBytes) && patch.patch_bytes.is_empty() {
            report.add_error(ValidationError::EmptyPatchBytes { patch_id: patch.id.clone() });
            if self.fail_fast { return; }
        }

        if self.rules.contains(&ValidatorRule::NotAlreadyApplied) && patch.applied {
            report.add_error(ValidationError::AlreadyApplied { patch_id: patch.id.clone() });
            if self.fail_fast { return; }
        }

        if self.require_same_size && !patch.is_same_size() {
            report.add_error(ValidationError::LengthMismatch {
                patch_id: patch.id.clone(),
                original_len: patch.original_bytes.len(),
                patch_len: patch.patch_bytes.len(),
            });
            if self.fail_fast { return; }
        }

        if self.rules.contains(&ValidatorRule::BoundsCheck) {
            match usize::try_from(patch.offset) {
                Err(_) => {
                    // u64 offset exceeds usize capacity — definitely out of bounds.
                    report.add_error(ValidationError::OffsetOutOfBounds {
                        patch_id: patch.id.clone(),
                        offset: patch.offset,
                        binary_len: binary.len(),
                    });
                    if self.fail_fast { return; }
                }
                Ok(offset) if offset >= binary.len() => {
                    // Any nonzero offset into an empty binary, or any offset past the
                    // end, is an out-of-bounds address — report it and skip the
                    // ExtendsBeyondEnd check which would be redundant.
                    report.add_error(ValidationError::OffsetOutOfBounds {
                        patch_id: patch.id.clone(),
                        offset: patch.offset,
                        binary_len: binary.len(),
                    });
                    if self.fail_fast { return; }
                }
                Ok(offset) => {
                    let end = offset.saturating_add(patch.patch_bytes.len());
                    if end > binary.len() {
                        report.add_error(ValidationError::ExtendsBeyondEnd {
                            patch_id: patch.id.clone(),
                            offset: patch.offset,
                            patch_len: patch.patch_bytes.len(),
                            binary_len: binary.len(),
                        });
                        if self.fail_fast { return; }
                    }
                }
            }
        }

        if self.rules.contains(&ValidatorRule::OriginalBytesCheck)
            && !patch.original_bytes.is_empty()
        {
            let offset = usize::try_from(patch.offset).unwrap_or(usize::MAX);
            let end = offset.saturating_add(patch.original_bytes.len());
            if end <= binary.len() {
                let found = &binary[offset..end];
                if found != patch.original_bytes.as_slice() {
                    report.add_error(ValidationError::OriginalBytesMismatch {
                        patch_id: patch.id.clone(),
                        offset: patch.offset,
                        expected: patch.original_bytes.clone(),
                        found: found.to_vec(),
                    });
                    if self.fail_fast {}
                }
            }
        }
    }

    fn check_overlaps(&self, patches: &[Patch], report: &mut ValidationReport) {
        for i in 0..patches.len() {
            let a = &patches[i];
            let a_start = usize::try_from(a.offset).unwrap_or(usize::MAX);
            let a_end = a_start.saturating_add(a.patch_bytes.len());
            for b in patches.iter().skip(i + 1) {
                let b_start = usize::try_from(b.offset).unwrap_or(usize::MAX);
                let b_end = b_start.saturating_add(b.patch_bytes.len());
                if a_start < b_end && b_start < a_end {
                    report.add_error(ValidationError::OverlappingRanges {
                        patch_id_a: a.id.clone(),
                        patch_id_b: b.id.clone(),
                    });
                    if self.fail_fast { return; }
                }
            }
        }
    }
}

impl Default for PatchValidator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// validate_patch — primary entry point
// ---------------------------------------------------------------------------

/// Validate a single [`Patch`] against a binary byte slice.
///
/// Returns a [`ValidationReport`].  This is the primary one-shot entry point.
#[must_use]
pub fn validate_patch(patch: &Patch, binary: &[u8]) -> ValidationReport {
    PatchValidator::new().validate_one(patch, binary)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn binary() -> Vec<u8> {
        (0u8..64).collect()
    }

    fn valid_patch() -> Patch {
        let orig = vec![0x00, 0x01, 0x02, 0x03];
        Patch::new("p1", "test patch", 0, orig, vec![0xAA, 0xBB, 0xCC, 0xDD])
    }

    #[test]
    fn test_validate_valid_patch() {
        let report = validate_patch(&valid_patch(), &binary());
        assert!(report.is_valid());
        assert_eq!(report.patches_valid, 1);
    }

    #[test]
    fn test_validate_empty_patch_bytes() {
        let p = Patch::new("p1", "bad", 0, vec![0x00], vec![]);
        let report = validate_patch(&p, &binary());
        assert!(!report.is_valid());
        assert!(matches!(report.errors[0], ValidationError::EmptyPatchBytes { .. }));
    }

    #[test]
    fn test_validate_offset_out_of_bounds() {
        let b = binary();
        let p = Patch::new("p1", "oob", b.len() as u64 + 10, vec![], vec![0xFF]);
        let validator = PatchValidator::new()
            .set_rule(ValidatorRule::NonEmptyPatchBytes, false)
            .set_rule(ValidatorRule::OriginalBytesCheck, false);
        let report = validator.validate_one(&p, &b);
        assert!(!report.is_valid());
        assert!(matches!(report.errors[0], ValidationError::OffsetOutOfBounds { .. }));
    }

    #[test]
    fn test_validate_extends_beyond_end() {
        let b = binary();
        let p = Patch::new("p1", "ext", 60, vec![0x3C, 0x3D, 0x3E, 0x3F, 0x00], vec![0xFF; 10]);
        let validator = PatchValidator::new()
            .set_rule(ValidatorRule::OriginalBytesCheck, false);
        let report = validator.validate_one(&p, &b);
        assert!(!report.is_valid());
        assert!(matches!(report.errors[0], ValidationError::ExtendsBeyondEnd { .. }));
    }

    #[test]
    fn test_validate_original_bytes_mismatch() {
        let b = binary();
        let p = Patch::new("p1", "mismatch", 0, vec![0xFF, 0xFF], vec![0xAA, 0xBB]);
        let report = validate_patch(&p, &b);
        assert!(!report.is_valid());
        assert!(matches!(report.errors[0], ValidationError::OriginalBytesMismatch { .. }));
    }

    #[test]
    fn test_validate_already_applied() {
        let mut p = valid_patch();
        p.applied = true;
        let report = validate_patch(&p, &binary());
        assert!(!report.is_valid());
        assert!(matches!(report.errors[0], ValidationError::AlreadyApplied { .. }));
    }

    #[test]
    fn test_validate_empty_id() {
        let p = Patch::new("", "no id", 0, vec![0x00], vec![0xFF]);
        let report = validate_patch(&p, &binary());
        assert!(!report.is_valid());
        assert!(matches!(report.errors[0], ValidationError::EmptyPatchId));
    }

    #[test]
    fn test_validate_set_no_overlap() {
        let mut set = PatchSet::new("s1", "test");
        set.add(valid_patch());
        set.add(Patch::new("p2", "patch 2", 10, vec![0x0A, 0x0B], vec![0xEE, 0xFF]));
        let validator = PatchValidator::new();
        let report = validator.validate_set(&set, &binary());
        assert!(report.is_valid());
    }

    #[test]
    fn test_validate_set_overlapping() {
        let mut set = PatchSet::new("s1", "test");
        set.add(Patch::new("p1", "a", 0, vec![0x00, 0x01], vec![0xAA, 0xBB]));
        set.add(Patch::new("p2", "b", 1, vec![0x01, 0x02], vec![0xCC, 0xDD]));
        let validator = PatchValidator::new().set_rule(ValidatorRule::OriginalBytesCheck, false);
        let report = validator.validate_set(&set, &binary());
        assert!(!report.is_valid());
        assert!(report.errors.iter().any(|e| matches!(e, ValidationError::OverlappingRanges { .. })));
    }

    #[test]
    fn test_validator_strict_length_mismatch() {
        let p = Patch::new("p1", "len mismatch", 0, vec![0x00, 0x01], vec![0xAA]);
        let validator = PatchValidator::strict()
            .set_rule(ValidatorRule::OriginalBytesCheck, false);
        let report = validator.validate_one(&p, &binary());
        assert!(!report.is_valid());
        assert!(matches!(report.errors[0], ValidationError::LengthMismatch { .. }));
    }

    #[test]
    fn test_validator_fail_fast() {
        let p = Patch::new("", "bad", 1000, vec![], vec![]);
        let validator = PatchValidator::new().fail_fast(true);
        let report = validator.validate_one(&p, &binary());
        // Should stop at first error (EmptyPatchId)
        assert_eq!(report.errors.len(), 1);
    }

    #[test]
    fn test_validation_report_display() {
        let report = validate_patch(&valid_patch(), &binary());
        let s = report.to_string();
        assert!(s.contains("ValidationReport"));
    }

    #[test]
    fn test_validation_error_display_mismatch() {
        let e = ValidationError::OriginalBytesMismatch {
            patch_id: "p1".to_string(),
            offset: 0,
            expected: vec![0xFF],
            found: vec![0x00],
        };
        let s = e.to_string();
        assert!(s.contains("mismatch"));
    }

    #[test]
    fn test_validator_rule_display() {
        let s = ValidatorRule::BoundsCheck.to_string();
        assert!(s.contains("within binary"));
    }
}
