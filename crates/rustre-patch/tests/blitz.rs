//! Exhaustive blitz tests for `rustre-patch`.
//!
//! Targets every public API surface, with adversarial inputs, boundary
//! checks, and round-trips.

use rustre_patch::binary_diff::{
    build_delta, diff, patch, BinaryDelta, DiffError, DiffOp, DiffOptions,
};
use rustre_patch::binary_patcher::{
    apply_patches, AppliedOp, BinaryPatcher, FailFast, PatchOp, PatchOptions, PatcherError,
    ValidateBefore,
};
use rustre_patch::code_cave::{
    find_code_caves, BinaryFormat, CaveError, CodeCave, CodeCaveScanner,
};
use rustre_patch::hot_patch::{
    HotPatchError, HotPatcher, InMemoryWriter, LivePatch, RuntimeMemoryWriter,
};
use rustre_patch::patch_rollback::{
    create_rollback, PatchRollback, RollbackEntry, RollbackError, RollbackResult, RollbackSnapshot,
};
use rustre_patch::patch_validator::{
    validate_patch, PatchValidator, ValidationError, ValidationReport, ValidatorRule,
};
use rustre_patch::{Patch, PatchSet};

// ---------------------------------------------------------------------------
// Patch / PatchSet (lib.rs)
// ---------------------------------------------------------------------------

#[test]
fn patch_new_initializes_fields() {
    let p = Patch::new("id1", "desc", 0x10, vec![1, 2], vec![3, 4]);
    assert_eq!(p.id, "id1");
    assert_eq!(p.description, "desc");
    assert_eq!(p.offset, 0x10);
    assert_eq!(p.original_bytes, vec![1, 2]);
    assert_eq!(p.patch_bytes, vec![3, 4]);
    assert!(!p.applied);
}

#[test]
fn patch_size_matches_patch_bytes() {
    let p = Patch::new("i", "d", 0, vec![], vec![0; 17]);
    assert_eq!(p.size(), 17);
}

#[test]
fn patch_is_same_size_true_and_false() {
    let a = Patch::new("a", "", 0, vec![1, 2], vec![3, 4]);
    assert!(a.is_same_size());
    let b = Patch::new("b", "", 0, vec![1, 2, 3], vec![3, 4]);
    assert!(!b.is_same_size());
}

#[test]
fn patch_display_contains_id_offset_size_status() {
    let p = Patch::new("xyz", "d", 0x1234, vec![0], vec![1]);
    let s = p.to_string();
    assert!(s.contains("xyz"));
    assert!(s.contains("0x1234"));
    assert!(s.contains("1 bytes"));
    assert!(s.contains("pending"));
    let mut p2 = p;
    p2.applied = true;
    assert!(p2.to_string().contains("applied"));
}

#[test]
fn patch_eq_and_clone_roundtrip() {
    let p = Patch::new("a", "b", 1, vec![1], vec![2]);
    let q = p.clone();
    assert_eq!(p, q);
}

#[test]
fn patchset_new_is_empty() {
    let s = PatchSet::new("id", "name");
    assert_eq!(s.id, "id");
    assert_eq!(s.name, "name");
    assert!(s.is_empty());
    assert_eq!(s.len(), 0);
    assert_eq!(s.total_bytes_modified(), 0);
    assert!(s.target_version.is_none());
}

#[test]
fn patchset_add_and_total_bytes() {
    let mut s = PatchSet::new("s", "n");
    s.add(Patch::new("p1", "", 0, vec![], vec![0; 4]));
    s.add(Patch::new("p2", "", 4, vec![], vec![0; 6]));
    assert_eq!(s.len(), 2);
    assert!(!s.is_empty());
    assert_eq!(s.total_bytes_modified(), 10);
}

#[test]
fn patchset_default_is_empty() {
    let s = PatchSet::default();
    assert!(s.is_empty());
}

#[test]
fn patchset_display_format() {
    let mut s = PatchSet::new("sid", "sname");
    s.add(Patch::new("p", "", 0, vec![], vec![0; 3]));
    let out = s.to_string();
    assert!(out.contains("sid"));
    assert!(out.contains("sname"));
    assert!(out.contains("1 patches"));
    assert!(out.contains("3 bytes"));
}

// ---------------------------------------------------------------------------
// patch_validator
// ---------------------------------------------------------------------------

fn bin64() -> Vec<u8> {
    (0u8..64).collect()
}

#[test]
fn validator_default_accepts_valid_patch() {
    let p = Patch::new("p", "", 0, vec![0, 1, 2, 3], vec![9, 9, 9, 9]);
    let r = validate_patch(&p, &bin64());
    assert!(r.is_valid());
    assert_eq!(r.patches_valid, 1);
    assert_eq!(r.error_count(), 0);
}

#[test]
fn validator_offset_out_of_bounds_into_empty_binary() {
    let p = Patch::new("p", "", 100, vec![], vec![1]);
    let v = PatchValidator::new()
        .set_rule(ValidatorRule::OriginalBytesCheck, false);
    let r = v.validate_one(&p, &[]);
    assert!(!r.is_valid());
    assert!(matches!(r.errors[0], ValidationError::OffsetOutOfBounds { .. }));
}

#[test]
fn validator_extends_beyond_end_at_last_byte() {
    let bin = vec![0u8; 4];
    let p = Patch::new("p", "", 2, vec![], vec![1, 2, 3]);
    let v = PatchValidator::new()
        .set_rule(ValidatorRule::OriginalBytesCheck, false);
    let r = v.validate_one(&p, &bin);
    assert!(!r.is_valid());
    assert!(r.errors.iter().any(|e| matches!(e, ValidationError::ExtendsBeyondEnd { .. })));
}

#[test]
fn validator_original_bytes_mismatch_specific_variant() {
    let p = Patch::new("p", "", 0, vec![0xAA, 0xBB], vec![1, 2]);
    let r = validate_patch(&p, &bin64());
    match &r.errors[0] {
        ValidationError::OriginalBytesMismatch { patch_id, offset, expected, found } => {
            assert_eq!(patch_id, "p");
            assert_eq!(*offset, 0);
            assert_eq!(expected, &vec![0xAA, 0xBB]);
            assert_eq!(found, &vec![0u8, 1]);
        }
        e => panic!("wrong variant: {e:?}"),
    }
}

#[test]
fn validator_empty_patch_bytes_blocked() {
    let p = Patch::new("p", "", 0, vec![0], vec![]);
    let r = validate_patch(&p, &bin64());
    assert!(matches!(r.errors[0], ValidationError::EmptyPatchBytes { .. }));
}

#[test]
fn validator_empty_id_detected() {
    let p = Patch::new("", "", 0, vec![0], vec![9]);
    let r = validate_patch(&p, &bin64());
    assert!(r.errors.iter().any(|e| matches!(e, ValidationError::EmptyPatchId)));
}

#[test]
fn validator_already_applied_detected() {
    let mut p = Patch::new("p", "", 0, vec![0], vec![9]);
    p.applied = true;
    let r = validate_patch(&p, &bin64());
    assert!(r.errors.iter().any(|e| matches!(e, ValidationError::AlreadyApplied { .. })));
}

#[test]
fn validator_strict_length_mismatch_detected() {
    let p = Patch::new("p", "", 0, vec![0, 1, 2], vec![9, 9]);
    let v = PatchValidator::strict()
        .set_rule(ValidatorRule::OriginalBytesCheck, false);
    let r = v.validate_one(&p, &bin64());
    assert!(r.errors.iter().any(|e| matches!(e, ValidationError::LengthMismatch { .. })));
}

#[test]
fn validator_set_overlapping_ranges_detected() {
    let mut s = PatchSet::new("s", "");
    s.add(Patch::new("a", "", 0, vec![0, 1, 2], vec![9, 9, 9]));
    s.add(Patch::new("b", "", 2, vec![2, 3], vec![8, 8]));
    let v = PatchValidator::new().set_rule(ValidatorRule::OriginalBytesCheck, false);
    let r = v.validate_set(&s, &bin64());
    assert!(r.errors.iter().any(|e| matches!(e, ValidationError::OverlappingRanges { .. })));
}

#[test]
fn validator_set_adjacent_non_overlapping_ok() {
    let mut s = PatchSet::new("s", "");
    s.add(Patch::new("a", "", 0, vec![0, 1], vec![9, 9]));
    s.add(Patch::new("b", "", 2, vec![2, 3], vec![8, 8]));
    let v = PatchValidator::new();
    let r = v.validate_set(&s, &bin64());
    assert!(r.is_valid(), "errors: {:?}", r.errors);
}

#[test]
fn validator_fail_fast_stops_after_first_error() {
    let p = Patch::new("", "", 9999, vec![], vec![]); // empty id + empty bytes + oob
    let v = PatchValidator::new().fail_fast(true);
    let r = v.validate_one(&p, &bin64());
    assert_eq!(r.errors.len(), 1);
}

#[test]
fn validator_set_rule_toggle_off_and_back_on() {
    let mut v = PatchValidator::new();
    v = v.set_rule(ValidatorRule::BoundsCheck, false);
    let p = Patch::new("p", "", 9999, vec![], vec![9]);
    let r = v.clone().set_rule(ValidatorRule::OriginalBytesCheck, false)
        .validate_one(&p, &bin64());
    // BoundsCheck disabled -> no OffsetOutOfBounds error
    assert!(!r.errors.iter().any(|e| matches!(e, ValidationError::OffsetOutOfBounds { .. })));
    // Turn it back on -> error reappears
    let v2 = v.set_rule(ValidatorRule::BoundsCheck, true)
        .set_rule(ValidatorRule::OriginalBytesCheck, false);
    let r2 = v2.validate_one(&p, &bin64());
    assert!(r2.errors.iter().any(|e| matches!(e, ValidationError::OffsetOutOfBounds { .. })));
}

#[test]
fn validator_set_rule_does_not_duplicate() {
    let v = PatchValidator::new()
        .set_rule(ValidatorRule::BoundsCheck, true)
        .set_rule(ValidatorRule::BoundsCheck, true);
    // No way to inspect rules directly; just confirm it still validates sensibly
    let r = v.validate_one(&Patch::new("p", "", 0, vec![0], vec![9]), &bin64());
    assert!(r.is_valid());
}

#[test]
fn validator_default_strict_distinguish() {
    // strict() requires same size; new() does not.
    let p = Patch::new("p", "", 0, vec![0, 1, 2], vec![9, 9]);
    // new() should report OriginalBytesCheck OK (orig matches), but no length mismatch
    let r = PatchValidator::new().validate_one(&p, &bin64());
    assert!(!r.errors.iter().any(|e| matches!(e, ValidationError::LengthMismatch { .. })));
    // strict() should flag length mismatch
    let r2 = PatchValidator::strict().validate_one(&p, &bin64());
    assert!(r2.errors.iter().any(|e| matches!(e, ValidationError::LengthMismatch { .. })));
}

#[test]
fn validation_report_add_warning_and_error() {
    let mut r = ValidationReport::new(0);
    r.add_warning("hi".into());
    r.add_error(ValidationError::EmptyPatchId);
    assert_eq!(r.warnings.len(), 1);
    assert_eq!(r.error_count(), 1);
    assert!(!r.is_valid());
}

#[test]
fn validation_error_display_all_variants() {
    let variants = [
        ValidationError::OffsetOutOfBounds { patch_id: "a".into(), offset: 0, binary_len: 0 },
        ValidationError::ExtendsBeyondEnd { patch_id: "a".into(), offset: 0, patch_len: 1, binary_len: 0 },
        ValidationError::OriginalBytesMismatch { patch_id: "a".into(), offset: 0, expected: vec![1], found: vec![2] },
        ValidationError::EmptyPatchBytes { patch_id: "a".into() },
        ValidationError::EmptyPatchId,
        ValidationError::LengthMismatch { patch_id: "a".into(), original_len: 1, patch_len: 2 },
        ValidationError::AlreadyApplied { patch_id: "a".into() },
        ValidationError::OverlappingRanges { patch_id_a: "a".into(), patch_id_b: "b".into() },
        ValidationError::Custom { patch_id: "a".into(), message: "x".into() },
    ];
    for v in &variants {
        let s = v.to_string();
        assert!(!s.is_empty());
    }
}

#[test]
fn validator_rule_descriptions_exist() {
    for r in [
        ValidatorRule::BoundsCheck,
        ValidatorRule::OriginalBytesCheck,
        ValidatorRule::NonEmptyPatchBytes,
        ValidatorRule::NotAlreadyApplied,
        ValidatorRule::NoOverlappingRanges,
        ValidatorRule::SameSizeRequirement,
    ] {
        assert!(!r.description().is_empty());
        assert_eq!(r.to_string(), r.description());
    }
}

// ---------------------------------------------------------------------------
// binary_patcher
// ---------------------------------------------------------------------------

#[test]
fn binary_patcher_apply_one_overwrite() {
    let bin = bin64();
    let p = Patch::new("p", "", 0, vec![0, 1, 2, 3], vec![0xAA; 4]);
    let r = BinaryPatcher::new().apply_one(&p, &bin).unwrap();
    assert_eq!(&r.data[0..4], &[0xAA; 4]);
    assert_eq!(r.patches_applied, 1);
    assert_eq!(r.bytes_modified, 4);
    assert_eq!(r.ops.len(), 1);
    assert_eq!(r.ops[0].op, PatchOp::Overwrite);
    assert!(r.is_complete(1));
}

#[test]
fn binary_patcher_records_original_bytes_in_op() {
    let bin = bin64();
    let p = Patch::new("p", "", 4, vec![4, 5], vec![0xEE, 0xEE]);
    let r = BinaryPatcher::new().apply_one(&p, &bin).unwrap();
    let op = r.find_op("p").unwrap();
    assert_eq!(op.bytes_original, vec![4, 5]);
    assert_eq!(op.bytes_written, vec![0xEE, 0xEE]);
    assert_eq!(op.offset, 4);
}

#[test]
fn binary_patcher_sort_by_offset_default() {
    let bin = bin64();
    let mut set = PatchSet::new("s", "");
    set.add(Patch::new("hi", "", 20, vec![20, 21], vec![0xCC, 0xCC]));
    set.add(Patch::new("lo", "", 0, vec![0, 1], vec![0xAA, 0xAA]));
    let r = BinaryPatcher::new().apply_set(&set, &bin).unwrap();
    // After sort, lo (offset 0) should be applied first
    assert_eq!(r.ops[0].patch_id, "lo");
    assert_eq!(r.ops[1].patch_id, "hi");
}

#[test]
fn binary_patcher_force_bypasses_validation_mismatch() {
    let bin = bin64();
    let p = Patch::new("p", "", 0, vec![0xFF, 0xFF], vec![0xAA, 0xBB]);
    let patcher = BinaryPatcher::new().force(true);
    let r = patcher.apply_one(&p, &bin).unwrap();
    assert_eq!(&r.data[0..2], &[0xAA, 0xBB]);
}

#[test]
fn binary_patcher_no_validate_skips_validation_field() {
    let bin = bin64();
    let p = Patch::new("p", "", 0, vec![0, 1], vec![0xAA, 0xBB]);
    let r = BinaryPatcher::new().no_validate().apply_one(&p, &bin).unwrap();
    assert!(r.validation.is_none());
}

#[test]
fn binary_patcher_validate_before_attaches_report() {
    let bin = bin64();
    let p = Patch::new("p", "", 0, vec![0, 1], vec![0xAA, 0xBB]);
    let r = BinaryPatcher::new().apply_one(&p, &bin).unwrap();
    assert!(r.validation.is_some());
    assert!(r.validation.unwrap().is_valid());
}

#[test]
fn binary_patcher_skips_already_applied() {
    let bin = bin64();
    let mut p = Patch::new("p", "", 0, vec![0, 1], vec![0xAA, 0xBB]);
    p.applied = true;
    let patcher = BinaryPatcher::new().no_validate();
    let r = patcher.apply_one(&p, &bin).unwrap();
    assert_eq!(r.patches_applied, 0);
    assert_eq!(&r.data[0..2], &[0, 1]);
}

#[test]
fn binary_patcher_skips_out_of_bounds_silently_without_fail_fast() {
    let bin = vec![0u8; 4];
    let p = Patch::new("p", "", 2, vec![], vec![1, 2, 3, 4]); // extends beyond end
    // no_validate so we hit the runtime path
    let r = BinaryPatcher::new().no_validate().apply_one(&p, &bin).unwrap();
    assert_eq!(r.patches_applied, 0);
}

#[test]
fn binary_patcher_fail_fast_on_oob_returns_err() {
    let bin = vec![0u8; 4];
    let p = Patch::new("p", "", 2, vec![], vec![1, 2, 3, 4]);
    let opts = PatchOptions { validate_before: ValidateBefore::No, fail_fast: FailFast::Yes, ..Default::default() };
    let err = BinaryPatcher::with_options(opts).apply_one(&p, &bin);
    assert!(matches!(err, Err(PatcherError::ApplicationFailed(_, _))));
}

#[test]
fn binary_patcher_with_validator_strict_rejects_size_mismatch() {
    let bin = bin64();
    let p = Patch::new("p", "", 0, vec![0, 1, 2], vec![9, 9]);
    let r = BinaryPatcher::new()
        .with_validator(PatchValidator::strict())
        .apply_one(&p, &bin);
    assert!(matches!(r, Err(PatcherError::ValidationFailed(_))));
}

#[test]
fn apply_patches_empty_err() {
    let err = apply_patches(&[], &bin64());
    assert!(matches!(err, Err(PatcherError::EmptyPatchSet)));
}

#[test]
fn apply_set_empty_err() {
    let set = PatchSet::new("s", "");
    let err = BinaryPatcher::new().apply_set(&set, &bin64());
    assert!(matches!(err, Err(PatcherError::EmptyPatchSet)));
}

#[test]
fn apply_inserts_at_zero_and_end() {
    let bin = vec![1, 2, 3];
    let patcher = BinaryPatcher::new();
    let r = patcher.apply_inserts(&[(0, vec![0xAA])], &bin).unwrap();
    assert_eq!(r, vec![0xAA, 1, 2, 3]);
    let r2 = patcher.apply_inserts(&[(3, vec![0xBB])], &bin).unwrap();
    assert_eq!(r2, vec![1, 2, 3, 0xBB]);
}

#[test]
fn apply_inserts_multiple_processed_in_reverse() {
    let bin = vec![1, 2, 3, 4];
    let inserts = vec![(1u64, vec![0xAA]), (3u64, vec![0xBB])];
    let r = BinaryPatcher::new().apply_inserts(&inserts, &bin).unwrap();
    // Reverse-order processing keeps original offsets meaningful:
    // insert 0xBB at 3 first -> [1,2,3,0xBB,4]; then 0xAA at 1 -> [1,0xAA,2,3,0xBB,4]
    assert_eq!(r, vec![1, 0xAA, 2, 3, 0xBB, 4]);
}

#[test]
fn apply_inserts_oob() {
    let bin = vec![1u8; 2];
    let err = BinaryPatcher::new().apply_inserts(&[(99, vec![0])], &bin);
    assert!(matches!(err, Err(PatcherError::ApplicationFailed(_, _))));
}

#[test]
fn apply_removals_basic() {
    let bin = vec![1u8, 2, 3, 4, 5];
    let r = BinaryPatcher::new().apply_removals(&[(1, 2)], &bin).unwrap();
    assert_eq!(r, vec![1, 4, 5]);
}

#[test]
fn apply_removals_zero_length_noop() {
    let bin = vec![1u8, 2, 3];
    let r = BinaryPatcher::new().apply_removals(&[(1, 0)], &bin).unwrap();
    assert_eq!(r, bin);
}

#[test]
fn apply_removals_oob() {
    let bin = vec![1u8, 2];
    let err = BinaryPatcher::new().apply_removals(&[(0, 99)], &bin);
    assert!(matches!(err, Err(PatcherError::ApplicationFailed(_, _))));
}

#[test]
fn checksum_after_differs_on_modification() {
    let bin = bin64();
    let p = Patch::new("p", "", 0, vec![0, 1], vec![0xAA, 0xBB]);
    let patcher = BinaryPatcher::new();
    let cs_modified = patcher.checksum_after(&[p], &bin).unwrap();
    // Compute checksum of unchanged via a no-op (Force-bypass null op not possible, so use noop patch with originals = patch)
    let noop = Patch::new("n", "", 0, vec![0, 1], vec![0, 1]);
    let cs_same = patcher.checksum_after(&[noop], &bin).unwrap();
    assert_ne!(cs_modified, cs_same);
}

#[test]
fn patchop_name_and_changes_size() {
    assert_eq!(PatchOp::Overwrite.name(), "overwrite");
    assert_eq!(PatchOp::Insert.name(), "insert");
    assert_eq!(PatchOp::Remove.name(), "remove");
    assert_eq!(PatchOp::Nop.name(), "nop");
    assert!(PatchOp::Insert.changes_size());
    assert!(PatchOp::Remove.changes_size());
    assert!(!PatchOp::Overwrite.changes_size());
    assert!(!PatchOp::Nop.changes_size());
}

#[test]
fn patcher_debug_format() {
    let s = format!("{:?}", BinaryPatcher::new());
    assert!(s.contains("BinaryPatcher"));
}

#[test]
fn patch_result_display() {
    let bin = bin64();
    let p = Patch::new("p", "", 0, vec![0, 1], vec![0xAA, 0xBB]);
    let r = apply_patches(&[p], &bin).unwrap();
    let s = r.to_string();
    assert!(s.contains("PatchResult"));
}

#[test]
fn applied_op_display_contains_id_and_op_name() {
    let op = AppliedOp { patch_id: "X".into(), op: PatchOp::Overwrite, offset: 8, bytes_written: vec![1], bytes_original: vec![0] };
    let s = op.to_string();
    assert!(s.contains('X'));
    assert!(s.contains("overwrite"));
}

// ---------------------------------------------------------------------------
// patch_rollback
// ---------------------------------------------------------------------------

#[test]
fn create_rollback_empty_err() {
    let err = create_rollback(&[], &bin64());
    assert!(matches!(err, Err(RollbackError::Empty)));
}

#[test]
fn create_rollback_id_is_rollback() {
    let p = Patch::new("p", "", 0, vec![0, 1], vec![9, 9]);
    let s = create_rollback(&[p], &bin64()).unwrap();
    assert_eq!(s.id, "rollback");
}

#[test]
fn rollback_entry_from_patch_fields() {
    let p = Patch::new("p", "desc", 0x100, vec![1, 2], vec![3, 4]);
    let e = RollbackEntry::from_patch(&p, 7);
    assert_eq!(e.patch_id, "p");
    assert_eq!(e.offset, 0x100);
    assert_eq!(e.original_bytes, vec![1, 2]);
    assert_eq!(e.patched_bytes, vec![3, 4]);
    assert_eq!(e.sequence, 7);
    assert_eq!(e.size(), 2);
    assert!(e.description.contains("desc"));
}

#[test]
fn rollback_entry_can_rollback_and_already_state() {
    let bin = bin64();
    let p = Patch::new("p", "", 0, vec![0, 1, 2, 3], vec![0xAA, 0xBB, 0xCC, 0xDD]);
    let e = RollbackEntry::from_patch(&p, 0);
    assert!(!e.can_rollback(&bin));
    assert!(e.is_already_rolled_back(&bin));
    let mut patched = bin;
    patched[0..4].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    assert!(e.can_rollback(&patched));
    assert!(!e.is_already_rolled_back(&patched));
}

#[test]
fn rollback_entry_from_applied_op() {
    let op = AppliedOp { patch_id: "p".into(), op: PatchOp::Overwrite, offset: 4, bytes_written: vec![9, 9], bytes_original: vec![1, 1] };
    let e = RollbackEntry::from_applied_op(&op, 3);
    assert_eq!(e.patch_id, "p");
    assert_eq!(e.sequence, 3);
    assert_eq!(e.original_bytes, vec![1, 1]);
    assert_eq!(e.patched_bytes, vec![9, 9]);
}

#[test]
fn rollback_restores_bytes_full_cycle() {
    let bin = bin64();
    let mut set = PatchSet::new("s", "");
    set.add(Patch::new("p1", "", 0, vec![0, 1, 2, 3], vec![0xAA, 0xBB, 0xCC, 0xDD]));
    set.add(Patch::new("p2", "", 8, vec![8, 9, 10, 11], vec![0x11, 0x22, 0x33, 0x44]));

    let mut rb = PatchRollback::new();
    rb.create_snapshot(&set, &bin, "snap").unwrap();

    let r = BinaryPatcher::new().apply_set(&set, &bin).unwrap();
    let restored = rb.rollback("snap", &r.data).unwrap();
    assert_eq!(restored.data, bin);
    assert!(restored.is_complete(2));
}

#[test]
fn rollback_unknown_snapshot_returns_unknown_patch_id() {
    let rb = PatchRollback::new();
    let err = rb.rollback("missing", &bin64());
    assert!(matches!(err, Err(RollbackError::UnknownPatchId(_))));
}

#[test]
fn rollback_oob_entry_fails() {
    let bin = vec![0u8; 4];
    let e = RollbackEntry {
        patch_id: "p".into(),
        offset: 10,
        original_bytes: vec![1, 2],
        patched_bytes: vec![9, 9],
        description: String::new(),
        sequence: 0,
    };
    let snap = RollbackSnapshot::new("s", vec![e], 0);
    let rb = PatchRollback::new().verify_checksum(false);
    let err = rb.apply_snapshot(&snap, &bin);
    assert!(matches!(err, Err(RollbackError::OutOfBounds(_))));
}

#[test]
fn rollback_empty_snapshot_err() {
    let snap = RollbackSnapshot::new("s", vec![], 0);
    let rb = PatchRollback::new();
    let err = rb.apply_snapshot(&snap, &bin64());
    assert!(matches!(err, Err(RollbackError::Empty)));
}

#[test]
fn rollback_checksum_mismatch_detected() {
    let bin = bin64();
    let mut set = PatchSet::new("s", "");
    set.add(Patch::new("p", "", 0, vec![0, 1], vec![0xAA, 0xBB]));
    let mut rb = PatchRollback::new();
    // create_snapshot stores fnv1a of original bin
    rb.create_snapshot(&set, &bin, "snap").unwrap();
    // Apply rollback to a buffer that *doesn't* recreate the snapshot's original checksum.
    let mut bogus = bin.clone();
    bogus[20] = 0xFF; // bytes outside the rollback range — rollback won't fix this
    bogus[0..2].copy_from_slice(&[0xAA, 0xBB]);
    let err = rb.rollback("snap", &bogus);
    assert!(matches!(err, Err(RollbackError::ChecksumMismatch { .. })));
}

#[test]
fn patchrollback_create_from_ops_empty_err() {
    let mut rb = PatchRollback::new();
    let err = rb.create_snapshot_from_ops(&[], 0, "x");
    assert!(matches!(err, Err(RollbackError::Empty)));
}

#[test]
fn patchrollback_create_from_ops_populates() {
    let mut rb = PatchRollback::new();
    let ops = vec![AppliedOp { patch_id: "a".into(), op: PatchOp::Overwrite, offset: 0, bytes_written: vec![9], bytes_original: vec![0] }];
    let snap = rb.create_snapshot_from_ops(&ops, 0xDEAD_BEEF, "snap").unwrap();
    assert_eq!(snap.entries.len(), 1);
    assert_eq!(snap.original_checksum, 0xDEAD_BEEF);
}

#[test]
fn patchrollback_snapshot_ids_sorted() {
    let mut rb = PatchRollback::new();
    let mut s = PatchSet::new("s", "");
    s.add(Patch::new("p", "", 0, vec![0], vec![1]));
    rb.create_snapshot(&s, &bin64(), "b").unwrap();
    rb.create_snapshot(&s, &bin64(), "a").unwrap();
    let ids = rb.snapshot_ids();
    assert_eq!(ids, vec!["a", "b"]);
}

#[test]
fn patchrollback_get_remove_clear_count() {
    let mut rb = PatchRollback::new();
    let mut s = PatchSet::new("s", "");
    s.add(Patch::new("p", "", 0, vec![0], vec![1]));
    rb.create_snapshot(&s, &bin64(), "x").unwrap();
    assert_eq!(rb.snapshot_count(), 1);
    assert!(rb.get_snapshot("x").is_some());
    assert!(rb.get_snapshot("missing").is_none());
    assert!(rb.remove_snapshot("x").is_some());
    assert_eq!(rb.snapshot_count(), 0);
    rb.create_snapshot(&s, &bin64(), "y").unwrap();
    rb.clear();
    assert_eq!(rb.snapshot_count(), 0);
}

#[test]
fn rollback_snapshot_with_label() {
    let snap = RollbackSnapshot::new("s", vec![], 0).with_label("v1.0");
    assert_eq!(snap.label.as_deref(), Some("v1.0"));
}

#[test]
fn rollback_result_display_contains_checksum() {
    let r = RollbackResult { data: vec![], entries_applied: 1, entries_skipped: 0, checksum: 0xCAFE };
    let s = r.to_string();
    assert!(s.contains("applied=1"));
    assert!(s.contains("0x"));
}

#[test]
fn rollback_entry_display_contains_id() {
    let e = RollbackEntry { patch_id: "id".into(), offset: 0, original_bytes: vec![], patched_bytes: vec![], description: String::new(), sequence: 0 };
    assert!(e.to_string().contains("id"));
}

#[test]
fn patchrollback_debug_format() {
    let s = format!("{:?}", PatchRollback::new());
    assert!(s.contains("PatchRollback"));
}

// ---------------------------------------------------------------------------
// code_cave
// ---------------------------------------------------------------------------

fn make_minimal_elf64_with_text(text: &[u8]) -> Vec<u8> {
    // Mirrors the helper in src/code_cave.rs tests so we can exercise the API.
    const SHF_EXECINSTR: u64 = 0x4;
    let shentsize = 64usize;
    let ehdr_size = 64usize;
    let text_off = ehdr_size;
    let text_size = text.len();
    let shstrtab_off = text_off + text_size;
    let mut shstrtab = Vec::new();
    shstrtab.push(0);
    let name_text = u32::try_from(shstrtab.len()).unwrap();
    shstrtab.extend_from_slice(b".text\0");
    let name_shstr = u32::try_from(shstrtab.len()).unwrap();
    shstrtab.extend_from_slice(b".shstrtab\0");
    let shstrtab_size = shstrtab.len();
    let shoff = shstrtab_off + shstrtab_size;
    let total = shoff + 3 * shentsize;

    let mut out = vec![0u8; total];
    out[0..4].copy_from_slice(b"\x7FELF");
    out[4] = 2;
    out[5] = 1;
    out[6] = 1;
    out[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes());
    out[0x3A..0x3C].copy_from_slice(&u16::try_from(shentsize).unwrap().to_le_bytes());
    out[0x3C..0x3E].copy_from_slice(&3u16.to_le_bytes());
    out[0x3E..0x40].copy_from_slice(&2u16.to_le_bytes());

    out[text_off..text_off + text_size].copy_from_slice(text);
    out[shstrtab_off..shstrtab_off + shstrtab_size].copy_from_slice(&shstrtab);

    let sh1 = shoff + shentsize;
    out[sh1..sh1 + 4].copy_from_slice(&name_text.to_le_bytes());
    out[sh1 + 4..sh1 + 8].copy_from_slice(&1u32.to_le_bytes());
    out[sh1 + 8..sh1 + 16].copy_from_slice(&(SHF_EXECINSTR | 0x2).to_le_bytes());
    out[sh1 + 16..sh1 + 24].copy_from_slice(&0x1000u64.to_le_bytes());
    out[sh1 + 24..sh1 + 32].copy_from_slice(&(text_off as u64).to_le_bytes());
    out[sh1 + 32..sh1 + 40].copy_from_slice(&(text_size as u64).to_le_bytes());

    let sh2 = shoff + 2 * shentsize;
    out[sh2..sh2 + 4].copy_from_slice(&name_shstr.to_le_bytes());
    out[sh2 + 4..sh2 + 8].copy_from_slice(&3u32.to_le_bytes());
    out[sh2 + 24..sh2 + 32].copy_from_slice(&(shstrtab_off as u64).to_le_bytes());
    out[sh2 + 32..sh2 + 40].copy_from_slice(&(shstrtab_size as u64).to_le_bytes());

    out
}

#[test]
fn detect_format_elf_pe_and_unknown() {
    let elf = make_minimal_elf64_with_text(&[0x90; 32]);
    assert_eq!(CodeCaveScanner::detect_format(&elf).unwrap(), BinaryFormat::Elf);
    let pe = vec![b'M', b'Z', 0, 0, 0, 0, 0, 0];
    assert_eq!(CodeCaveScanner::detect_format(&pe).unwrap(), BinaryFormat::Pe);
    let bad = vec![0xFF, 0xFE, 0xFD, 0xFC];
    assert!(matches!(CodeCaveScanner::detect_format(&bad), Err(CaveError::UnknownFormat(_))));
}

#[test]
fn detect_format_too_small() {
    let bin = vec![0u8; 3];
    assert!(matches!(CodeCaveScanner::detect_format(&bin), Err(CaveError::TooSmall(_))));
}

#[test]
fn scanner_new_zero_min_size_err() {
    assert!(matches!(CodeCaveScanner::new(0), Err(CaveError::InvalidMinSize)));
}

#[test]
fn scanner_default_min_size_16() {
    let s = CodeCaveScanner::default();
    assert_eq!(s.min_size, 16);
    assert_eq!(s.fill_bytes, vec![0x00, 0xCC, 0x90]);
}

#[test]
fn find_code_caves_default_fill_set() {
    let mut text = vec![0x55u8; 4];
    text.extend(std::iter::repeat_n(0xCC, 32));
    text.extend(vec![0x55u8; 4]);
    text.extend(std::iter::repeat_n(0x90, 20));
    text.extend(vec![0x55u8; 4]);
    let bin = make_minimal_elf64_with_text(&text);
    let caves = find_code_caves(&bin, 16).unwrap();
    assert_eq!(caves.len(), 2);
    let sizes: Vec<usize> = caves.iter().map(|c| c.size).collect();
    assert!(sizes.contains(&32));
    assert!(sizes.contains(&20));
}

#[test]
fn cave_below_min_size_filtered() {
    let mut text = vec![0x55u8; 4];
    text.extend(std::iter::repeat_n(0xCC, 8)); // smaller than min_size=16
    text.extend(vec![0x55u8; 4]);
    let bin = make_minimal_elf64_with_text(&text);
    let caves = find_code_caves(&bin, 16).unwrap();
    assert!(caves.is_empty());
}

#[test]
fn scanner_with_custom_fill_bytes() {
    let mut text = vec![0x55u8; 4];
    text.extend(std::iter::repeat_n(0xABu8, 32)); // unusual fill
    text.extend(vec![0x55u8; 4]);
    let bin = make_minimal_elf64_with_text(&text);
    // Default fill set won't find it
    let none = find_code_caves(&bin, 16).unwrap();
    assert!(none.is_empty());
    // Custom fill set finds it
    let scanner = CodeCaveScanner::new(16).unwrap().with_fill_bytes(vec![0xAB]);
    let caves = scanner.scan(&bin).unwrap();
    assert_eq!(caves.len(), 1);
    assert_eq!(caves[0].fill_byte, 0xAB);
}

#[test]
fn find_first_fit_returns_smallest() {
    let mut text = vec![0x55u8; 4];
    text.extend(std::iter::repeat_n(0x00, 64));
    text.push(0x55);
    text.extend(std::iter::repeat_n(0x00, 32));
    let bin = make_minimal_elf64_with_text(&text);
    let scanner = CodeCaveScanner::new(16).unwrap();
    let fit = scanner.find_first_fit(&bin, 20).unwrap().unwrap();
    assert_eq!(fit.size, 32);
}

#[test]
fn find_first_fit_returns_none_when_too_small() {
    let mut text = vec![0x55u8; 4];
    text.extend(std::iter::repeat_n(0x00, 20));
    let bin = make_minimal_elf64_with_text(&text);
    let scanner = CodeCaveScanner::new(16).unwrap();
    let fit = scanner.find_first_fit(&bin, 100).unwrap();
    assert!(fit.is_none());
}

#[test]
fn pe_too_small_err() {
    let pe = vec![b'M', b'Z', 0, 0, 0, 0, 0, 0]; // 8 bytes < 0x40
    let scanner = CodeCaveScanner::new(16).unwrap();
    let err = scanner.scan(&pe);
    assert!(matches!(err, Err(CaveError::TooSmall(_))));
}

#[test]
fn pe_bad_signature_malformed() {
    // 0x40+ bytes, e_lfanew points into middle but signature isn't PE\0\0
    let mut pe = vec![0u8; 0x100];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    // bytes at 0x80 are 0,0,0,0 — not "PE\0\0"
    let scanner = CodeCaveScanner::new(16).unwrap();
    let err = scanner.scan(&pe);
    assert!(matches!(err, Err(CaveError::Malformed(_))));
}

#[test]
fn pe_e_lfanew_out_of_bounds() {
    let mut pe = vec![0u8; 0x80];
    pe[0..2].copy_from_slice(b"MZ");
    // e_lfanew points way past end
    pe[0x3C..0x40].copy_from_slice(&0xFFFF_0000u32.to_le_bytes());
    let scanner = CodeCaveScanner::new(16).unwrap();
    let err = scanner.scan(&pe);
    assert!(matches!(err, Err(CaveError::Malformed(_))));
}

#[test]
fn elf_big_endian_rejected() {
    let mut bin = vec![0u8; 0x80];
    bin[0..4].copy_from_slice(b"\x7FELF");
    bin[4] = 2;
    bin[5] = 2; // big-endian
    let scanner = CodeCaveScanner::new(16).unwrap();
    let err = scanner.scan(&bin);
    assert!(matches!(err, Err(CaveError::Malformed(_))));
}

#[test]
fn elf_unknown_class_rejected() {
    let mut bin = vec![0u8; 0x80];
    bin[0..4].copy_from_slice(b"\x7FELF");
    bin[4] = 9;
    bin[5] = 1;
    let scanner = CodeCaveScanner::new(16).unwrap();
    let err = scanner.scan(&bin);
    assert!(matches!(err, Err(CaveError::Malformed(_))));
}

#[test]
fn binary_format_display() {
    assert_eq!(BinaryFormat::Pe.to_string(), "PE");
    assert_eq!(BinaryFormat::Elf.to_string(), "ELF");
}

#[test]
fn code_cave_display_with_and_without_va() {
    let c = CodeCave { section: ".text".into(), file_offset: 0x10, virtual_address: Some(0x1000), size: 32, fill_byte: 0xCC };
    let s = c.to_string();
    assert!(s.contains(".text"));
    assert!(s.contains("0x1000"));
    let c2 = CodeCave { virtual_address: None, ..c };
    assert!(!c2.to_string().contains("va@"));
}

// ---------------------------------------------------------------------------
// hot_patch
// ---------------------------------------------------------------------------

#[test]
fn hot_patch_apply_and_revert_roundtrip() {
    let original = vec![0xE8, 0x10, 0x20, 0x30, 0x40, 0xAA, 0xBB];
    let writer = InMemoryWriter::new(0x4000, original);
    let patcher = HotPatcher::new(writer);
    let p = Patch::new("p", "", 0, vec![0xE8, 0x10, 0x20, 0x30, 0x40], vec![0x90; 5]);

    let live = patcher.apply(&p, 0x4000).unwrap();
    assert_eq!(live.captured_original, vec![0xE8, 0x10, 0x20, 0x30, 0x40]);
    assert_eq!(live.written_bytes, vec![0x90; 5]);
    assert_eq!(patcher.live_count(), 1);

    let _r = patcher.revert("p").unwrap();
    assert_eq!(patcher.live_count(), 0);
}

#[test]
fn hot_patch_rejects_double_apply() {
    let writer = InMemoryWriter::new(0, vec![0xE8, 0x10, 0x20, 0x30, 0x40]);
    let patcher = HotPatcher::new(writer);
    let p = Patch::new("dup", "", 0, vec![0xE8, 0x10, 0x20, 0x30, 0x40], vec![0x90; 5]);
    patcher.apply(&p, 0).unwrap();
    assert!(matches!(patcher.apply(&p, 0), Err(HotPatchError::AlreadyLive(_))));
}

#[test]
fn hot_patch_detects_original_mismatch_when_verify_on() {
    let writer = InMemoryWriter::new(0, vec![0u8; 8]);
    let patcher = HotPatcher::new(writer);
    let p = Patch::new("p", "", 0, vec![0xE8; 5], vec![0x90; 5]);
    assert!(matches!(patcher.apply(&p, 0), Err(HotPatchError::OriginalMismatch { .. })));
}

#[test]
fn hot_patch_skips_verify_when_disabled() {
    let writer = InMemoryWriter::new(0, vec![0u8; 8]);
    let mut patcher = HotPatcher::new(writer);
    patcher.verify_originals = false;
    let p = Patch::new("p", "", 0, vec![0xE8; 5], vec![0x90; 5]);
    let res = patcher.apply(&p, 0);
    assert!(res.is_ok());
}

#[test]
fn hot_patch_writer_error_propagates() {
    // Reading from below the base produces an InMemoryWriter error.
    let writer = InMemoryWriter::new(0x1000, vec![0u8; 16]);
    let patcher = HotPatcher::new(writer);
    let p = Patch::new("p", "", 0, vec![], vec![0; 4]);
    let err = patcher.apply(&p, 0x500);
    assert!(matches!(err, Err(HotPatchError::Writer { .. })));
}

#[test]
fn hot_patch_revert_missing_returns_not_found() {
    let writer = InMemoryWriter::new(0, vec![0u8; 4]);
    let patcher = HotPatcher::new(writer);
    let err = patcher.revert("ghost");
    assert!(matches!(err, Err(HotPatchError::NotFound(_))));
}

#[test]
fn hot_patch_revert_all_returns_all_results() {
    let writer = InMemoryWriter::new(0, vec![0xE8, 0x10, 0x20, 0x30, 0x40, 0xE8, 0x10, 0x20, 0x30, 0x40]);
    let patcher = HotPatcher::new(writer);
    let p1 = Patch::new("p1", "", 0, vec![0xE8, 0x10, 0x20, 0x30, 0x40], vec![0x90; 5]);
    let p2 = Patch::new("p2", "", 0, vec![0xE8, 0x10, 0x20, 0x30, 0x40], vec![0x90; 5]);
    patcher.apply(&p1, 0).unwrap();
    patcher.apply(&p2, 5).unwrap();
    let results = patcher.revert_all();
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(std::result::Result::is_ok));
    assert_eq!(patcher.live_count(), 0);
}

#[test]
fn hot_patch_get_and_live_patches() {
    let writer = InMemoryWriter::new(0, vec![0xE8, 0x10, 0x20, 0x30, 0x40]);
    let patcher = HotPatcher::new(writer);
    let p = Patch::new("p", "", 0, vec![0xE8, 0x10, 0x20, 0x30, 0x40], vec![0x90; 5]);
    patcher.apply(&p, 0).unwrap();
    assert!(patcher.get("p").is_some());
    assert!(patcher.get("missing").is_none());
    let live = patcher.live_patches();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].id, "p");
}

#[test]
fn live_patch_display_contains_fields() {
    let lp = LivePatch { id: "x".into(), address: 0x1000, captured_original: vec![0; 4], written_bytes: vec![1; 4] };
    let s = lp.to_string();
    assert!(s.contains('x'));
    assert!(s.contains("0x1000"));
}

#[test]
fn in_memory_writer_read_oob() {
    let w = InMemoryWriter::new(0, vec![0; 4]);
    assert!(w.read(0, 10).is_err());
    assert!(w.read(10, 1).is_err());
}

#[test]
fn in_memory_writer_write_oob() {
    let w = InMemoryWriter::new(0, vec![0; 4]);
    assert!(w.write(0, &[0; 10]).is_err());
    assert!(w.write(10, &[0]).is_err());
}

#[test]
fn in_memory_writer_flush_icache_default_noop() {
    let w = InMemoryWriter::new(0, vec![0; 4]);
    assert!(w.flush_icache(0, 4).is_ok());
}

#[test]
fn in_memory_writer_snapshot_independent() {
    let w = InMemoryWriter::new(0, vec![1, 2, 3, 4]);
    let s1 = w.snapshot();
    w.write(0, &[9]).unwrap();
    let s2 = w.snapshot();
    assert_eq!(s1, vec![1, 2, 3, 4]);
    assert_eq!(s2[0], 9);
}

#[test]
fn runtime_memory_writer_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<InMemoryWriter>();
}

// ---------------------------------------------------------------------------
// binary_diff
// ---------------------------------------------------------------------------

#[test]
fn diff_roundtrip_identical() {
    let buf = vec![0x42u8; 256];
    let delta = build_delta(&buf, &buf, &DiffOptions::default());
    assert_eq!(delta.apply(&buf).unwrap(), buf);
}

#[test]
fn diff_roundtrip_small_modification() {
    let old: Vec<u8> = (0u8..=255).collect();
    let mut new = old.clone();
    new[100] = 0xFF;
    new[101] = 0xFE;
    let delta = build_delta(&old, &new, &DiffOptions { min_match: 4, window: 256 });
    let out = delta.apply(&old).unwrap();
    assert_eq!(out, new);
}

#[test]
fn diff_completely_different() {
    let old: Vec<u8> = (0u8..=255).collect();
    let new: Vec<u8> = (0u8..=255).rev().collect();
    let delta = build_delta(&old, &new, &DiffOptions::default());
    assert_eq!(delta.apply(&old).unwrap(), new);
}

#[test]
fn diff_empty_old_to_nonempty_new() {
    let old: Vec<u8> = vec![];
    let new: Vec<u8> = (0..32).collect();
    let delta = build_delta(&old, &new, &DiffOptions::default());
    assert_eq!(delta.apply(&old).unwrap(), new);
}

#[test]
fn diff_nonempty_old_to_empty_new() {
    let old: Vec<u8> = (0..32).collect();
    let new: Vec<u8> = vec![];
    let delta = build_delta(&old, &new, &DiffOptions::default());
    assert_eq!(delta.apply(&old).unwrap(), new);
}

#[test]
fn diff_both_empty() {
    let delta = build_delta(&[], &[], &DiffOptions::default());
    assert_eq!(delta.apply(&[]).unwrap(), Vec::<u8>::new());
}

#[test]
fn diff_encode_decode_preserves_delta() {
    let old = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let new = vec![1u8, 2, 3, 99, 5, 6, 7, 8, 9, 10];
    let delta = build_delta(&old, &new, &DiffOptions { min_match: 4, window: 32 });
    let blob = delta.encode();
    let decoded = BinaryDelta::decode(&blob).unwrap();
    assert_eq!(decoded, delta);
}

#[test]
fn diff_apply_detects_source_size_mismatch_via_hash() {
    let old = vec![1u8; 64];
    let new = vec![2u8; 64];
    let delta = build_delta(&old, &new, &DiffOptions::default());
    let wrong_len = vec![1u8; 63];
    assert!(matches!(delta.apply(&wrong_len), Err(DiffError::SourceHashMismatch)));
}

#[test]
fn diff_apply_detects_source_hash_mismatch_same_size() {
    let old = vec![1u8; 64];
    let new = vec![2u8; 64];
    let delta = build_delta(&old, &new, &DiffOptions::default());
    let wrong = vec![9u8; 64];
    assert!(matches!(delta.apply(&wrong), Err(DiffError::SourceHashMismatch)));
}

#[test]
fn diff_decode_bad_magic() {
    let mut blob = vec![0u8; 256];
    blob[0..4].copy_from_slice(b"XXXX");
    assert!(matches!(BinaryDelta::decode(&blob), Err(DiffError::BadMagic)));
}

#[test]
fn diff_decode_truncated() {
    let blob = vec![b'R', b'R', b'D', b'F', 1, 0];
    assert!(matches!(BinaryDelta::decode(&blob), Err(DiffError::Truncated(_))));
}

#[test]
fn diff_decode_unsupported_version() {
    // Build a valid-ish header with version 99
    let mut blob = vec![0u8; 90];
    blob[0..4].copy_from_slice(b"RRDF");
    blob[4..6].copy_from_slice(&99u16.to_le_bytes());
    assert!(matches!(BinaryDelta::decode(&blob), Err(DiffError::UnsupportedVersion(99))));
}

#[test]
fn diff_decode_unknown_op_tag() {
    // Build a header with 1 op of unknown tag.
    let mut blob = Vec::new();
    blob.extend_from_slice(b"RRDF");
    blob.extend_from_slice(&1u16.to_le_bytes());
    blob.extend_from_slice(&0u64.to_le_bytes()); // old_size
    blob.extend_from_slice(&0u64.to_le_bytes()); // new_size
    blob.extend_from_slice(&[0u8; 32]);          // old_sha
    blob.extend_from_slice(&[0u8; 32]);          // new_sha
    blob.extend_from_slice(&1u32.to_le_bytes()); // op_count = 1
    blob.push(0xFE);                              // unknown tag
    let err = BinaryDelta::decode(&blob);
    assert!(matches!(err, Err(DiffError::UnknownOpTag(0xFE))));
}

#[test]
fn diff_decode_truncated_copy_op_payload() {
    // op_count=1, tag=0x01 (Copy), but only 8 bytes (not 16) of payload follow.
    let mut blob = Vec::new();
    blob.extend_from_slice(b"RRDF");
    blob.extend_from_slice(&1u16.to_le_bytes());
    blob.extend_from_slice(&0u64.to_le_bytes());
    blob.extend_from_slice(&0u64.to_le_bytes());
    blob.extend_from_slice(&[0u8; 32]);
    blob.extend_from_slice(&[0u8; 32]);
    blob.extend_from_slice(&1u32.to_le_bytes());
    blob.push(0x01);
    blob.extend_from_slice(&0u64.to_le_bytes()); // only src_offset, length missing
    assert!(matches!(BinaryDelta::decode(&blob), Err(DiffError::Truncated(_))));
}

#[test]
fn diff_decode_insert_truncated() {
    // op_count=1, tag=0x02 (Insert), length=100 but no body bytes after.
    let mut blob = Vec::new();
    blob.extend_from_slice(b"RRDF");
    blob.extend_from_slice(&1u16.to_le_bytes());
    blob.extend_from_slice(&0u64.to_le_bytes());
    blob.extend_from_slice(&0u64.to_le_bytes());
    blob.extend_from_slice(&[0u8; 32]);
    blob.extend_from_slice(&[0u8; 32]);
    blob.extend_from_slice(&1u32.to_le_bytes());
    blob.push(0x02);
    blob.extend_from_slice(&100u64.to_le_bytes()); // length 100, no body
    assert!(matches!(BinaryDelta::decode(&blob), Err(DiffError::InsertTruncated { .. })));
}

#[test]
fn diff_copy_op_out_of_bounds_apply_err() {
    let old = vec![1u8; 16];
    let mut delta = build_delta(&old, &old, &DiffOptions::default());
    // Inject a bogus Copy that runs off the end
    delta.ops = vec![DiffOp::Copy { src_offset: 10, length: 1000 }];
    delta.new_size = 1000;
    let err = delta.apply(&old);
    assert!(matches!(err, Err(DiffError::CopyOutOfBounds { .. })));
}

#[test]
fn diff_copy_op_overflow_apply_err() {
    let old = vec![1u8; 16];
    let mut delta = build_delta(&old, &old, &DiffOptions::default());
    // src_offset + length overflows u64
    delta.ops = vec![DiffOp::Copy { src_offset: u64::MAX, length: 5 }];
    delta.new_size = 5;
    let err = delta.apply(&old);
    assert!(matches!(err, Err(DiffError::CopyOutOfBounds { .. })));
}

#[test]
fn diff_size_mismatch_after_apply() {
    let old: Vec<u8> = (0u8..16).collect();
    let mut delta = build_delta(&old, &old, &DiffOptions::default());
    // Force a header that claims more bytes than the ops produce
    delta.new_size = 9999;
    let err = delta.apply(&old);
    // Either SizeMismatch or TargetHashMismatch could trigger; SizeMismatch comes first
    assert!(matches!(err, Err(DiffError::SizeMismatch { .. })));
}

#[test]
fn diff_target_hash_mismatch() {
    let old: Vec<u8> = (0u8..16).collect();
    let mut delta = build_delta(&old, &old, &DiffOptions::default());
    delta.new_sha256 = [0xAA; 32]; // wrong target hash
    let err = delta.apply(&old);
    assert!(matches!(err, Err(DiffError::TargetHashMismatch)));
}

#[test]
fn diff_convenience_functions_roundtrip() {
    let old = b"hello world this is a long string for diffing test".to_vec();
    let mut new = old.clone();
    new[6..11].copy_from_slice(b"THERE");
    let blob = diff(&old, &new);
    let out = patch(&old, &blob).unwrap();
    assert_eq!(out, new);
}

#[test]
fn diff_encoded_size_matches_encode_length() {
    let old = vec![1u8; 64];
    let new = vec![2u8; 64];
    let delta = build_delta(&old, &new, &DiffOptions::default());
    assert_eq!(delta.encoded_size(), delta.encode().len());
}

#[test]
fn diff_op_display() {
    let c = DiffOp::Copy { src_offset: 0x10, length: 32 };
    let i = DiffOp::Insert { bytes: vec![0; 8] };
    assert!(c.to_string().contains("Copy"));
    assert!(c.to_string().contains("0x10"));
    assert!(i.to_string().contains("Insert"));
    assert!(i.to_string().contains("len=8"));
}

#[test]
fn diff_options_default_values() {
    let o = DiffOptions::default();
    assert_eq!(o.min_match, 16);
    assert_eq!(o.window, 4096);
}

#[test]
fn diff_large_append_roundtrip() {
    let old: Vec<u8> = (0u8..=255).collect();
    let mut new = old.clone();
    new.extend(std::iter::repeat_n(0xCD, 512));
    let delta = build_delta(&old, &new, &DiffOptions::default());
    assert_eq!(delta.apply(&old).unwrap(), new);
}
