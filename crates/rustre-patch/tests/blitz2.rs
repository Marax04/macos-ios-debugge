//! Deep adversarial tests for rustre-patch (Y109).

use rustre_patch::*;
use rustre_patch::binary_diff::{BinaryDelta, DiffError, DiffOp, DiffOptions, build_delta, diff, patch};
use rustre_patch::binary_patcher::{BinaryPatcher, PatchOp, PatcherError, apply_patches};
use rustre_patch::code_cave::{BinaryFormat, CaveError, CodeCaveScanner, find_code_caves};
use rustre_patch::hot_patch::{HotPatchError, HotPatcher, InMemoryWriter};
use rustre_patch::patch_rollback::{PatchRollback, RollbackEntry, RollbackError, create_rollback};
use rustre_patch::patch_validator::{
    PatchValidator, ValidationError, ValidationReport, ValidatorRule, validate_patch,
};

use std::collections::HashSet;
use std::sync::Arc;
use std::thread;

// ---------------------------------------------------------------------------
// Seeded LCG
// ---------------------------------------------------------------------------
struct Lcg(u64);
impl Lcg {
    const fn new(seed: u64) -> Self { Self(seed) }
    const fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    fn byte(&mut self) -> u8 { u8::try_from(self.next() & 0xFF).unwrap() }
    fn bytes(&mut self, n: usize) -> Vec<u8> { (0..n).map(|_| self.byte()).collect() }
}

fn binary64() -> Vec<u8> { (0u8..64).collect() }

// ---------------------------------------------------------------------------
// Patch / PatchSet basic
// ---------------------------------------------------------------------------

#[test]
fn patch_new_basic_fields() {
    let p = Patch::new("id", "desc", 0x42, vec![1, 2], vec![3, 4]);
    assert_eq!(p.id, "id");
    assert_eq!(p.description, "desc");
    assert_eq!(p.offset, 0x42);
    assert_eq!(p.size(), 2);
    assert!(p.is_same_size());
    assert!(!p.applied);
}

#[test]
fn patch_size_and_is_same_size_mismatch() {
    let p = Patch::new("i", "d", 0, vec![1, 2, 3], vec![9, 8]);
    assert_eq!(p.size(), 2);
    assert!(!p.is_same_size());
}

#[test]
fn patch_display_format() {
    let p = Patch::new("xp", "test", 0x10, vec![0], vec![0xAB]);
    let s = p.to_string();
    assert!(s.contains("xp"));
    assert!(s.contains("0x10"));
    assert!(s.contains("pending"));
}

#[test]
fn patch_set_total_bytes_and_len() {
    let mut s = PatchSet::new("s", "n");
    assert!(s.is_empty());
    s.add(Patch::new("a", "", 0, vec![], vec![1, 2, 3]));
    s.add(Patch::new("b", "", 4, vec![], vec![4, 5]));
    assert_eq!(s.len(), 2);
    assert_eq!(s.total_bytes_modified(), 5);
    let d = s.to_string();
    assert!(d.contains("PatchSet"));
    assert!(d.contains("2 patches"));
}

#[test]
fn patch_round_trip_fuzz_50_inputs() {
    let mut g = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..50 {
        let len = (g.byte() as usize % 8) + 1;
        let id = format!("p{}", g.next() % 10000);
        let off = g.next() & 0xFFFF;
        let orig = g.bytes(len);
        let new = g.bytes(len);
        let p = Patch::new(id.clone(), "x", off, orig.clone(), new.clone());
        assert_eq!(p.id, id);
        assert_eq!(p.offset, off);
        assert_eq!(p.original_bytes, orig);
        assert_eq!(p.patch_bytes, new);
        assert_eq!(p.size(), len);
        assert!(p.is_same_size());
    }
}

// ---------------------------------------------------------------------------
// Validator
// ---------------------------------------------------------------------------

#[test]
fn validator_valid_patch_passes() {
    let p = Patch::new("p", "", 0, vec![0, 1, 2, 3], vec![0xA, 0xB, 0xC, 0xD]);
    let r = validate_patch(&p, &binary64());
    assert!(r.is_valid());
    assert_eq!(r.patches_valid, 1);
    assert_eq!(r.error_count(), 0);
}

#[test]
fn validator_empty_bytes_and_id() {
    let p = Patch::new("", "", 0, vec![0], vec![]);
    let r = validate_patch(&p, &binary64());
    assert!(!r.is_valid());
    assert!(r.errors.iter().any(|e| matches!(e, ValidationError::EmptyPatchId)));
    assert!(r.errors.iter().any(|e| matches!(e, ValidationError::EmptyPatchBytes { .. })));
}

#[test]
fn validator_offset_at_exact_boundary_is_oob() {
    let b = binary64();
    let p = Patch::new("p", "", b.len() as u64, vec![], vec![1]);
    let v = PatchValidator::new().set_rule(ValidatorRule::OriginalBytesCheck, false);
    let r = v.validate_one(&p, &b);
    assert!(!r.is_valid());
    assert!(matches!(r.errors[0], ValidationError::OffsetOutOfBounds { .. }));
}

#[test]
fn validator_offset_at_max_u64_oob() {
    let b = binary64();
    let p = Patch::new("p", "", u64::MAX, vec![], vec![1]);
    let v = PatchValidator::new().set_rule(ValidatorRule::OriginalBytesCheck, false);
    let r = v.validate_one(&p, &b);
    assert!(!r.is_valid());
}

#[test]
fn validator_extends_beyond_end() {
    let b = binary64();
    let p = Patch::new("p", "", 60, vec![], vec![0xFF; 10]);
    let v = PatchValidator::new().set_rule(ValidatorRule::OriginalBytesCheck, false);
    let r = v.validate_one(&p, &b);
    assert!(!r.is_valid());
    assert!(matches!(r.errors[0], ValidationError::ExtendsBeyondEnd { .. }));
}

#[test]
fn validator_orig_bytes_mismatch() {
    let p = Patch::new("p", "", 0, vec![0xFF; 4], vec![0xAA; 4]);
    let r = validate_patch(&p, &binary64());
    assert!(!r.is_valid());
    assert!(r.errors.iter().any(|e| matches!(e, ValidationError::OriginalBytesMismatch { .. })));
}

#[test]
fn validator_already_applied_rule() {
    let mut p = Patch::new("p", "", 0, vec![0, 1], vec![0xA, 0xB]);
    p.applied = true;
    let r = validate_patch(&p, &binary64());
    assert!(!r.is_valid());
}

#[test]
fn validator_strict_length_mismatch() {
    let p = Patch::new("p", "", 0, vec![0, 1], vec![0xA]);
    let v = PatchValidator::strict().set_rule(ValidatorRule::OriginalBytesCheck, false);
    let r = v.validate_one(&p, &binary64());
    assert!(!r.is_valid());
    assert!(r.errors.iter().any(|e| matches!(e, ValidationError::LengthMismatch { .. })));
}

#[test]
fn validator_fail_fast_stops_at_first() {
    let p = Patch::new("", "", 1_000_000, vec![], vec![]);
    let v = PatchValidator::new().fail_fast(true);
    let r = v.validate_one(&p, &binary64());
    assert_eq!(r.errors.len(), 1);
}

#[test]
fn validator_set_overlapping_ranges() {
    let mut set = PatchSet::new("s", "");
    set.add(Patch::new("a", "", 0, vec![0, 1], vec![0xA, 0xB]));
    set.add(Patch::new("b", "", 1, vec![1, 2], vec![0xC, 0xD]));
    let v = PatchValidator::new().set_rule(ValidatorRule::OriginalBytesCheck, false);
    let r = v.validate_set(&set, &binary64());
    assert!(r.errors.iter().any(|e| matches!(e, ValidationError::OverlappingRanges { .. })));
}

#[test]
fn validator_non_overlapping_adjacent_ok() {
    // [0..2) and [2..4) touch but don't overlap.
    let mut set = PatchSet::new("s", "");
    set.add(Patch::new("a", "", 0, vec![0, 1], vec![0xA, 0xB]));
    set.add(Patch::new("b", "", 2, vec![2, 3], vec![0xC, 0xD]));
    let v = PatchValidator::new();
    let r = v.validate_set(&set, &binary64());
    assert!(r.is_valid(), "errors: {:?}", r.errors);
}

#[test]
fn validator_rule_display_and_descriptions() {
    for r in [
        ValidatorRule::BoundsCheck,
        ValidatorRule::OriginalBytesCheck,
        ValidatorRule::NonEmptyPatchBytes,
        ValidatorRule::NotAlreadyApplied,
        ValidatorRule::NoOverlappingRanges,
        ValidatorRule::SameSizeRequirement,
    ] {
        let s = r.to_string();
        assert!(!s.is_empty());
        assert_eq!(s, r.description());
    }
}

#[test]
fn validator_report_add_warning_and_display() {
    let mut rep = ValidationReport::new(2);
    rep.add_warning("warn1".into());
    rep.add_error(ValidationError::EmptyPatchId);
    assert_eq!(rep.error_count(), 1);
    assert_eq!(rep.warnings.len(), 1);
    let s = rep.to_string();
    assert!(s.contains("ValidationReport"));
}

#[test]
fn validator_disable_rule_round_trip() {
    let v = PatchValidator::new().set_rule(ValidatorRule::BoundsCheck, false);
    // patch with bad offset but bounds check disabled -> won't add bounds err
    let p = Patch::new("p", "", 10_000, vec![], vec![0xFF]);
    let v2 = v.set_rule(ValidatorRule::OriginalBytesCheck, false);
    let r = v2.validate_one(&p, &binary64());
    // No bounds-check, no original-check, non-empty bytes OK -> valid
    assert!(r.is_valid(), "errors: {:?}", r.errors);
}

#[test]
fn validator_fuzz_random_patches_never_panic() {
    let mut g = Lcg::new(0xA);
    let bin = binary64();
    for _ in 0..80 {
        let off = g.next() % 200;
        let olen = (g.byte() as usize) % 8;
        let nlen = (g.byte() as usize) % 8;
        let p = Patch::new(format!("p{}", g.byte()), "", off, g.bytes(olen), g.bytes(nlen));
        let _ = validate_patch(&p, &bin);
        let _ = PatchValidator::strict().validate_one(&p, &bin);
    }
}

// ---------------------------------------------------------------------------
// Binary patcher
// ---------------------------------------------------------------------------

#[test]
fn apply_patches_empty_errors() {
    assert!(matches!(apply_patches(&[], &binary64()), Err(PatcherError::EmptyPatchSet)));
}

#[test]
fn apply_patches_single_overwrites() {
    let bin = binary64();
    let p = Patch::new("p", "", 0, vec![0, 1, 2, 3], vec![0xAA, 0xBB, 0xCC, 0xDD]);
    let r = apply_patches(&[p], &bin).unwrap();
    assert_eq!(&r.data[..4], &[0xAA, 0xBB, 0xCC, 0xDD]);
    assert_eq!(r.bytes_modified, 4);
    assert!(r.is_complete(1));
}

#[test]
fn apply_patches_data_outside_region_untouched() {
    let bin = binary64();
    let p = Patch::new("p", "", 8, vec![8, 9], vec![0xEE, 0xFF]);
    let r = apply_patches(&[p], &bin).unwrap();
    assert_eq!(&r.data[..8], &bin[..8]);
    assert_eq!(&r.data[10..], &bin[10..]);
}

#[test]
fn apply_patches_validation_failure_returns_err() {
    let bin = binary64();
    let p = Patch::new("p", "", 0, vec![0xFF, 0xFF], vec![0xAA, 0xBB]);
    assert!(matches!(apply_patches(&[p], &bin), Err(PatcherError::ValidationFailed(_))));
}

#[test]
fn apply_force_bypasses_validation() {
    let bin = binary64();
    let p = Patch::new("p", "", 0, vec![0xFF, 0xFF], vec![0xAA, 0xBB]);
    let r = BinaryPatcher::new().force(true).apply_one(&p, &bin).unwrap();
    assert_eq!(&r.data[..2], &[0xAA, 0xBB]);
}

#[test]
fn apply_inserts_basic_and_oob() {
    let p = BinaryPatcher::new();
    let bin = vec![0, 1, 2, 3];
    let out = p.apply_inserts(&[(2u64, vec![0xAA, 0xBB])], &bin).unwrap();
    assert_eq!(out, vec![0, 1, 0xAA, 0xBB, 2, 3]);
    let oob = p.apply_inserts(&[(99, vec![1])], &bin);
    assert!(oob.is_err());
}

#[test]
fn apply_inserts_at_end_appends() {
    let p = BinaryPatcher::new();
    let bin = vec![0, 1, 2];
    let out = p.apply_inserts(&[(3u64, vec![0xAA])], &bin).unwrap();
    assert_eq!(out, vec![0, 1, 2, 0xAA]);
}

#[test]
fn apply_removals_basic() {
    let p = BinaryPatcher::new();
    let out = p.apply_removals(&[(1u64, 2)], &[0, 1, 2, 3, 4]).unwrap();
    assert_eq!(out, vec![0, 3, 4]);
}

#[test]
fn apply_removals_zero_len_is_noop() {
    let p = BinaryPatcher::new();
    let out = p.apply_removals(&[(2u64, 0)], &[1, 2, 3, 4]).unwrap();
    assert_eq!(out, vec![1, 2, 3, 4]);
}

#[test]
fn apply_set_empty_errors() {
    let bin = binary64();
    let set = PatchSet::new("e", "e");
    assert!(matches!(BinaryPatcher::new().apply_set(&set, &bin), Err(PatcherError::EmptyPatchSet)));
}

#[test]
fn apply_set_multi_patches_sorted_by_offset() {
    let bin = binary64();
    let mut set = PatchSet::new("s", "");
    set.add(Patch::new("p2", "", 8, vec![8, 9], vec![0xEE, 0xFF]));
    set.add(Patch::new("p1", "", 0, vec![0, 1], vec![0xAA, 0xBB]));
    let r = BinaryPatcher::new().apply_set(&set, &bin).unwrap();
    assert_eq!(r.patches_applied, 2);
    assert_eq!(&r.data[..2], &[0xAA, 0xBB]);
    assert_eq!(&r.data[8..10], &[0xEE, 0xFF]);
}

#[test]
fn checksum_after_deterministic() {
    let bin = binary64();
    let p = Patch::new("p", "", 0, vec![0, 1], vec![0xA, 0xB]);
    let a = BinaryPatcher::new().checksum_after(std::slice::from_ref(&p), &bin).unwrap();
    let b = BinaryPatcher::new().checksum_after(&[p], &bin).unwrap();
    assert_eq!(a, b);
}

#[test]
fn patch_op_display_and_changes_size() {
    assert_eq!(PatchOp::Overwrite.to_string(), "overwrite");
    assert_eq!(PatchOp::Insert.to_string(), "insert");
    assert_eq!(PatchOp::Remove.to_string(), "remove");
    assert_eq!(PatchOp::Nop.to_string(), "nop");
    assert!(PatchOp::Insert.changes_size());
    assert!(PatchOp::Remove.changes_size());
    assert!(!PatchOp::Overwrite.changes_size());
    assert!(!PatchOp::Nop.changes_size());
}

#[test]
fn patcher_fuzz_random_safe() {
    let mut g = Lcg::new(0xCAFE);
    let bin: Vec<u8> = (0u8..128).collect();
    for _ in 0..50 {
        let off = u64::from(g.byte()) % 200;
        let nlen = (g.byte() as usize) % 16;
        let p = Patch::new(format!("p{}", g.byte()), "", off, vec![], g.bytes(nlen));
        let _ = BinaryPatcher::new().force(true).no_validate().apply_one(&p, &bin);
    }
}

// ---------------------------------------------------------------------------
// Rollback
// ---------------------------------------------------------------------------

#[test]
fn create_rollback_empty_errors() {
    assert!(matches!(create_rollback(&[], &binary64()), Err(RollbackError::Empty)));
}

#[test]
fn rollback_full_round_trip() {
    let bin = binary64();
    let p = Patch::new("p1", "", 0, vec![0, 1, 2, 3], vec![0xAA, 0xBB, 0xCC, 0xDD]);
    let snap = create_rollback(std::slice::from_ref(&p), &bin).unwrap();
    let r = apply_patches(&[p], &bin).unwrap();
    let rb = PatchRollback::new();
    let restored = rb.apply_snapshot(&snap, &r.data).unwrap();
    assert_eq!(restored.data, bin);
}

#[test]
fn rollback_skips_already_rolled_back() {
    let bin = binary64();
    let p = Patch::new("p1", "", 0, vec![0, 1, 2, 3], vec![0xAA, 0xBB, 0xCC, 0xDD]);
    let snap = create_rollback(&[p], &bin).unwrap();
    let rb = PatchRollback::new();
    let r = rb.apply_snapshot(&snap, &bin).unwrap();
    assert_eq!(r.entries_applied, 0);
    assert_eq!(r.entries_skipped, 1);
}

#[test]
fn rollback_checksum_mismatch_detected() {
    let bin = binary64();
    let p = Patch::new("p1", "", 0, vec![0, 1, 2, 3], vec![0xAA, 0xBB, 0xCC, 0xDD]);
    let snap = create_rollback(std::slice::from_ref(&p), &bin).unwrap();
    // Apply patches AND modify extra byte so post-rollback hash won't match.
    let mut state = bin;
    state[0..4].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    state[10] = 0xFF;
    let rb = PatchRollback::new(); // verify on
    let err = rb.apply_snapshot(&snap, &state);
    assert!(matches!(err, Err(RollbackError::ChecksumMismatch { .. })));
}

#[test]
fn rollback_manager_snapshot_lifecycle() {
    let bin = binary64();
    let mut set = PatchSet::new("s", "");
    set.add(Patch::new("p", "", 0, vec![0, 1], vec![0xAA, 0xBB]));
    let mut rb = PatchRollback::new().verify_checksum(false);
    rb.create_snapshot(&set, &bin, "snap").unwrap();
    assert_eq!(rb.snapshot_count(), 1);
    assert!(rb.get_snapshot("snap").is_some());
    let ids = rb.snapshot_ids();
    assert!(ids.contains(&"snap"));
    rb.remove_snapshot("snap").unwrap();
    assert_eq!(rb.snapshot_count(), 0);
    rb.create_snapshot(&set, &bin, "snap2").unwrap();
    rb.clear();
    assert_eq!(rb.snapshot_count(), 0);
}

#[test]
fn rollback_entry_can_rollback_and_already_back() {
    let bin = binary64();
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
fn rollback_unknown_snapshot_id_errors() {
    let rb = PatchRollback::new();
    let err = rb.rollback("nope", &binary64());
    assert!(matches!(err, Err(RollbackError::UnknownPatchId(_))));
}

// ---------------------------------------------------------------------------
// Code cave
// ---------------------------------------------------------------------------

#[test]
fn code_cave_zero_min_size_errs() {
    assert!(matches!(CodeCaveScanner::new(0), Err(CaveError::InvalidMinSize)));
}

#[test]
fn code_cave_detect_format_too_small() {
    assert!(matches!(CodeCaveScanner::detect_format(&[0, 1]), Err(CaveError::TooSmall(_))));
}

#[test]
fn code_cave_detect_unknown_format() {
    let bin = vec![0xFFu8; 8];
    assert!(matches!(CodeCaveScanner::detect_format(&bin), Err(CaveError::UnknownFormat(_))));
}

#[test]
fn code_cave_detect_pe_mz() {
    let bin = b"MZthisispe...".to_vec();
    assert_eq!(CodeCaveScanner::detect_format(&bin).unwrap(), BinaryFormat::Pe);
}

#[test]
fn code_cave_fuzz_random_data_never_panics() {
    let mut g = Lcg::new(0xF00D);
    for _ in 0..40 {
        let len = (g.byte() as usize) % 256;
        let data = g.bytes(len);
        let _ = CodeCaveScanner::detect_format(&data);
        let _ = find_code_caves(&data, 16);
    }
}

#[test]
fn code_cave_binary_format_display() {
    assert_eq!(BinaryFormat::Pe.to_string(), "PE");
    assert_eq!(BinaryFormat::Elf.to_string(), "ELF");
}

// ---------------------------------------------------------------------------
// Hot patch
// ---------------------------------------------------------------------------

#[test]
fn hot_patch_apply_revert_round_trip() {
    let original = vec![0xE8, 0x10, 0x20, 0x30, 0x40, 0xAA];
    let w = InMemoryWriter::new(0x1000, original);
    let hp = HotPatcher::new(w);
    let p = Patch::new("x", "", 0, vec![0xE8, 0x10, 0x20, 0x30, 0x40], vec![0x90; 5]);
    hp.apply(&p, 0x1000).unwrap();
    assert_eq!(hp.live_count(), 1);
    assert_eq!(&hp.live_patches()[0].written_bytes[..], &[0x90; 5]);
    hp.revert("x").unwrap();
    assert_eq!(hp.live_count(), 0);
}

#[test]
fn hot_patch_double_apply_rejected() {
    let w = InMemoryWriter::new(0, vec![0xE8, 0x10, 0x20, 0x30, 0x40]);
    let hp = HotPatcher::new(w);
    let p = Patch::new("x", "", 0, vec![0xE8, 0x10, 0x20, 0x30, 0x40], vec![0x90; 5]);
    hp.apply(&p, 0).unwrap();
    assert!(matches!(hp.apply(&p, 0), Err(HotPatchError::AlreadyLive(_))));
}

#[test]
fn hot_patch_original_mismatch() {
    let w = InMemoryWriter::new(0, vec![0x00; 8]);
    let hp = HotPatcher::new(w);
    let p = Patch::new("x", "", 0, vec![0xE8; 5], vec![0x90; 5]);
    assert!(matches!(hp.apply(&p, 0), Err(HotPatchError::OriginalMismatch { .. })));
}

#[test]
fn hot_patch_writer_oob_propagates() {
    let w = InMemoryWriter::new(0x1000, vec![0u8; 4]);
    let hp = HotPatcher::new(w);
    let p = Patch::new("x", "", 0, vec![], vec![0x90; 16]);
    // read fails because address + len > buffer
    let err = hp.apply(&p, 0x1000);
    assert!(matches!(err, Err(HotPatchError::Writer { .. })));
}

#[test]
fn hot_patch_revert_unknown() {
    let w = InMemoryWriter::new(0, vec![0u8; 4]);
    let hp = HotPatcher::new(w);
    assert!(matches!(hp.revert("nope"), Err(HotPatchError::NotFound(_))));
}

#[test]
fn hot_patch_revert_all_two_patches() {
    let w = InMemoryWriter::new(0, vec![0xE8, 0x10, 0x20, 0x30, 0x40, 0xE8, 0x10, 0x20, 0x30, 0x40]);
    let hp = HotPatcher::new(w);
    let p1 = Patch::new("a", "", 0, vec![0xE8, 0x10, 0x20, 0x30, 0x40], vec![0x90; 5]);
    let p2 = Patch::new("b", "", 5, vec![0xE8, 0x10, 0x20, 0x30, 0x40], vec![0x90; 5]);
    hp.apply(&p1, 0).unwrap();
    hp.apply(&p2, 5).unwrap();
    let results = hp.revert_all();
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(std::result::Result::is_ok));
    assert_eq!(hp.live_count(), 0);
}

#[test]
fn hot_patch_thread_stress_send_sync() {
    let w = InMemoryWriter::new(0, vec![0u8; 4096]);
    let hp = Arc::new(HotPatcher::new(w));
    let mut handles = Vec::new();
    for tid in 0..4u64 {
        let hp_c = Arc::clone(&hp);
        handles.push(thread::spawn(move || {
            for i in 0..100u64 {
                let id = format!("t{tid}-{i}");
                let off = tid * 1000 + i * 4;
                let p = Patch::new(id.clone(), "", 0, vec![], vec![0xAA, 0xBB, 0xCC, 0xDD]);
                if hp_c.apply(&p, off).is_ok() {
                    let _ = hp_c.revert(&id);
                }
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
    assert_eq!(hp.live_count(), 0);
}

// ---------------------------------------------------------------------------
// Binary diff
// ---------------------------------------------------------------------------

#[test]
fn diff_identical_buffers_round_trip() {
    let b = vec![0xAAu8; 256];
    let d = diff(&b, &b);
    let out = patch(&b, &d).unwrap();
    assert_eq!(out, b);
}

#[test]
fn diff_completely_different_round_trip() {
    let old: Vec<u8> = (0u8..255).collect();
    let new: Vec<u8> = (0u8..255).rev().collect();
    let d = diff(&old, &new);
    assert_eq!(patch(&old, &d).unwrap(), new);
}

#[test]
fn diff_50_seeded_random_round_trips() {
    let mut g = Lcg::new(0x1234_5678_9ABC_DEF0);
    for _ in 0..50 {
        let len = ((g.byte() as usize) % 200) + 32;
        let old = g.bytes(len);
        let mut new = old.clone();
        // Mutate a few bytes
        let muts = (g.byte() as usize) % 4 + 1;
        for _ in 0..muts {
            let idx = (g.byte() as usize) % new.len();
            new[idx] = g.byte();
        }
        let blob = diff(&old, &new);
        let out = patch(&old, &blob).unwrap();
        assert_eq!(out, new);
    }
}

#[test]
fn diff_bad_magic_rejected() {
    let blob = vec![0u8; 256];
    assert!(matches!(BinaryDelta::decode(&blob), Err(DiffError::BadMagic)));
}

#[test]
fn diff_truncated_blob_rejected() {
    let blob = vec![b'R', b'R', b'D', b'F', 1, 0];
    assert!(matches!(BinaryDelta::decode(&blob), Err(DiffError::Truncated(_))));
}

#[test]
fn diff_unsupported_version_rejected() {
    let mut blob = vec![0u8; 90];
    blob[0..4].copy_from_slice(b"RRDF");
    blob[4..6].copy_from_slice(&99u16.to_le_bytes()); // bad version
    assert!(matches!(BinaryDelta::decode(&blob), Err(DiffError::UnsupportedVersion(_))));
}

#[test]
fn diff_source_hash_mismatch_detected() {
    let old = vec![1u8; 64];
    let new = vec![2u8; 64];
    let delta = build_delta(&old, &new, &DiffOptions::default());
    let wrong = vec![9u8; 64];
    assert!(matches!(delta.apply(&wrong), Err(DiffError::SourceHashMismatch)));
}

#[test]
fn diff_source_size_mismatch_detected() {
    let old = vec![1u8; 64];
    let new = vec![2u8; 64];
    let delta = build_delta(&old, &new, &DiffOptions::default());
    let wrong = vec![1u8; 60];
    assert!(matches!(delta.apply(&wrong), Err(DiffError::SourceHashMismatch)));
}

#[test]
fn diff_encode_decode_preserves_struct() {
    let old: Vec<u8> = (0u8..64).collect();
    let mut new = old.clone();
    new[10..20].fill(0x77);
    let delta = build_delta(&old, &new, &DiffOptions { min_match: 4, window: 64 });
    let blob = delta.encode();
    let decoded = BinaryDelta::decode(&blob).unwrap();
    assert_eq!(decoded, delta);
}

#[test]
fn diff_unknown_op_tag_rejected() {
    // craft minimal valid header, then 1 op with bad tag.
    let mut blob = Vec::new();
    blob.extend_from_slice(b"RRDF");
    blob.extend_from_slice(&1u16.to_le_bytes());
    blob.extend_from_slice(&0u64.to_le_bytes()); // old_size
    blob.extend_from_slice(&0u64.to_le_bytes()); // new_size
    blob.extend_from_slice(&[0u8; 32]); // old hash
    blob.extend_from_slice(&[0u8; 32]); // new hash
    blob.extend_from_slice(&1u32.to_le_bytes()); // op_count
    blob.push(0xEE); // bad tag
    assert!(matches!(BinaryDelta::decode(&blob), Err(DiffError::UnknownOpTag(_))));
}

#[test]
fn diff_insert_truncated_rejected() {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"RRDF");
    blob.extend_from_slice(&1u16.to_le_bytes());
    blob.extend_from_slice(&0u64.to_le_bytes());
    blob.extend_from_slice(&0u64.to_le_bytes());
    blob.extend_from_slice(&[0u8; 32]);
    blob.extend_from_slice(&[0u8; 32]);
    blob.extend_from_slice(&1u32.to_le_bytes());
    blob.push(0x02); // Insert
    blob.extend_from_slice(&100u64.to_le_bytes()); // claims 100 bytes, none follow
    assert!(matches!(BinaryDelta::decode(&blob), Err(DiffError::InsertTruncated { .. })));
}

#[test]
fn diff_op_display() {
    let c = DiffOp::Copy { src_offset: 0x10, length: 8 };
    let i = DiffOp::Insert { bytes: vec![1, 2, 3] };
    assert!(c.to_string().contains("Copy"));
    assert!(i.to_string().contains("Insert"));
}

#[test]
fn diff_fuzz_decoder_never_panics() {
    let mut g = Lcg::new(0x7777);
    for _ in 0..60 {
        let len = (g.byte() as usize) % 300;
        let blob = g.bytes(len);
        let _ = BinaryDelta::decode(&blob);
    }
}

#[test]
fn diff_empty_to_nonempty() {
    let old: Vec<u8> = vec![];
    let new: Vec<u8> = vec![1, 2, 3, 4, 5];
    let blob = diff(&old, &new);
    let out = patch(&old, &blob).unwrap();
    assert_eq!(out, new);
}

#[test]
fn diff_nonempty_to_empty() {
    let old: Vec<u8> = vec![1, 2, 3, 4, 5];
    let new: Vec<u8> = vec![];
    let blob = diff(&old, &new);
    let out = patch(&old, &blob).unwrap();
    assert_eq!(out, new);
}

// ---------------------------------------------------------------------------
// Hash/Eq pairs and Send/Sync
// ---------------------------------------------------------------------------

#[test]
fn patch_op_hash_eq_consistency_30_pairs() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let ops = [PatchOp::Overwrite, PatchOp::Insert, PatchOp::Remove, PatchOp::Nop];
    let mut count = 0;
    for a in &ops {
        for b in &ops {
            let mut ha = DefaultHasher::new();
            let mut hb = DefaultHasher::new();
            a.hash(&mut ha);
            b.hash(&mut hb);
            if a == b {
                assert_eq!(ha.finish(), hb.finish());
            }
            count += 1;
        }
    }
    assert!(count >= 16);
    // Plus ValidatorRule pairs
    let rules = [
        ValidatorRule::BoundsCheck, ValidatorRule::OriginalBytesCheck,
        ValidatorRule::NonEmptyPatchBytes, ValidatorRule::NotAlreadyApplied,
        ValidatorRule::NoOverlappingRanges, ValidatorRule::SameSizeRequirement,
    ];
    let mut set: HashSet<ValidatorRule> = HashSet::new();
    for r in rules { set.insert(r); }
    assert_eq!(set.len(), rules.len());
}

#[test]
fn patch_eq_when_fields_equal() {
    let a = Patch::new("id", "d", 0, vec![1], vec![2]);
    let b = Patch::new("id", "d", 0, vec![1], vec![2]);
    let c = Patch::new("id", "d", 1, vec![1], vec![2]);
    assert_eq!(a, b);
    assert_ne!(a, c);
}
