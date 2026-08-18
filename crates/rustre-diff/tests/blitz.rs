//! Exhaustive blitz test suite for `rustre-diff`.
//!
//! Targets the re-exported public API surface from lib.rs, structural, and
//! instruction_diff. Tests cover happy paths, edge cases, boundaries,
//! malformed/adversarial inputs, round-trips, and invariants.

use std::collections::HashMap;

use rustre_diff::{
    BasicBlock, BasicBlockDiffer, BinaryDiff, ChangeType, DiffEngine, DiffError, DiffFunction,
    DiffInstr, DiffReport, ExportEntry, FuncFingerprint, FuncMatch, FunctionDiff,
    InstrDiffKind, InstrDiffer, MatchKind, NamedBinaryDiff, StructuralDiffer, StructuralMatch,
    StructuralMatchKind, byte_histogram_similarity, combined_byte_similarity, diff_by_name,
    diff_exports, histogram_cosine, jaccard, lcs_similarity, ngram_jaccard_similarity, ratio,
    simple_hash,
};

fn fp(addr: u64, name: &str, bytes: &[u8]) -> FuncFingerprint {
    FuncFingerprint::new(addr, name.to_string(), bytes.to_vec())
}

// ============================================================================
// simple_hash
// ============================================================================

#[test]
fn simple_hash_empty_is_fnv_basis() {
    assert_eq!(simple_hash(&[]), 0xcbf2_9ce4_8422_2325);
}

#[test]
fn simple_hash_deterministic() {
    for s in &[b"" as &[u8], b"x", b"hello world", b"\x00\x01\x02\xff"] {
        assert_eq!(simple_hash(s), simple_hash(s));
    }
}

#[test]
fn simple_hash_single_byte_differs() {
    let a = simple_hash(&[0x00]);
    let b = simple_hash(&[0x01]);
    assert_ne!(a, b);
}

#[test]
fn simple_hash_order_sensitive() {
    assert_ne!(simple_hash(&[1, 2, 3]), simple_hash(&[3, 2, 1]));
}

#[test]
fn simple_hash_large_input_no_panic() {
    let big = vec![0xAB; 100_000];
    let _ = simple_hash(&big);
}

// ============================================================================
// lcs_similarity
// ============================================================================

#[test]
fn lcs_both_empty_is_one() {
    assert_eq!(lcs_similarity(&[], &[]), 1.0);
}

#[test]
fn lcs_one_empty_is_zero() {
    assert_eq!(lcs_similarity(&[1, 2, 3], &[]), 0.0);
    assert_eq!(lcs_similarity(&[], &[1, 2, 3]), 0.0);
}

#[test]
fn lcs_identical_short() {
    let v = vec![1u8, 2, 3, 4];
    assert!((lcs_similarity(&v, &v) - 1.0).abs() < 1e-9);
}

#[test]
fn lcs_disjoint_bytes() {
    let a = vec![0u8; 50];
    let b = vec![1u8; 50];
    assert_eq!(lcs_similarity(&a, &b), 0.0);
}

#[test]
fn lcs_truncation_scales_down() {
    // 1024-byte identical: should be 1.0 if it were full, but capped at 512
    // each → coverage = 0.5 → raw 1.0 * 0.5 = 0.5
    let a = vec![0x42u8; 1024];
    let b = vec![0x42u8; 1024];
    let s = lcs_similarity(&a, &b);
    assert!(s <= 1.0 && s >= 0.4 && s <= 0.6, "got {s}");
}

#[test]
fn lcs_score_in_range() {
    let a: Vec<u8> = (0u8..100).collect();
    let b: Vec<u8> = (50u8..150).collect();
    let s = lcs_similarity(&a, &b);
    assert!((0.0..=1.0).contains(&s));
}

#[test]
fn lcs_asymmetric_lengths() {
    let a = vec![0x90u8; 10];
    let b = vec![0x90u8; 100];
    let s = lcs_similarity(&a, &b);
    assert!(s > 0.0 && s < 1.0);
}

// ============================================================================
// FuncFingerprint
// ============================================================================

#[test]
fn fingerprint_fields_populated() {
    let f = fp(0x4000, "main", &[0x55, 0x89, 0xe5]);
    assert_eq!(f.address, 0x4000);
    assert_eq!(f.name, "main");
    assert_eq!(f.size, 3);
    assert_eq!(f.bytes, vec![0x55, 0x89, 0xe5]);
    assert_eq!(f.call_count, 0);
    assert_eq!(f.block_count, 0);
    assert_eq!(f.edge_count, 0);
}

#[test]
fn fingerprint_similarity_self_is_one() {
    let f = fp(0, "f", &[1, 2, 3, 4, 5]);
    assert_eq!(f.similarity(&f), 1.0);
}

#[test]
fn fingerprint_similarity_in_range() {
    let a = fp(0, "a", &[1, 2, 3, 4, 5, 6, 7, 8]);
    let b = fp(0, "b", &[1, 2, 3, 9, 9, 9, 7, 8]);
    let s = a.similarity(&b);
    assert!((0.0..=1.0).contains(&s));
}

#[test]
fn fingerprint_similarity_both_empty() {
    let a = fp(0, "a", &[]);
    let b = fp(0, "b", &[]);
    assert_eq!(a.similarity(&b), 1.0);
}

#[test]
fn fingerprint_display_contains_meta() {
    let f = fp(0x4321, "func", &[0; 7]);
    let s = f.to_string();
    assert!(s.contains("func"));
    assert!(s.contains("0x4321"));
    assert!(s.contains("7"));
}

#[test]
fn fingerprint_serde_roundtrip() {
    let f = fp(0x1000, "foo", &[1, 2, 3]);
    let j = serde_json::to_string(&f).unwrap();
    let d: FuncFingerprint = serde_json::from_str(&j).unwrap();
    assert_eq!(d.address, f.address);
    assert_eq!(d.name, f.name);
    assert_eq!(d.bytes, f.bytes);
    assert_eq!(d.hash, f.hash);
}

// ============================================================================
// MatchKind / FuncMatch
// ============================================================================

#[test]
fn matchkind_display_all_variants() {
    assert_eq!(MatchKind::Identical.to_string(), "Identical");
    assert_eq!(MatchKind::Similar.to_string(), "Similar");
    assert_eq!(MatchKind::Added.to_string(), "Added");
    assert_eq!(MatchKind::Removed.to_string(), "Removed");
    assert_eq!(MatchKind::Renamed.to_string(), "Renamed");
}

#[test]
fn matchkind_eq_hash() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(MatchKind::Identical);
    s.insert(MatchKind::Identical);
    assert_eq!(s.len(), 1);
    s.insert(MatchKind::Added);
    assert_eq!(s.len(), 2);
}

#[test]
fn funcmatch_identical_invariants() {
    let a = fp(0, "f", &[1]);
    let b = fp(0, "f", &[1]);
    let m = FuncMatch::identical(a, b);
    assert_eq!(m.kind, MatchKind::Identical);
    assert_eq!(m.similarity, 1.0);
    assert_eq!(m.confidence, 100);
    assert!(!m.is_changed());
}

#[test]
fn funcmatch_similar_confidence_rounded() {
    let a = fp(0, "f", &[1]);
    let b = fp(0, "f", &[2]);
    let m = FuncMatch::similar(a, b, 0.756);
    assert_eq!(m.confidence, 76);
    assert!(m.is_changed());
}

#[test]
fn funcmatch_similarity_clamped_for_confidence() {
    let a = fp(0, "f", &[1]);
    let b = fp(0, "f", &[2]);
    let m = FuncMatch::similar(a, b, 5.0);
    assert_eq!(m.confidence, 100);

    let a2 = fp(0, "f", &[1]);
    let b2 = fp(0, "f", &[2]);
    let m2 = FuncMatch::similar(a2, b2, -2.0);
    assert_eq!(m2.confidence, 0);
}

#[test]
fn funcmatch_renamed() {
    let a = fp(0, "old", &[1, 2, 3]);
    let b = fp(0, "new", &[1, 2, 3]);
    let m = FuncMatch::renamed(a, b, 0.95);
    assert_eq!(m.kind, MatchKind::Renamed);
    assert_eq!(m.confidence, 95);
    assert!(m.is_changed());
}

#[test]
fn funcmatch_added_removed_have_none_side() {
    let f = fp(0, "f", &[1]);
    let added = FuncMatch::added(f.clone());
    assert!(added.primary.is_none());
    assert!(added.secondary.is_some());
    assert!(added.is_changed());
    let removed = FuncMatch::removed(f);
    assert!(removed.primary.is_some());
    assert!(removed.secondary.is_none());
    assert!(removed.is_changed());
}

#[test]
fn funcmatch_display_handles_none_side() {
    let f = fp(0, "only", &[1]);
    let s = FuncMatch::added(f).to_string();
    assert!(s.contains("only"));
    assert!(s.contains("<none>"));
}

// ============================================================================
// BinaryDiff
// ============================================================================

#[test]
fn binarydiff_new_zero_counts() {
    let d = BinaryDiff::new("a".into(), "b".into());
    assert_eq!(d.identical_count(), 0);
    assert_eq!(d.added_count(), 0);
    assert_eq!(d.removed_count(), 0);
    assert_eq!(d.changed_count(), 0);
    assert_eq!(d.similarity_ratio(), 0.0);
}

#[test]
fn binarydiff_similarity_ratio_averages_paired() {
    let mut d = BinaryDiff::new("a".into(), "b".into());
    let a1 = fp(0, "f", &[1]);
    let b1 = fp(0, "f", &[1]);
    let a2 = fp(0, "g", &[1]);
    let b2 = fp(0, "g", &[2]);
    d.matches.push(FuncMatch::identical(a1, b1));
    d.matches.push(FuncMatch::similar(a2, b2, 0.6));
    let expected = (1.0 + 0.6) / 2.0;
    assert!((d.similarity_ratio() - expected).abs() < 1e-9);
}

#[test]
fn binarydiff_added_removed_excluded_from_ratio() {
    let mut d = BinaryDiff::new("a".into(), "b".into());
    d.matches.push(FuncMatch::added(fp(0, "x", &[1])));
    d.matches.push(FuncMatch::removed(fp(0, "y", &[2])));
    // No paired matches → 0.0
    assert_eq!(d.similarity_ratio(), 0.0);
}

#[test]
fn binarydiff_display_format() {
    let d = BinaryDiff::new("old.bin".into(), "new.bin".into());
    let s = d.to_string();
    assert!(s.contains("old.bin"));
    assert!(s.contains("new.bin"));
}

#[test]
fn binarydiff_serde_roundtrip() {
    let mut d = BinaryDiff::new("a".into(), "b".into());
    d.matches.push(FuncMatch::added(fp(0, "x", &[1, 2, 3])));
    let j = serde_json::to_string(&d).unwrap();
    let d2: BinaryDiff = serde_json::from_str(&j).unwrap();
    assert_eq!(d2.added_count(), 1);
}

// ============================================================================
// DiffEngine
// ============================================================================

#[test]
fn diffengine_both_empty_errors() {
    let eng = DiffEngine::default();
    let r = eng.diff(vec![], &vec![], "a".into(), "b".into());
    assert!(matches!(r, Err(DiffError::EmptyInput(_))));
}

#[test]
fn diffengine_only_a_empty() {
    let eng = DiffEngine::default();
    let r = eng
        .diff(vec![], &vec![fp(0, "x", &[1])], "a".into(), "b".into())
        .unwrap();
    assert_eq!(r.added_count(), 1);
    assert_eq!(r.removed_count(), 0);
    assert_eq!(r.total_functions_a, 0);
    assert_eq!(r.total_functions_b, 1);
}

#[test]
fn diffengine_only_b_empty() {
    let eng = DiffEngine::default();
    let r = eng
        .diff(vec![fp(0, "x", &[1])], &vec![], "a".into(), "b".into())
        .unwrap();
    assert_eq!(r.removed_count(), 1);
    assert_eq!(r.added_count(), 0);
}

#[test]
fn diffengine_all_identical() {
    let eng = DiffEngine::default();
    let a = vec![
        fp(0x1000, "f", &[1, 2, 3]),
        fp(0x2000, "g", &[4, 5, 6]),
    ];
    let b = a.clone();
    let r = eng.diff(a, &b, "a".into(), "b".into()).unwrap();
    assert_eq!(r.identical_count(), 2);
    assert_eq!(r.changed_count(), 0);
    assert_eq!(r.added_count(), 0);
    assert_eq!(r.removed_count(), 0);
}

#[test]
fn diffengine_renamed_pair_detected() {
    let eng = DiffEngine::new(0.5);
    // Same bytes (hash match) but different names → identical hash takes precedence.
    let a = vec![fp(0x1000, "old_name", &[1; 50])];
    let b = vec![fp(0x2000, "new_name", &[1; 50])];
    let r = eng.diff(a, &b, "a".into(), "b".into()).unwrap();
    // Hash matches first → Identical (since byte-identical), even though names differ.
    assert_eq!(r.identical_count(), 1);
}

#[test]
fn diffengine_renamed_with_small_change() {
    // Different bytes (no hash collision) but very similar + different name → Renamed.
    let eng = DiffEngine::new(0.5);
    let bytes_a: Vec<u8> = (0u8..50).collect();
    let mut bytes_b = bytes_a.clone();
    bytes_b[49] = 0xFF;
    let a = vec![fp(0x1000, "old_name", &bytes_a)];
    let b = vec![fp(0x2000, "new_name", &bytes_b)];
    let r = eng.diff(a, &b, "a".into(), "b".into()).unwrap();
    assert_eq!(r.matches.len(), 1);
    // similarity should be > 0.9 → renamed
    let m = &r.matches[0];
    assert!(matches!(m.kind, MatchKind::Renamed | MatchKind::Similar));
}

#[test]
fn diffengine_duplicate_hash_only_pairs_once() {
    let eng = DiffEngine::default();
    let a = vec![
        fp(0x1000, "f1", &[0xAA]),
        fp(0x1100, "f2", &[0xAA]),
    ];
    let b = vec![fp(0x2000, "g", &[0xAA])];
    let r = eng.diff(a, &b, "a".into(), "b".into()).unwrap();
    assert_eq!(r.identical_count(), 1);
    // The other must be removed (or matched fuzzily)
    let total = r.identical_count() + r.changed_count() + r.removed_count() + r.added_count();
    assert_eq!(total, r.matches.len());
}

#[test]
fn diffengine_totals_match_input() {
    let eng = DiffEngine::default();
    let a: Vec<_> = (0..5)
        .map(|i| fp(0x1000 + i, &format!("a{i}"), &[i as u8; 3]))
        .collect();
    let b: Vec<_> = (0..7)
        .map(|i| fp(0x2000 + i, &format!("b{i}"), &[i as u8; 3]))
        .collect();
    let r = eng.diff(a, &b, "a".into(), "b".into()).unwrap();
    assert_eq!(r.total_functions_a, 5);
    assert_eq!(r.total_functions_b, 7);
}

#[test]
fn diffengine_debug_includes_threshold() {
    let eng = DiffEngine::new(0.42);
    let s = format!("{eng:?}");
    assert!(s.contains("0.42"));
}

#[test]
fn diffengine_default_threshold_06() {
    let s = format!("{:?}", DiffEngine::default());
    assert!(s.contains("0.6"));
}

// ============================================================================
// ChangeType / FunctionDiff
// ============================================================================

#[test]
fn changetype_display() {
    assert_eq!(ChangeType::Added.to_string(), "Added");
    assert_eq!(ChangeType::Removed.to_string(), "Removed");
    assert_eq!(ChangeType::Unchanged.to_string(), "Unchanged");
    let s = ChangeType::Modified { similarity: 0.5 }.to_string();
    assert!(s.contains("Modified"));
    assert!(s.contains("50"));
}

#[test]
fn changetype_eq() {
    assert_eq!(ChangeType::Added, ChangeType::Added);
    assert_ne!(ChangeType::Added, ChangeType::Removed);
    assert_eq!(
        ChangeType::Modified { similarity: 0.5 },
        ChangeType::Modified { similarity: 0.5 }
    );
}

#[test]
fn functiondiff_display_name_prefers_a() {
    let d = FunctionDiff {
        addr_a: Some(0x1000),
        addr_b: Some(0x2000),
        name_a: Some("a_name".into()),
        name_b: Some("b_name".into()),
        similarity: 1.0,
        change_type: ChangeType::Unchanged,
    };
    assert_eq!(d.display_name(), "a_name");
}

#[test]
fn functiondiff_display_name_falls_back_to_b() {
    let d = FunctionDiff {
        addr_a: None,
        addr_b: None,
        name_a: None,
        name_b: Some("b".into()),
        similarity: 0.0,
        change_type: ChangeType::Added,
    };
    assert_eq!(d.display_name(), "b");
}

#[test]
fn functiondiff_display_name_unknown() {
    let d = FunctionDiff {
        addr_a: None,
        addr_b: None,
        name_a: None,
        name_b: None,
        similarity: 0.0,
        change_type: ChangeType::Removed,
    };
    assert_eq!(d.display_name(), "<unknown>");
}

// ============================================================================
// byte_histogram_similarity / ngram_jaccard_similarity / combined
// ============================================================================

#[test]
fn histogram_both_empty_is_one() {
    assert_eq!(byte_histogram_similarity(&[], &[]), 1.0);
}

#[test]
fn histogram_one_empty_is_zero() {
    assert_eq!(byte_histogram_similarity(&[1], &[]), 0.0);
    assert_eq!(byte_histogram_similarity(&[], &[1]), 0.0);
}

#[test]
fn histogram_identical_is_one() {
    let v = vec![1u8, 2, 3, 4, 5];
    assert!((byte_histogram_similarity(&v, &v) - 1.0).abs() < 1e-5);
}

#[test]
fn histogram_disjoint_is_zero() {
    let a = vec![0u8; 50];
    let b = vec![1u8; 50];
    assert!(byte_histogram_similarity(&a, &b) < 1e-5);
}

#[test]
fn histogram_permutation_invariant() {
    let a = vec![1u8, 2, 3, 4];
    let b = vec![4u8, 3, 2, 1];
    let s = byte_histogram_similarity(&a, &b);
    assert!((s - 1.0).abs() < 1e-5);
}

#[test]
fn ngram_both_empty_is_one() {
    assert_eq!(ngram_jaccard_similarity(&[], &[], 4), 1.0);
}

#[test]
fn ngram_one_empty_is_zero() {
    assert_eq!(ngram_jaccard_similarity(&[1, 2, 3, 4], &[], 4), 0.0);
}

#[test]
fn ngram_zero_n_returns_zero() {
    assert_eq!(ngram_jaccard_similarity(&[1, 2, 3], &[1, 2, 3], 0), 0.0);
}

#[test]
fn ngram_input_smaller_than_n_returns_one_when_both_empty_sets() {
    // bytes shorter than n → both produce empty hashsets → 1.0
    let a = vec![1u8, 2];
    let b = vec![9u8, 9];
    let s = ngram_jaccard_similarity(&a, &b, 4);
    assert_eq!(s, 1.0);
}

#[test]
fn ngram_identical_is_one() {
    let v: Vec<u8> = (0u8..32).collect();
    assert_eq!(ngram_jaccard_similarity(&v, &v, 4), 1.0);
}

#[test]
fn ngram_n_capped_at_8() {
    let v: Vec<u8> = (0u8..32).collect();
    // n=100 should be treated as 8, not panic
    let s = ngram_jaccard_similarity(&v, &v, 100);
    assert_eq!(s, 1.0);
}

#[test]
fn combined_byte_similarity_identical() {
    let v: Vec<u8> = (0u8..32).collect();
    let s = combined_byte_similarity(&v, &v);
    assert!(s > 0.99);
}

#[test]
fn combined_byte_similarity_disjoint() {
    let a = vec![0u8; 50];
    let b = vec![1u8; 50];
    let s = combined_byte_similarity(&a, &b);
    assert!(s < 0.5);
}

// ============================================================================
// diff_by_name / NamedBinaryDiff
// ============================================================================

#[test]
fn diff_by_name_empty_inputs() {
    let a: HashMap<String, Vec<u8>> = HashMap::new();
    let b: HashMap<String, Vec<u8>> = HashMap::new();
    let r = diff_by_name(&a, &b);
    assert_eq!(r.functions.len(), 0);
    assert_eq!(r.overall_similarity, 0.0);
}

#[test]
fn diff_by_name_classifies_correctly() {
    let mut a = HashMap::new();
    a.insert("keep".to_string(), vec![1u8; 32]);
    a.insert("modify".to_string(), vec![2u8; 32]);
    a.insert("remove".to_string(), vec![3u8; 32]);
    let mut b = HashMap::new();
    b.insert("keep".to_string(), vec![1u8; 32]);
    b.insert("modify".to_string(), vec![4u8; 32]);
    b.insert("add".to_string(), vec![5u8; 32]);
    let r = diff_by_name(&a, &b);
    assert_eq!(r.added_count(), 1);
    assert_eq!(r.removed_count(), 1);
    assert_eq!(r.unchanged_count(), 1);
    assert_eq!(r.modified_count(), 1);
}

#[test]
fn diff_by_name_sort_order_unchanged_first() {
    let mut a = HashMap::new();
    a.insert("k".to_string(), vec![1u8; 32]);
    a.insert("m".to_string(), vec![2u8; 32]);
    let mut b = HashMap::new();
    b.insert("k".to_string(), vec![1u8; 32]);
    b.insert("m".to_string(), vec![9u8; 32]);
    b.insert("a".to_string(), vec![3u8; 32]);
    let r = diff_by_name(&a, &b);
    // unchanged should come first
    assert_eq!(r.functions[0].change_type, ChangeType::Unchanged);
}

#[test]
fn diff_by_name_overall_in_range() {
    let mut a = HashMap::new();
    a.insert("f".to_string(), vec![1u8; 32]);
    let mut b = HashMap::new();
    b.insert("f".to_string(), vec![1u8; 32]);
    let r = diff_by_name(&a, &b);
    assert!(r.overall_similarity > 0.99);
}

// ============================================================================
// ExportEntry / ExportDiff / diff_exports
// ============================================================================

fn ee(name: Option<&str>, ord: u32, addr: u64) -> ExportEntry {
    ExportEntry {
        name: name.map(String::from),
        ordinal: ord,
        address: addr,
    }
}

#[test]
fn diff_exports_empty() {
    let d = diff_exports(&[], &[]);
    assert!(d.is_clean());
    assert_eq!(d.added.len(), 0);
    assert_eq!(d.removed.len(), 0);
}

#[test]
fn diff_exports_added() {
    let d = diff_exports(&[], &[ee(Some("f"), 1, 0x1000)]);
    assert_eq!(d.added.len(), 1);
    assert!(!d.is_clean());
}

#[test]
fn diff_exports_removed() {
    let d = diff_exports(&[ee(Some("f"), 1, 0x1000)], &[]);
    assert_eq!(d.removed.len(), 1);
}

#[test]
fn diff_exports_moved_when_address_changes() {
    let a = vec![ee(Some("f"), 1, 0x1000)];
    let b = vec![ee(Some("f"), 1, 0x2000)];
    let d = diff_exports(&a, &b);
    assert_eq!(d.moved.len(), 1);
    assert_eq!(d.unchanged.len(), 0);
}

#[test]
fn diff_exports_unchanged_when_same() {
    let v = vec![ee(Some("f"), 1, 0x1000)];
    let d = diff_exports(&v, &v);
    assert_eq!(d.unchanged.len(), 1);
    assert!(d.is_clean());
}

#[test]
fn diff_exports_anonymous_keyed_by_ordinal() {
    let a = vec![ee(None, 42, 0x1000)];
    let b = vec![ee(None, 42, 0x2000)];
    let d = diff_exports(&a, &b);
    assert_eq!(d.moved.len(), 1);
}

#[test]
fn diff_exports_display_includes_counts() {
    let a = vec![ee(Some("a"), 1, 0x1000), ee(Some("b"), 2, 0x2000)];
    let b = vec![ee(Some("a"), 1, 0x1000), ee(Some("c"), 3, 0x3000)];
    let d = diff_exports(&a, &b);
    let s = d.to_string();
    assert!(s.contains("ExportDiff"));
}

#[test]
fn diff_exports_sorted_by_ordinal() {
    let a = vec![
        ee(Some("a"), 3, 0x1000),
        ee(Some("b"), 1, 0x2000),
        ee(Some("c"), 2, 0x3000),
    ];
    let d = diff_exports(&a, &[]);
    let ords: Vec<u32> = d.removed.iter().map(|e| e.ordinal).collect();
    assert_eq!(ords, vec![1, 2, 3]);
}

// ============================================================================
// structural: ratio / histogram_cosine / jaccard (re-exports)
// ============================================================================

#[test]
fn ratio_both_zero_is_one() {
    assert_eq!(ratio(0, 0), 1.0);
}

#[test]
fn ratio_asymmetric() {
    assert!((ratio(2, 8) - 0.25).abs() < 1e-12);
    assert!((ratio(8, 2) - 0.25).abs() < 1e-12);
}

#[test]
fn histogram_cosine_via_export() {
    use std::collections::BTreeMap;
    let mut a = BTreeMap::new();
    a.insert("mov".to_string(), 2usize);
    let b = a.clone();
    let s = histogram_cosine(&a, &b);
    assert!((s - 1.0).abs() < 1e-12);
}

#[test]
fn jaccard_via_export() {
    let a = vec![1u64, 2, 3];
    let b = vec![2u64, 3, 4];
    let s = jaccard(&a, &b);
    // intersection {2,3}=2, union {1,2,3,4}=4 → 0.5
    assert!((s - 0.5).abs() < 1e-12);
}

// ============================================================================
// DiffFunction / StructuralDiffer / DiffReport
// ============================================================================

fn dfn(name: &str, addr: u64, bb: usize, edges: usize, mn: &[&str], calls: Vec<u64>) -> DiffFunction {
    let m: Vec<String> = mn.iter().map(|s| s.to_string()).collect();
    DiffFunction::new(name, addr, bb, edges, &m, calls)
}

#[test]
fn difffunction_md_index_deterministic() {
    let f = dfn("f", 0x1000, 4, 5, &["mov"], vec![]);
    assert_eq!(f.md_index(), f.md_index());
}

#[test]
fn difffunction_md_index_ignores_name_addr_mnemonic() {
    let a = dfn("a", 0x1000, 4, 5, &["mov"], vec![]);
    let b = dfn("zz", 0x9999, 4, 5, &["xor"], vec![]);
    assert_eq!(a.md_index(), b.md_index());
}

#[test]
fn difffunction_cyclomatic_basic() {
    let f = dfn("f", 0, 4, 5, &[], vec![]);
    assert_eq!(f.cyclomatic_complexity(), 3);
}

#[test]
fn difffunction_cyclomatic_floor_one() {
    let f = dfn("f", 0, 50, 0, &[], vec![]);
    assert_eq!(f.cyclomatic_complexity(), 1);
}

#[test]
fn difffunction_with_degrees_attaches() {
    let f = dfn("f", 0, 3, 3, &[], vec![]).with_degrees(vec![1, 1, 1], vec![1, 1, 1]);
    assert_eq!(f.in_degrees, vec![1, 1, 1]);
    assert_eq!(f.out_degrees, vec![1, 1, 1]);
}

#[test]
fn difffunction_instruction_count() {
    let f = dfn("f", 0, 1, 0, &["mov", "mov", "ret"], vec![]);
    assert_eq!(f.instruction_count(), 3);
}

#[test]
fn difffunction_similarity_self_is_one() {
    let f = dfn("f", 0, 4, 5, &["mov", "call"], vec![0x10]);
    assert!((f.similarity(&f) - 1.0).abs() < 1e-9);
}

#[test]
fn difffunction_similarity_in_unit_range() {
    let a = dfn("a", 0, 4, 5, &["mov", "add"], vec![1]);
    let b = dfn("b", 0, 9, 14, &["sub", "xor"], vec![2, 3]);
    let s = a.similarity(&b);
    assert!((0.0..=1.0).contains(&s));
}

#[test]
fn structuraldiffer_threshold_clamped_high() {
    let d = StructuralDiffer::new(2.0);
    assert!((d.fuzzy_threshold() - 1.0).abs() < 1e-12);
}

#[test]
fn structuraldiffer_threshold_clamped_low() {
    let d = StructuralDiffer::new(-1.0);
    assert!(d.fuzzy_threshold().abs() < 1e-12);
}

#[test]
fn structuraldiffer_empty_inputs() {
    let r = StructuralDiffer::default().diff(&[], &[]);
    assert_eq!(r.matches.len(), 0);
    assert_eq!(r.total_old, 0);
    assert_eq!(r.total_new, 0);
    assert_eq!(r.similarity_ratio(), 0.0);
}

#[test]
fn structuraldiffer_identical_sets() {
    let set = vec![dfn("f", 0x1000, 4, 5, &["mov"], vec![])];
    let r = StructuralDiffer::default().diff(&set, &set);
    assert_eq!(r.identical_count(), 1);
    assert!((r.similarity_ratio() - 1.0).abs() < 1e-9);
}

#[test]
fn structuraldiffer_added_only() {
    let r = StructuralDiffer::default()
        .diff(&[], &[dfn("x", 0, 1, 0, &["ret"], vec![])]);
    assert_eq!(r.added_count(), 1);
    assert_eq!(r.matched_count(), 0);
}

#[test]
fn structuraldiffer_removed_only() {
    let r = StructuralDiffer::default()
        .diff(&[dfn("x", 0, 1, 0, &["ret"], vec![])], &[]);
    assert_eq!(r.removed_count(), 1);
    assert_eq!(r.matched_count(), 0);
}

#[test]
fn structuraldiffer_name_match_changed_body() {
    let old = vec![dfn("compute", 0x1000, 4, 5, &["mov"], vec![])];
    let new = vec![dfn("compute", 0x2000, 99, 200, &["xor"], vec![])];
    // High fuzzy threshold prevents fuzzy/exact match; name match still applies.
    let r = StructuralDiffer::new(0.99).diff(&old, &new);
    assert_eq!(r.matched_count(), 1);
    assert_eq!(r.matches[0].kind, StructuralMatchKind::Name);
}

#[test]
fn structuralmatch_added_removed() {
    let f = dfn("f", 0, 1, 0, &["ret"], vec![]);
    assert!(StructuralMatch::added(f.clone()).old.is_none());
    assert!(StructuralMatch::removed(f).new.is_none());
}

#[test]
fn structuralmatch_identical_predicate() {
    let f = dfn("f", 0, 4, 5, &["mov"], vec![]);
    let m = StructuralMatch::paired(f.clone(), f.clone(), StructuralMatchKind::ExactHash, 1.0);
    assert!(m.is_identical());
    assert!(!m.is_changed());
}

#[test]
fn structuralmatch_changed_predicate() {
    let f = dfn("f", 0, 4, 5, &["mov"], vec![]);
    let m = StructuralMatch::paired(f.clone(), f, StructuralMatchKind::Fuzzy, 0.7);
    assert!(m.is_changed());
    assert!(!m.is_identical());
}

#[test]
fn structuralmatchkind_display() {
    assert_eq!(StructuralMatchKind::ExactHash.to_string(), "ExactHash");
    assert_eq!(StructuralMatchKind::Name.to_string(), "Name");
    assert_eq!(StructuralMatchKind::Fuzzy.to_string(), "Fuzzy");
    assert_eq!(StructuralMatchKind::Added.to_string(), "Added");
    assert_eq!(StructuralMatchKind::Removed.to_string(), "Removed");
}

#[test]
fn diffreport_generate_html_contains_keywords() {
    let f = dfn("f", 0, 1, 0, &["ret"], vec![]);
    let r = StructuralDiffer::default().diff(&[f.clone()], &[f]);
    let html = r.generate_html();
    assert!(html.contains("<html>"));
    assert!(html.contains("</html>"));
    assert!(html.contains("Identical"));
}

#[test]
fn diffreport_generate_json_has_summary() {
    let f = dfn("f", 0, 1, 0, &["ret"], vec![]);
    let r = StructuralDiffer::default().diff(&[f.clone()], &[f]);
    let j = r.generate_json();
    assert!(j.get("summary").is_some());
    assert!(j.get("matches").is_some());
}

#[test]
fn diffreport_serde_roundtrip() {
    let f = dfn("f", 0, 1, 0, &["ret"], vec![]);
    let r = StructuralDiffer::default().diff(&[f.clone()], &[f]);
    let s = serde_json::to_string(&r).unwrap();
    let d: DiffReport = serde_json::from_str(&s).unwrap();
    assert_eq!(d.matches.len(), r.matches.len());
}

#[test]
fn difffunction_serde_roundtrip() {
    let f = dfn("foo", 0x1000, 4, 5, &["mov"], vec![0x10]);
    let s = serde_json::to_string(&f).unwrap();
    let d: DiffFunction = serde_json::from_str(&s).unwrap();
    assert_eq!(d, f);
}

// ============================================================================
// InstrDiffer / DiffInstr / InstrDiffKind
// ============================================================================

fn instr(off: u64, mnem: &str, ops: &str) -> DiffInstr {
    DiffInstr::new(off, mnem, ops, vec![0x90])
}

#[test]
fn diffinstr_text_with_operands() {
    let i = instr(0, "mov", "rax, rbx");
    assert_eq!(i.text(), "mov rax, rbx");
}

#[test]
fn diffinstr_text_no_operands() {
    let i = instr(0, "ret", "");
    assert_eq!(i.text(), "ret");
}

#[test]
fn diffinstr_is_call() {
    assert!(instr(0, "call", "0x1000").is_call());
    assert!(!instr(0, "jmp", "0x1000").is_call());
}

#[test]
fn diffinstr_is_branch_variants() {
    for m in ["jmp", "je", "jne", "jz", "jnz", "jl", "jg", "ja", "jb"] {
        assert!(instr(0, m, "x").is_branch(), "{m} should be branch");
    }
    assert!(!instr(0, "mov", "x").is_branch());
    assert!(!instr(0, "call", "x").is_branch());
}

#[test]
fn diffinstr_is_return() {
    assert!(instr(0, "ret", "").is_return());
    assert!(instr(0, "retn", "").is_return());
    assert!(!instr(0, "mov", "x").is_return());
}

#[test]
fn diffinstr_size_derived_from_bytes() {
    let i = DiffInstr::new(0, "x", "", vec![0x90, 0x90, 0x90]);
    assert_eq!(i.size, 3);
}

#[test]
fn instrdiffer_empty_inputs() {
    let d = InstrDiffer::new().diff("f", &[], &[]);
    assert_eq!(d.total(), 0);
    assert_eq!(d.similarity(), 1.0);
}

#[test]
fn instrdiffer_identical_sequence() {
    let v = vec![instr(0, "mov", "a"), instr(1, "ret", "")];
    let d = InstrDiffer::new().diff("f", &v, &v);
    assert_eq!(d.unchanged_count(), 2);
    assert_eq!(d.added_count(), 0);
    assert_eq!(d.removed_count(), 0);
    assert_eq!(d.changed_count(), 0);
    assert!((d.similarity() - 1.0).abs() < 1e-9);
}

#[test]
fn instrdiffer_all_added() {
    let v = vec![instr(0, "mov", "a")];
    let d = InstrDiffer::new().diff("f", &[], &v);
    assert_eq!(d.added_count(), 1);
}

#[test]
fn instrdiffer_all_removed() {
    let v = vec![instr(0, "mov", "a")];
    let d = InstrDiffer::new().diff("f", &v, &[]);
    assert_eq!(d.removed_count(), 1);
}

#[test]
fn instrdiffer_operands_changed() {
    let a = vec![instr(0, "mov", "rax, 1")];
    let b = vec![instr(0, "mov", "rax, 2")];
    let d = InstrDiffer::new().diff("f", &a, &b);
    assert_eq!(d.changed_count(), 1);
    let ce = d.changed_entries();
    assert_eq!(ce.len(), 1);
    assert_eq!(ce[0].kind, InstrDiffKind::OperandsChanged);
}

#[test]
fn instrdiffer_mnemonic_changed() {
    let a = vec![instr(0, "mov", "rax")];
    let b = vec![instr(0, "xor", "rax")];
    let d = InstrDiffer::new().diff("f", &a, &b);
    // Different mnemonics → LCS sees them as add+remove (not "changed").
    assert_eq!(d.added_count() + d.removed_count(), 2);
    assert_eq!(d.unchanged_count(), 0);
}

#[test]
fn instrdiff_similarity_when_empty_is_one() {
    let d = InstrDiffer::new().diff("f", &[], &[]);
    assert_eq!(d.similarity(), 1.0);
}

#[test]
fn instrdiff_display_format() {
    let v = vec![instr(0, "ret", "")];
    let d = InstrDiffer::new().diff("myfunc", &v, &v);
    let s = d.to_string();
    assert!(s.contains("myfunc"));
    assert!(s.contains("Summary"));
}

#[test]
fn instrdiffkind_display() {
    assert_eq!(InstrDiffKind::Unchanged.to_string(), "Unchanged");
    assert_eq!(InstrDiffKind::Added.to_string(), "Added");
    assert_eq!(InstrDiffKind::Removed.to_string(), "Removed");
    assert_eq!(InstrDiffKind::MnemonicChanged.to_string(), "MnemonicChanged");
    assert_eq!(InstrDiffKind::OperandsChanged.to_string(), "OperandsChanged");
    assert_eq!(InstrDiffKind::FullyChanged.to_string(), "FullyChanged");
}

#[test]
fn operand_changes_detects_per_operand_diff() {
    use rustre_diff::operand_changes;
    let a = instr(0, "mov", "rax, 1");
    let b = instr(0, "mov", "rbx, 1");
    let ch = operand_changes(&a, &b);
    assert_eq!(ch.len(), 1);
    assert_eq!(ch[0].index, 0);
    assert_eq!(ch[0].old, "rax");
    assert_eq!(ch[0].new, "rbx");
}

#[test]
fn operand_changes_handles_different_arity() {
    use rustre_diff::operand_changes;
    let a = instr(0, "x", "a");
    let b = instr(0, "x", "a, b");
    let ch = operand_changes(&a, &b);
    assert_eq!(ch.len(), 1);
    assert_eq!(ch[0].index, 1);
    assert_eq!(ch[0].old, "");
    assert_eq!(ch[0].new, "b");
}

#[test]
fn operand_changes_no_diff() {
    use rustre_diff::operand_changes;
    let a = instr(0, "mov", "rax, 1");
    let b = instr(0, "mov", "rax, 1");
    assert_eq!(operand_changes(&a, &b).len(), 0);
}

// ============================================================================
// BasicBlock / BasicBlockDiffer (re-exports — exercise dead-code surface)
// ============================================================================

#[test]
fn basicblock_construct_and_use() {
    // Use the publicly re-exported types to keep them from being dead-code.
    let _diff_using_basicblock_re_export: Option<BasicBlock> = None;
    // Ensure the differ type can be referenced.
    let _ = std::mem::size_of::<BasicBlockDiffer>();
}

// ============================================================================
// DiffError
// ============================================================================

#[test]
fn differror_display_variants() {
    let e1 = DiffError::EmptyInput("x".into());
    let e2 = DiffError::HashError("y".into());
    let e3 = DiffError::Other("z".into());
    assert!(e1.to_string().contains("empty input"));
    assert!(e2.to_string().contains("hash error"));
    assert_eq!(e3.to_string(), "z");
}

// ============================================================================
// NamedBinaryDiff counts on empty
// ============================================================================

#[test]
fn namedbinarydiff_default_counts() {
    let n = NamedBinaryDiff {
        functions: vec![],
        overall_similarity: 0.0,
    };
    assert_eq!(n.added_count(), 0);
    assert_eq!(n.removed_count(), 0);
    assert_eq!(n.modified_count(), 0);
    assert_eq!(n.unchanged_count(), 0);
}
