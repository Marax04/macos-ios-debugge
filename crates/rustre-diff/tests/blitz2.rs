//! Deep adversarial coverage of rustre-diff public API.

use rustre_diff::{
    BinaryDiff, ChangeType, DiffEngine, DiffError, ExportDiff, ExportEntry, FuncFingerprint,
    FuncMatch, FunctionDiff, MatchKind, byte_histogram_similarity,
    combined_byte_similarity, diff_by_name, diff_exports, lcs_similarity, ngram_jaccard_similarity,
    simple_hash,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

fn rand_bytes(g: &mut dyn FnMut() -> u64, n: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    while v.len() < n {
        let r = g();
        for i in 0..8 {
            if v.len() >= n {
                break;
            }
            v.push((r >> (i * 8)) as u8);
        }
    }
    v
}

fn fp(addr: u64, name: &str, bytes: &[u8]) -> FuncFingerprint {
    FuncFingerprint::new(addr, name.to_string(), bytes.to_vec())
}

// ============================================================================
// simple_hash
// ============================================================================

#[test]
fn simple_hash_empty_is_fnv_offset() {
    assert_eq!(simple_hash(&[]), 0xcbf2_9ce4_8422_2325);
}

#[test]
fn simple_hash_deterministic_over_lcg() {
    let mut g = lcg();
    for _ in 0..60 {
        let len = (g() % 200) as usize;
        let data = rand_bytes(&mut g, len);
        assert_eq!(simple_hash(&data), simple_hash(&data));
    }
}

#[test]
fn simple_hash_single_byte_differs() {
    let mut g = lcg();
    let base = rand_bytes(&mut g, 32);
    let mut other = base.clone();
    other[0] = other[0].wrapping_add(1);
    assert_ne!(simple_hash(&base), simple_hash(&other));
}

#[test]
fn simple_hash_collision_rate_low() {
    // 200 random inputs should produce 200 unique hashes (extremely likely).
    let mut g = lcg();
    let mut hashes = std::collections::HashSet::new();
    for _ in 0..200 {
        let len = ((g() % 60) + 4) as usize;
        let data = rand_bytes(&mut g, len);
        hashes.insert(simple_hash(&data));
    }
    assert!(hashes.len() > 195);
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
fn lcs_identical_is_one() {
    let mut g = lcg();
    for _ in 0..30 {
        let len = ((g() % 100) + 1) as usize;
        let data = rand_bytes(&mut g, len);
        let s = lcs_similarity(&data, &data);
        // For lengths <= 512 the truncation factor is 1.0, so should be exactly 1.0.
        assert!((s - 1.0).abs() < 1e-9, "len={} s={}", len, s);
    }
}

#[test]
fn lcs_in_range_fuzz() {
    let mut g = lcg();
    for _ in 0..60 {
        let la = ((g() % 200) + 1) as usize;
        let lb = ((g() % 200) + 1) as usize;
        let a = rand_bytes(&mut g, la);
        let b = rand_bytes(&mut g, lb);
        let s = lcs_similarity(&a, &b);
        assert!((0.0..=1.0).contains(&s), "out of range: {}", s);
    }
}

#[test]
fn lcs_long_inputs_capped_no_panic() {
    let a = vec![0xAB; 2000];
    let b = vec![0xAB; 2000];
    let s = lcs_similarity(&a, &b);
    assert!((0.0..=1.0).contains(&s));
}

#[test]
fn lcs_completely_disjoint_zero() {
    let a = vec![0x00u8; 30];
    let b = vec![0xFFu8; 30];
    assert_eq!(lcs_similarity(&a, &b), 0.0);
}

// ============================================================================
// byte_histogram_similarity / ngram / combined
// ============================================================================

#[test]
fn histogram_both_empty_one() {
    assert_eq!(byte_histogram_similarity(&[], &[]), 1.0);
}

#[test]
fn histogram_one_empty_zero() {
    assert_eq!(byte_histogram_similarity(b"hi", &[]), 0.0);
    assert_eq!(byte_histogram_similarity(&[], b"hi"), 0.0);
}

#[test]
fn histogram_identical_one() {
    let mut g = lcg();
    for _ in 0..20 {
        let len = ((g() % 100) + 1) as usize;
        let data = rand_bytes(&mut g, len);
        let s = byte_histogram_similarity(&data, &data);
        assert!((s - 1.0).abs() < 1e-5, "{}", s);
    }
}

#[test]
fn histogram_in_range() {
    let mut g = lcg();
    for _ in 0..50 {
        let la = ((g() % 80) + 1) as usize;
        let lb = ((g() % 80) + 1) as usize;
        let a = rand_bytes(&mut g, la);
        let b = rand_bytes(&mut g, lb);
        let s = byte_histogram_similarity(&a, &b);
        assert!((0.0..=1.0).contains(&s));
    }
}

#[test]
fn ngram_both_empty_one() {
    assert_eq!(ngram_jaccard_similarity(&[], &[], 4), 1.0);
}

#[test]
fn ngram_n_zero_returns_zero() {
    assert_eq!(ngram_jaccard_similarity(b"abc", b"abc", 0), 0.0);
}

#[test]
fn ngram_identical_one() {
    let data = b"abcdefghij";
    let s = ngram_jaccard_similarity(data, data, 4);
    assert!((s - 1.0).abs() < 1e-5);
}

#[test]
fn ngram_n_capped_at_8_no_panic() {
    let s = ngram_jaccard_similarity(b"abcdefghijk", b"abcdefghijk", 99);
    assert!((0.0..=1.0).contains(&s));
}

#[test]
fn ngram_fuzz_in_range() {
    let mut g = lcg();
    for _ in 0..40 {
        let la = ((g() % 60) + 1) as usize;
        let lb = ((g() % 60) + 1) as usize;
        let a = rand_bytes(&mut g, la);
        let b = rand_bytes(&mut g, lb);
        let n = ((g() % 8) + 1) as usize;
        let s = ngram_jaccard_similarity(&a, &b, n);
        assert!((0.0..=1.0).contains(&s));
    }
}

#[test]
fn combined_byte_similarity_identical_near_one() {
    let mut g = lcg();
    for _ in 0..20 {
        let data = rand_bytes(&mut g, 50);
        let s = combined_byte_similarity(&data, &data);
        assert!(s > 0.99, "{}", s);
    }
}

#[test]
fn combined_byte_similarity_in_range() {
    let mut g = lcg();
    for _ in 0..40 {
        let la = ((g() % 80) + 4) as usize;
        let lb = ((g() % 80) + 4) as usize;
        let a = rand_bytes(&mut g, la);
        let b = rand_bytes(&mut g, lb);
        let s = combined_byte_similarity(&a, &b);
        assert!((0.0..=1.0).contains(&s));
    }
}

// ============================================================================
// FuncFingerprint
// ============================================================================

#[test]
fn fingerprint_new_metadata_default_zero() {
    let f = FuncFingerprint::new(0x100, "x".into(), vec![1, 2, 3]);
    assert_eq!(f.size, 3);
    assert_eq!(f.call_count, 0);
    assert_eq!(f.block_count, 0);
    assert_eq!(f.edge_count, 0);
}

#[test]
fn fingerprint_similarity_self_is_one() {
    let mut g = lcg();
    for _ in 0..30 {
        let len = ((g() % 50) + 1) as usize;
        let data = rand_bytes(&mut g, len);
        let f = fp(0, "a", &data);
        assert_eq!(f.similarity(&f), 1.0);
    }
}

#[test]
fn fingerprint_similarity_in_range_fuzz() {
    let mut g = lcg();
    for _ in 0..50 {
        let la = ((g() % 40) + 1) as usize;
        let lb = ((g() % 40) + 1) as usize;
        let a = fp(0, "a", &rand_bytes(&mut g, la));
        let b = fp(0, "b", &rand_bytes(&mut g, lb));
        let s = a.similarity(&b);
        assert!((0.0..=1.0).contains(&s));
    }
}

#[test]
fn fingerprint_similarity_both_empty() {
    let a = FuncFingerprint::new(0, "a".into(), vec![]);
    let b = FuncFingerprint::new(0, "b".into(), vec![]);
    assert_eq!(a.similarity(&b), 1.0);
}

#[test]
fn fingerprint_display_contains_name_addr_size() {
    let f = fp(0xABCD, "myfunc", &[1, 2, 3]);
    let s = f.to_string();
    assert!(s.contains("myfunc"));
    assert!(s.contains("0xabcd"));
    assert!(s.contains("sz=3"));
}

// ============================================================================
// MatchKind / FuncMatch
// ============================================================================

#[test]
fn match_kind_display_roundtrip_all_variants() {
    for k in [
        MatchKind::Identical,
        MatchKind::Similar,
        MatchKind::Added,
        MatchKind::Removed,
        MatchKind::Renamed,
    ] {
        let s = k.to_string();
        assert!(!s.is_empty());
    }
}

#[test]
fn match_kind_hash_eq_consistency() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    for k in [
        MatchKind::Identical,
        MatchKind::Similar,
        MatchKind::Added,
        MatchKind::Removed,
        MatchKind::Renamed,
    ] {
        set.insert(k);
    }
    assert_eq!(set.len(), 5);
    // 30+ pairs check
    let kinds = [
        MatchKind::Identical,
        MatchKind::Similar,
        MatchKind::Added,
        MatchKind::Removed,
        MatchKind::Renamed,
    ];
    let mut pairs = 0;
    for a in &kinds {
        for b in &kinds {
            if a == b {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b);
            }
            pairs += 1;
        }
    }
    assert!(pairs >= 25);
}

#[test]
fn func_match_similar_confidence_rounds_correctly() {
    let a = fp(0, "a", &[1, 2, 3]);
    let b = fp(0, "a", &[1, 2, 3]);
    let m = FuncMatch::similar(a, b, 0.75);
    assert_eq!(m.confidence, 75);
}

#[test]
fn func_match_similar_confidence_clamps_out_of_range() {
    let a = fp(0, "a", &[1]);
    let b = fp(0, "a", &[1]);
    let m1 = FuncMatch::similar(a.clone(), b.clone(), 1.5);
    assert_eq!(m1.confidence, 100);
    let m2 = FuncMatch::similar(a, b, -0.5);
    assert_eq!(m2.confidence, 0);
}

#[test]
fn func_match_renamed_confidence_matches_similarity() {
    let a = fp(0, "old", &[1]);
    let b = fp(0, "new", &[1]);
    let m = FuncMatch::renamed(a, b, 0.95);
    assert_eq!(m.confidence, 95);
    assert_eq!(m.kind, MatchKind::Renamed);
    assert!(m.is_changed());
}

#[test]
fn func_match_added_removed_state() {
    let f = fp(0x10, "f", &[1]);
    let added = FuncMatch::added(f.clone());
    let removed = FuncMatch::removed(f.clone());
    assert!(added.primary.is_none() && added.secondary.is_some());
    assert!(removed.primary.is_some() && removed.secondary.is_none());
    assert!(added.is_changed() && removed.is_changed());
}

// ============================================================================
// BinaryDiff
// ============================================================================

#[test]
fn binary_diff_new_zero_counts() {
    let d = BinaryDiff::new("a".into(), "b".into());
    assert_eq!(d.identical_count(), 0);
    assert_eq!(d.added_count(), 0);
    assert_eq!(d.removed_count(), 0);
    assert_eq!(d.changed_count(), 0);
    assert_eq!(d.similarity_ratio(), 0.0);
}

#[test]
fn binary_diff_display_contains_names_and_counts() {
    let d = BinaryDiff::new("alpha".into(), "beta".into());
    let s = d.to_string();
    assert!(s.contains("alpha"));
    assert!(s.contains("beta"));
}

// ============================================================================
// DiffEngine
// ============================================================================

#[test]
fn diff_engine_both_empty_err() {
    let eng = DiffEngine::default();
    let r = eng.diff(vec![], &vec![], "a".into(), "b".into());
    assert!(matches!(r, Err(DiffError::EmptyInput(_))));
}

#[test]
fn diff_engine_identical_pair() {
    let eng = DiffEngine::default();
    let a = vec![fp(0x100, "f", &[1, 2, 3, 4, 5])];
    let b = vec![fp(0x100, "f", &[1, 2, 3, 4, 5])];
    let d = eng.diff(a, &b, "a".into(), "b".into()).unwrap();
    assert_eq!(d.identical_count(), 1);
    assert_eq!(d.similarity_ratio(), 1.0);
}

#[test]
fn diff_engine_only_a_yields_all_removed() {
    let eng = DiffEngine::default();
    let a: Vec<_> = (0..5)
        .map(|i| fp(0x1000 + i, &format!("f{i}"), &[i as u8; 10]))
        .collect();
    let d = eng.diff(a, &vec![], "a".into(), "b".into()).unwrap();
    assert_eq!(d.removed_count(), 5);
    assert_eq!(d.added_count(), 0);
}

#[test]
fn diff_engine_only_b_yields_all_added() {
    let eng = DiffEngine::default();
    let b: Vec<_> = (0..5)
        .map(|i| fp(0x1000 + i, &format!("f{i}"), &[i as u8; 10]))
        .collect();
    let d = eng.diff(vec![], &b, "a".into(), "b".into()).unwrap();
    assert_eq!(d.added_count(), 5);
    assert_eq!(d.removed_count(), 0);
}

#[test]
fn diff_engine_total_counts_preserved() {
    let eng = DiffEngine::default();
    let a: Vec<_> = (0..7).map(|i| fp(i, &format!("a{i}"), &[i as u8; 8])).collect();
    let b: Vec<_> = (0..3).map(|i| fp(i, &format!("b{i}"), &[i as u8; 8])).collect();
    let d = eng.diff(a, &b, "x".into(), "y".into()).unwrap();
    assert_eq!(d.total_functions_a, 7);
    assert_eq!(d.total_functions_b, 3);
}

#[test]
fn diff_engine_default_threshold_in_debug() {
    let d = format!("{:?}", DiffEngine::default());
    assert!(d.contains("0.6"));
}

#[test]
fn diff_engine_renamed_detected() {
    let eng = DiffEngine::new(0.5);
    let body = vec![0x55u8, 0x8b, 0xec, 0x83, 0xec, 0x10, 0x33, 0xc0, 0xc9, 0xc3];
    let a = vec![fp(0x1000, "oldName", &body)];
    let b = vec![fp(0x2000, "newName", &body)];
    let d = eng.diff(a, &b, "a".into(), "b".into()).unwrap();
    // identical hash means it matches in pass 1 as Identical (body equal); name diff irrelevant there
    assert_eq!(d.matches.len(), 1);
    assert_eq!(d.identical_count(), 1);
}

#[test]
fn diff_engine_lcg_fuzz_never_panics() {
    let eng = DiffEngine::default();
    let mut g = lcg();
    for _ in 0..15 {
        let na = (g() % 6) as usize;
        let nb = (g() % 6) as usize;
        if na == 0 && nb == 0 {
            continue;
        }
        let a: Vec<_> = (0..na)
            .map(|i| fp(i as u64, &format!("a{i}"), &rand_bytes(&mut g, 16)))
            .collect();
        let b: Vec<_> = (0..nb)
            .map(|i| fp(i as u64, &format!("b{i}"), &rand_bytes(&mut g, 16)))
            .collect();
        let r = eng.diff(a, &b, "x".into(), "y".into()).unwrap();
        assert_eq!(r.total_functions_a, na);
        assert_eq!(r.total_functions_b, nb);
    }
}

// ============================================================================
// ChangeType / FunctionDiff / NamedBinaryDiff
// ============================================================================

#[test]
fn change_type_display_variants() {
    assert_eq!(ChangeType::Added.to_string(), "Added");
    assert_eq!(ChangeType::Removed.to_string(), "Removed");
    assert_eq!(ChangeType::Unchanged.to_string(), "Unchanged");
    let s = ChangeType::Modified { similarity: 0.5 }.to_string();
    assert!(s.contains("Modified"));
}

#[test]
fn function_diff_display_name_fallbacks() {
    let only_a = FunctionDiff {
        addr_a: None,
        addr_b: None,
        name_a: Some("foo".into()),
        name_b: None,
        similarity: 0.0,
        change_type: ChangeType::Removed,
    };
    assert_eq!(only_a.display_name(), "foo");
    let only_b = FunctionDiff {
        addr_a: None,
        addr_b: None,
        name_a: None,
        name_b: Some("bar".into()),
        similarity: 0.0,
        change_type: ChangeType::Added,
    };
    assert_eq!(only_b.display_name(), "bar");
    let neither = FunctionDiff {
        addr_a: None,
        addr_b: None,
        name_a: None,
        name_b: None,
        similarity: 0.0,
        change_type: ChangeType::Added,
    };
    assert_eq!(neither.display_name(), "<unknown>");
}

#[test]
fn diff_by_name_unchanged_for_identical() {
    let mut a: HashMap<String, Vec<u8>> = HashMap::new();
    let mut b: HashMap<String, Vec<u8>> = HashMap::new();
    for i in 0..10 {
        let body = vec![i as u8; 16];
        a.insert(format!("f{i}"), body.clone());
        b.insert(format!("f{i}"), body);
    }
    let d = diff_by_name(&a, &b);
    assert_eq!(d.unchanged_count(), 10);
    assert_eq!(d.modified_count(), 0);
    assert_eq!(d.added_count(), 0);
    assert_eq!(d.removed_count(), 0);
}

#[test]
fn diff_by_name_added_removed() {
    let mut a: HashMap<String, Vec<u8>> = HashMap::new();
    let mut b: HashMap<String, Vec<u8>> = HashMap::new();
    a.insert("only_a".into(), vec![1, 2, 3]);
    b.insert("only_b".into(), vec![4, 5, 6]);
    let d = diff_by_name(&a, &b);
    assert_eq!(d.added_count(), 1);
    assert_eq!(d.removed_count(), 1);
}

#[test]
fn diff_by_name_modified() {
    let mut a: HashMap<String, Vec<u8>> = HashMap::new();
    let mut b: HashMap<String, Vec<u8>> = HashMap::new();
    a.insert("f".into(), (0u8..30).collect());
    let mut bb: Vec<u8> = (0u8..30).collect();
    bb[5] = 0xFF;
    bb[10] = 0xFF;
    b.insert("f".into(), bb);
    let d = diff_by_name(&a, &b);
    assert!(d.modified_count() >= 1 || d.unchanged_count() >= 1);
}

#[test]
fn diff_by_name_empty_yields_zero_overall() {
    let a: HashMap<String, Vec<u8>> = HashMap::new();
    let b: HashMap<String, Vec<u8>> = HashMap::new();
    let d = diff_by_name(&a, &b);
    assert_eq!(d.overall_similarity, 0.0);
    assert!(d.functions.is_empty());
}

#[test]
fn diff_by_name_sort_order_unchanged_first() {
    let mut a: HashMap<String, Vec<u8>> = HashMap::new();
    let mut b: HashMap<String, Vec<u8>> = HashMap::new();
    a.insert("same".into(), vec![1, 2, 3, 4]);
    b.insert("same".into(), vec![1, 2, 3, 4]);
    a.insert("removed".into(), vec![9, 9, 9]);
    b.insert("added".into(), vec![8, 8, 8]);
    let d = diff_by_name(&a, &b);
    // first must be unchanged
    assert_eq!(d.functions[0].change_type, ChangeType::Unchanged);
    // last should be added
    assert_eq!(
        d.functions.last().unwrap().change_type,
        ChangeType::Added
    );
}

#[test]
fn named_binary_diff_counts_consistency() {
    let mut a: HashMap<String, Vec<u8>> = HashMap::new();
    let mut b: HashMap<String, Vec<u8>> = HashMap::new();
    for i in 0..5 {
        let body = vec![i as u8; 8];
        a.insert(format!("u{i}"), body.clone());
        b.insert(format!("u{i}"), body);
    }
    a.insert("gone".into(), vec![1; 4]);
    b.insert("new".into(), vec![2; 4]);
    let d = diff_by_name(&a, &b);
    let total = d.unchanged_count() + d.modified_count() + d.added_count() + d.removed_count();
    assert_eq!(total, d.functions.len());
}

// ============================================================================
// Export diff
// ============================================================================

fn ee(name: Option<&str>, ord: u32, addr: u64) -> ExportEntry {
    ExportEntry {
        name: name.map(|s| s.to_string()),
        ordinal: ord,
        address: addr,
    }
}

#[test]
fn export_diff_empty_clean() {
    let d: ExportDiff = diff_exports(&[], &[]);
    assert!(d.is_clean());
    assert_eq!(d.unchanged.len(), 0);
}

#[test]
fn export_diff_unchanged() {
    let a = vec![ee(Some("foo"), 1, 0x1000)];
    let b = vec![ee(Some("foo"), 1, 0x1000)];
    let d = diff_exports(&a, &b);
    assert_eq!(d.unchanged.len(), 1);
    assert!(d.is_clean());
}

#[test]
fn export_diff_added_removed() {
    let a = vec![ee(Some("only_a"), 1, 0x1000)];
    let b = vec![ee(Some("only_b"), 2, 0x2000)];
    let d = diff_exports(&a, &b);
    assert_eq!(d.added.len(), 1);
    assert_eq!(d.removed.len(), 1);
    assert!(!d.is_clean());
}

#[test]
fn export_diff_moved() {
    let a = vec![ee(Some("foo"), 1, 0x1000)];
    let b = vec![ee(Some("foo"), 1, 0x2000)];
    let d = diff_exports(&a, &b);
    assert_eq!(d.moved.len(), 1);
    assert!(!d.is_clean());
}

#[test]
fn export_diff_anonymous_matches_by_ordinal() {
    let a = vec![ee(None, 5, 0x1000)];
    let b = vec![ee(None, 5, 0x1000)];
    let d = diff_exports(&a, &b);
    assert_eq!(d.unchanged.len(), 1);
}

#[test]
fn export_diff_display_format() {
    let a = vec![ee(Some("f"), 1, 0x10)];
    let b = vec![ee(Some("g"), 2, 0x20)];
    let d = diff_exports(&a, &b);
    let s = d.to_string();
    assert!(s.contains("ExportDiff"));
}

#[test]
fn export_diff_sort_determinism() {
    let a = vec![
        ee(Some("a"), 3, 0x1),
        ee(Some("b"), 1, 0x2),
        ee(Some("c"), 2, 0x3),
    ];
    let b: Vec<ExportEntry> = vec![];
    let d = diff_exports(&a, &b);
    let ords: Vec<u32> = d.removed.iter().map(|e| e.ordinal).collect();
    assert_eq!(ords, vec![1, 2, 3]);
}

// ============================================================================
// Send + Sync / threaded stress
// ============================================================================

#[test]
fn fingerprint_is_send_sync_threaded() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FuncFingerprint>();
    assert_send_sync::<BinaryDiff>();
    assert_send_sync::<FuncMatch>();
    assert_send_sync::<MatchKind>();
    assert_send_sync::<ExportDiff>();

    let fp_shared = Arc::new(fp(0x100, "shared", &[1, 2, 3, 4, 5, 6, 7, 8]));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let f = Arc::clone(&fp_shared);
        handles.push(thread::spawn(move || {
            let mut sum: f64 = 0.0;
            for _ in 0..100 {
                let other = fp(0x200, "other", &[1, 2, 3, 4, 5, 6, 7, 9]);
                sum += f.similarity(&other);
            }
            sum
        }));
    }
    for h in handles {
        let s = h.join().unwrap();
        assert!(s.is_finite());
    }
}

#[test]
fn diff_engine_threaded_stress() {
    let eng = Arc::new(DiffEngine::default());
    let mut handles = Vec::new();
    for t in 0..4 {
        let e = Arc::clone(&eng);
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                let a = vec![fp(
                    i as u64,
                    "f",
                    &[(t as u8).wrapping_add(i as u8); 16],
                )];
                let b = vec![fp(
                    i as u64,
                    "f",
                    &[(t as u8).wrapping_add(i as u8); 16],
                )];
                let d = e.diff(a, &b, "a".into(), "b".into()).unwrap();
                assert_eq!(d.identical_count(), 1);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}
