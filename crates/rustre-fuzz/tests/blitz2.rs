//! Deep adversarial test suite (Y062) for `rustre-fuzz` lib.rs public API.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustre_fuzz::{
    fnv1a, Corpus, CorpusEntry, CorpusMeta, CoverageMap, CrashDeduplicator, CrashRecord,
    CrashType, Dictionary, ExecutionResult, ExecutionStatus, FuzzCorpusManager,
    FuzzCrashAnalyzer, FuzzError, FuzzInput, FuzzMutator, FuzzResult, FuzzRng, FuzzerStats,
    InputQueue, Minimizer, MutationEngine, MutationStrategy, PowerSchedule, PowerScheduleKind,
    SharedCoverage,
};

/// Seeded LCG fuzz generator.
fn lcg_seq(n: usize) -> Vec<u64> {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    (0..n)
        .map(|_| {
            s = s
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            s
        })
        .collect()
}

fn lcg_bytes(n: usize) -> Vec<u8> {
    lcg_seq(n).into_iter().map(|x| u8::try_from((x >> 24) & 0xff).unwrap_or(0)).collect()
}

// ── 1. FuzzInput round-trip ─────────────────────────────────────────────────

#[test]
fn t01_fuzz_input_derive_chain_50() {
    let mut parent = FuzzInput::new(0, vec![0]);
    for i in 1u64..=50 {
        let child = parent.derive(i, vec![u8::try_from(i & 0xff).unwrap_or(0)]);
        assert_eq!(child.id, i);
        assert_eq!(child.parent, Some(parent.id));
        assert_eq!(child.generation, parent.generation + 1);
        parent = child;
    }
    assert_eq!(parent.generation, 50);
}

#[test]
fn t02_fuzz_input_data_hash_consistency() {
    for v in lcg_seq(50) {
        let bytes = v.to_le_bytes().to_vec();
        let a = FuzzInput::new(0, bytes.clone());
        let b = FuzzInput::new(99, bytes);
        assert_eq!(a.data_hash(), b.data_hash(),
            "data_hash should depend only on data");
    }
}

#[test]
fn t03_fuzz_input_serde_roundtrip() {
    for v in lcg_seq(50) {
        let inp = FuzzInput::new_with_origin(v, v.to_le_bytes().to_vec(), "bit_flip");
        let json = serde_json::to_string(&inp).expect("serialize");
        let back: FuzzInput = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(inp, back);
    }
}

#[test]
fn t04_fuzz_input_generation_saturates() {
    let mut p = FuzzInput::new(0, vec![]);
    p.generation = u32::MAX;
    let child = p.derive(1, vec![]);
    assert_eq!(child.generation, u32::MAX); // saturating
}

#[test]
fn t05_fuzz_input_empty() {
    let inp = FuzzInput::new(0, vec![]);
    assert!(inp.is_empty());
    assert_eq!(inp.len(), 0);
    assert_eq!(inp.data_hash(), fnv1a(&[]));
}

// ── 2. fnv1a ────────────────────────────────────────────────────────────────

#[test]
fn t06_fnv1a_known_vectors() {
    // FNV-1a empty offset basis
    assert_eq!(fnv1a(&[]), 0xcbf2_9ce4_8422_2325);
    // Determinism over LCG fuzz
    for v in lcg_seq(50) {
        let b = v.to_le_bytes();
        assert_eq!(fnv1a(&b), fnv1a(&b));
    }
}

#[test]
fn t07_fnv1a_byte_sensitivity() {
    // Different single-byte inputs produce different hashes
    let mut seen = std::collections::HashSet::new();
    for b in 0u8..=255 {
        seen.insert(fnv1a(&[b]));
    }
    assert_eq!(seen.len(), 256);
}

// ── 3. FuzzResult / ExecutionStatus ─────────────────────────────────────────

#[test]
fn t08_fuzz_result_variants_exhaustive() {
    assert!(FuzzResult::Crash { input: vec![], signal: 0, address: 0 }.is_crash());
    assert!(FuzzResult::Interesting(vec![]).is_interesting());
    assert!(FuzzResult::Normal.is_normal());
    assert!(!FuzzResult::Timeout.is_normal());
    assert!(!FuzzResult::Timeout.is_crash());
}

#[test]
fn t09_execution_status_flags() {
    assert!(ExecutionStatus::Crash { signal: 1, fault_addr: None }.is_crash());
    assert!(ExecutionStatus::Hang.is_hang());
    assert!(ExecutionStatus::Timeout.is_hang());
    assert!(!ExecutionStatus::Normal.is_hang());
    assert!(!ExecutionStatus::Normal.is_crash());
}

#[test]
fn t10_execution_result_normal_and_crash() {
    let n = ExecutionResult::normal(Duration::from_millis(1));
    assert!(n.status.is_normal());
    assert_eq!(n.coverage_hash, 0);
    let c = ExecutionResult::crash(11, Some(0xfeed), Duration::from_millis(3));
    assert!(c.status.is_crash());
}

// ── 4. CoverageMap ──────────────────────────────────────────────────────────

#[test]
fn t11_coverage_map_size_invariants() {
    for &n in &[0usize, 1, 2, 8, 16, 64] {
        let m = CoverageMap::new(n);
        assert_eq!(m.bits.len(), n);
        assert_eq!(m.hit_counts.len(), n * 8);
        assert_eq!(m.total_bits_set(), 0);
        assert!(m.is_empty());
    }
}

#[test]
fn t12_coverage_map_update_idempotent() {
    let mut m = CoverageMap::new(4);
    let bits = vec![0xAA, 0x55, 0xFF, 0x00];
    let first = m.update(&bits);
    let second = m.update(&bits);
    assert_eq!(first, m.total_bits_set());
    assert_eq!(second, 0);
}

#[test]
fn t13_coverage_map_update_truncation() {
    // new_bits shorter than internal buffer
    let mut m = CoverageMap::new(8);
    let n = m.update(&[0xFF]);
    assert_eq!(n, 8);
    assert_eq!(m.total_bits_set(), 8);
    // new_bits longer: extra bytes ignored
    let mut m2 = CoverageMap::new(2);
    let n2 = m2.update(&[0xFF, 0xFF, 0xFF, 0xFF]);
    assert_eq!(n2, 16);
}

#[test]
fn t14_coverage_map_lcg_fuzz_never_panics() {
    let mut m = CoverageMap::new(16);
    let words = lcg_seq(60);
    for w in words {
        let b = w.to_le_bytes();
        let _ = m.update(&b);
    }
    let _ = m.hash();
    let _ = m.active_edges();
    let _ = m.hot_edges();
}

#[test]
fn t15_coverage_map_reset_clears_state() {
    let mut m = CoverageMap::new(4);
    m.update(&[0xFF, 0xFF, 0xFF, 0xFF]);
    assert!(!m.is_empty());
    m.reset();
    assert!(m.is_empty());
    assert_eq!(m.bits_set_since_last_reset(), 0);
    assert_eq!(m.cumulative_bits_set(), 0);
}

#[test]
fn t16_coverage_map_edge_hit_count_oob() {
    let m = CoverageMap::new(2);
    assert_eq!(m.edge_hit_count(usize::MAX), 0);
    assert_eq!(m.edge_hit_count(1_000_000), 0);
}

// ── 5. InputQueue ───────────────────────────────────────────────────────────

#[test]
fn t17_input_queue_round_robin() {
    let mut q = InputQueue::new();
    for i in 0..5u64 {
        q.add(FuzzInput::new(i, vec![u8::try_from(i).unwrap_or(0)]), false);
    }
    let mut seen = std::collections::HashSet::new();
    for _ in 0..20 {
        seen.insert(q.select().id);
    }
    assert_eq!(seen.len(), 5);
}

#[test]
fn t18_input_queue_remove_clears_favored() {
    let mut q = InputQueue::new();
    q.add(FuzzInput::new(0, vec![1]), true);
    q.add(FuzzInput::new(1, vec![2]), true);
    assert_eq!(q.favored_count(), 2);
    q.remove(0);
    assert_eq!(q.favored_count(), 1);
}

#[test]
#[should_panic(expected = "empty")]
fn t19_input_queue_select_empty_panics_should_panic() {
    let mut q = InputQueue::new();
    let _ = q.select();
}

#[test]
fn t20_input_queue_next_id_monotonic_50() {
    let mut q = InputQueue::new();
    for i in 0..50u64 {
        assert_eq!(q.next_id(), i);
    }
}

// ── 6. FuzzerStats ──────────────────────────────────────────────────────────

#[test]
fn t21_fuzzer_stats_record_execution_max_len() {
    let mut s = FuzzerStats::new();
    for &v in &[10usize, 5, 30, 20, 100, 50] {
        s.record_execution(v);
    }
    assert_eq!(s.executions, 6);
    assert_eq!(s.max_input_len, 100);
    assert_eq!(s.total_bytes_generated, 215);
}

#[test]
fn t22_fuzzer_stats_crash_rate_boundary() {
    let mut s = FuzzerStats::new();
    assert!(s.crash_rate().abs() < f64::EPSILON);
    s.executions = 1;
    s.crashes = 1;
    assert!((s.crash_rate() - 1.0).abs() < f64::EPSILON);
}

#[test]
fn t23_fuzzer_stats_serde() {
    let s = FuzzerStats::new();
    let j = serde_json::to_string(&s).unwrap();
    let _: FuzzerStats = serde_json::from_str(&j).unwrap();
}

// ── 7. CorpusMeta / Corpus ──────────────────────────────────────────────────

#[test]
fn t24_corpus_meta_selected_count_saturates() {
    let mut m = CorpusMeta::new(0, 0, Duration::ZERO);
    m.selected_count = u64::MAX - 1;
    m.record_selection();
    m.record_selection(); // would overflow without saturating
    assert_eq!(m.selected_count, u64::MAX);
}

#[test]
fn t25_corpus_dedup_50_entries() {
    let mut c = Corpus::new();
    let mut added_unique = 0;
    for (i, v) in lcg_seq(50).into_iter().enumerate() {
        let h = v;
        let m = CorpusMeta::new(h, 1, Duration::ZERO);
        if c.add_input(FuzzInput::new(i as u64, vec![u8::try_from(i & 0xff).unwrap_or(0)]), m) {
            added_unique += 1;
        }
    }
    // LCG values are unique, so all should be novel
    assert_eq!(added_unique, 50);
    assert_eq!(c.unique_coverage_hashes(), 50);
}

#[test]
fn t26_corpus_sorted_by_coverage_descending() {
    let mut c = Corpus::new();
    for (i, bits) in [3u32, 1, 7, 4, 2].into_iter().enumerate() {
        c.add_input(
            FuzzInput::new(i as u64, vec![]),
            CorpusMeta::new(i as u64, bits, Duration::ZERO),
        );
    }
    let s = c.sorted_by_coverage();
    let bits: Vec<u32> = s
        .iter()
        .map(|i| c.metadata.get(&i.id).unwrap().coverage_bits)
        .collect();
    assert_eq!(bits, vec![7, 4, 3, 2, 1]);
}

#[test]
fn t27_corpus_prune_keeps_roots() {
    let mut c = Corpus::new();
    // Root input with low coverage — should be kept
    let root = FuzzInput::new(0, vec![]);
    c.add_input(root, CorpusMeta::new(0, 0, Duration::ZERO));
    // Non-root with low coverage — should be pruned
    let mut child = FuzzInput::new(1, vec![]);
    child.parent = Some(0);
    c.add_input(child, CorpusMeta::new(1, 0, Duration::ZERO));
    let removed = c.prune(5);
    assert_eq!(removed, 1);
    assert!(c.get_entry(0).is_some());
}

#[test]
fn t28_corpus_entry_accessors() {
    let inp = FuzzInput::new(42, vec![1, 2, 3]);
    let meta = CorpusMeta::new(0, 0, Duration::ZERO);
    let e = CorpusEntry::new(inp, meta);
    assert_eq!(e.id(), 42);
    assert_eq!(e.data(), &[1, 2, 3]);
}

// ── 8. CrashRecord / CrashDeduplicator ──────────────────────────────────────

#[test]
fn t29_crash_record_stack_hash_changes_dedup() {
    let mut r = CrashRecord::new(0, vec![], 11, None, 0xAAAA);
    let before = r.dedup_key();
    r.set_stack_hash(&[1, 2, 3]);
    assert_ne!(r.dedup_key(), before);
}

#[test]
fn t30_dedup_iter_order_preserved() {
    let mut d = CrashDeduplicator::new();
    let hashes = [10u64, 20, 30, 40, 50];
    for &h in &hashes {
        d.submit(vec![], 11, None, h);
    }
    let collected: Vec<u64> = d.iter().map(|r| r.coverage_hash).collect();
    assert_eq!(collected, hashes);
}

#[test]
fn t31_dedup_lcg_fuzz_unique_count() {
    let mut d = CrashDeduplicator::new();
    for v in lcg_seq(60) {
        d.submit(vec![], 11, None, v);
    }
    // LCG values are unique
    assert_eq!(d.unique_count(), 60);
}

#[test]
fn t32_dedup_clear_and_resubmit() {
    let mut d = CrashDeduplicator::new();
    d.submit(vec![1], 11, None, 1);
    d.clear();
    assert_eq!(d.unique_count(), 0);
    // After clear, the same hash should be considered new again
    assert!(d.submit(vec![1], 11, None, 1));
}

// ── 9. MutationStrategy ─────────────────────────────────────────────────────

#[test]
fn t33_mutation_strategy_display_all() {
    for &s in MutationStrategy::all() {
        let n = s.to_string();
        assert!(!n.is_empty());
        assert_eq!(n, s.name());
    }
}

#[test]
fn t34_mutation_strategy_hash_eq() {
    use std::collections::HashSet;
    let set: HashSet<MutationStrategy> = MutationStrategy::all().iter().copied().collect();
    assert_eq!(set.len(), MutationStrategy::all().len());
}

// ── 10. Dictionary ──────────────────────────────────────────────────────────

#[test]
fn t35_dictionary_load_invalid_hex_returns_err() {
    let mut d = Dictionary::new();
    let err = d.load_from_text("x\"zz\"\n");
    assert!(matches!(err, Err(FuzzError::InputError(_))));
}

#[test]
fn t36_dictionary_load_mixed_formats() {
    let mut d = Dictionary::new();
    let text = "# comment\n\
        bare_token\n\
        \"quoted\"\n\
        x\"de ad\"\n\
        \n";
    let n = d.load_from_text(text).unwrap();
    assert_eq!(n, 3);
    assert_eq!(d.entries[0], b"bare_token");
    assert_eq!(d.entries[1], b"quoted");
    assert_eq!(d.entries[2], vec![0xDE, 0xAD]);
}

#[test]
fn t37_dictionary_get_wrapping_oob() {
    let mut d = Dictionary::new();
    d.add(vec![1]);
    d.add(vec![2]);
    d.add(vec![3]);
    // wraps cleanly for any index
    for i in 0..100usize {
        let t = d.get_wrapping(i).unwrap();
        assert_eq!(t[0], u8::try_from(i % 3 + 1).unwrap_or(0));
    }
}

// ── 11. MutationEngine / FuzzRng ────────────────────────────────────────────

#[test]
fn t38_mutation_engine_lcg_fuzz_never_panics() {
    let mut e = MutationEngine::with_seed(0xCAFE);
    e.dictionary.add(b"AAAA".to_vec());
    for v in lcg_seq(60) {
        let len = usize::try_from(v).unwrap_or(0) % 64;
        let input: Vec<u8> = (0..len).map(|i| u8::try_from((v >> (i % 8)) & 0xff).unwrap_or(0)).collect();
        for &s in MutationStrategy::all() {
            let out = e.mutate(&input, s);
            assert!(out.len() <= e.max_size);
        }
    }
}

#[test]
fn t39_mutation_engine_respects_max_size_insert() {
    let mut e = MutationEngine::with_seed(1);
    e.max_size = 16;
    let input = vec![0u8; 16];
    let out = e.mutate(&input, MutationStrategy::Insert);
    // Insert is a no-op when at max_size
    assert_eq!(out, input);
}

#[test]
fn t40_mutation_engine_delete_min_size() {
    let mut e = MutationEngine::with_seed(2);
    e.min_size = 4;
    let input = vec![0u8; 4];
    let out = e.mutate(&input, MutationStrategy::Delete);
    assert_eq!(out, input); // no shrink possible
}

#[test]
fn t41_fuzz_rng_determinism_pair() {
    for seed in lcg_seq(30) {
        let mut a = FuzzRng::new(seed);
        let mut b = FuzzRng::new(seed);
        for _ in 0..16 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }
}

#[test]
fn t42_fuzz_rng_next_usize_zero_returns_zero() {
    let mut r = FuzzRng::new(1);
    assert_eq!(r.next_usize(0), 0);
}

// ── 12. PowerSchedule ──────────────────────────────────────────────────────

#[test]
fn t43_power_schedule_all_kinds_bounded() {
    let kinds = [
        PowerScheduleKind::Uniform,
        PowerScheduleKind::CoverageFavored,
        PowerScheduleKind::Recency,
        PowerScheduleKind::Rare,
        PowerScheduleKind::AflFast,
    ];
    for k in kinds {
        let mut ps = PowerSchedule::new(k);
        ps.max_energy = 50;
        for v in lcg_seq(20) {
            let bits = u32::try_from(v & 0xffff_ffff).unwrap_or(0) % 200;
            let m = CorpusMeta::new(v, bits, Duration::from_millis((v % 16) + 1));
            let e = ps.energy(&m, 1000);
            assert!((1..=50).contains(&e), "energy out of range: {e} for {k:?}");
        }
    }
}

// ── 13. Minimizer ──────────────────────────────────────────────────────────

#[test]
fn t44_minimizer_idempotent() {
    let m = Minimizer::new(8);
    let input = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
    // "Interesting" if contains byte 3
    let first = m.minimize(&input, |d| d.contains(&3));
    let second = m.minimize(&first, |d| d.contains(&3));
    assert_eq!(first, second);
    assert!(first.contains(&3));
}

#[test]
fn t45_minimizer_preserves_when_all_needed() {
    let m = Minimizer::new(5);
    let input: Vec<u8> = (0u8..10).collect();
    // Interesting only if all original bytes still present
    let mini = m.minimize(&input, |d| (0u8..10).all(|b| d.contains(&b)));
    assert_eq!(mini, input);
}

#[test]
fn t46_minimizer_tracked_rounds_positive() {
    let m = Minimizer::new(4);
    let input = vec![0u8; 64];
    let (mini, rounds) = m.minimize_tracked(&input, |d| !d.is_empty());
    assert!(rounds >= 1);
    assert!(mini.len() <= input.len());
}

// ── 14. SharedCoverage / Send+Sync stress ──────────────────────────────────

#[test]
fn t47_shared_coverage_threaded_stress() {
    let sc = Arc::new(SharedCoverage::new(64));
    let mut handles = vec![];
    for t in 0..4u64 {
        let sc = Arc::clone(&sc);
        handles.push(thread::spawn(move || {
            let mut s = 0xDEAD_BEEF_CAFE_BABEu64 ^ t;
            for _ in 0..100 {
                s = s
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let buf = s.to_le_bytes();
                let _ = sc.update(&buf);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let _ = sc.total_bits_set();
    let _ = sc.snapshot();
    sc.reset();
    assert_eq!(sc.total_bits_set(), 0);
}

#[test]
fn t48_shared_coverage_hash_matches_snapshot() {
    let sc = SharedCoverage::new(8);
    sc.update(&[0xAA, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    assert_eq!(sc.hash(), sc.snapshot().hash());
}

// ── 15. FuzzCorpusManager ──────────────────────────────────────────────────

#[test]
fn t49_corpus_manager_lcg_fuzz_dedup() {
    let mut m = FuzzCorpusManager::new();
    let seq = lcg_seq(60);
    for v in &seq {
        m.add(v.to_le_bytes().to_vec());
    }
    // All LCG outputs unique → all added
    assert_eq!(m.len(), 60);
    // Re-adding the same payloads must return false
    for v in &seq {
        assert!(!m.add(v.to_le_bytes().to_vec()));
    }
    assert_eq!(m.len(), 60);
}

#[test]
fn t49b_corpus_manager_lcg_bytes_input() {
    let mut m = FuzzCorpusManager::new();
    let bytes = lcg_bytes(32);
    assert_eq!(bytes.len(), 32);
    assert!(m.add(bytes));
}

#[test]
fn t50_corpus_manager_save_load_unique_dir() {
    let dir = std::env::temp_dir().join("rustre_fuzz_blitz2_t50");
    let _ = std::fs::remove_dir_all(&dir);
    let dir_str = dir.to_str().unwrap();
    let mut m = FuzzCorpusManager::new();
    for i in 0..10u8 {
        m.add(vec![i; 4]);
    }
    let saved = m.save_to_dir(dir_str).unwrap();
    assert_eq!(saved, 10);
    let mut m2 = FuzzCorpusManager::new();
    let loaded = m2.load_from_dir(dir_str).unwrap();
    assert_eq!(loaded, 10);
    assert_eq!(m2.len(), 10);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t51_corpus_manager_empty_default() {
    let m = FuzzCorpusManager::default();
    assert!(m.is_empty());
    assert_eq!(m.len(), 0);
}

// ── 16. FuzzMutator ─────────────────────────────────────────────────────────

#[test]
fn t52_fuzz_mutator_determinism() {
    let mut a = FuzzMutator::new(42);
    let mut b = FuzzMutator::new(42);
    let input = vec![1u8, 2, 3, 4, 5];
    for _ in 0..20 {
        assert_eq!(a.bit_flip(&input), b.bit_flip(&input));
    }
}

#[test]
fn t53_fuzz_mutator_lcg_fuzz_never_panics() {
    let mut m = FuzzMutator::new(0xBEEF);
    for v in lcg_seq(60) {
        let len = usize::try_from(v).unwrap_or(0) % 32;
        let input: Vec<u8> = (0..len).map(|i| u8::try_from((v >> (i % 8)) & 0xff).unwrap_or(0)).collect();
        let _ = m.bit_flip(&input);
        let _ = m.byte_flip(&input);
        let _ = m.insert_magic_value(&input);
        let _ = m.splice(&input, &input);
        let _ = m.havoc(&input, 4);
    }
}

#[test]
fn t54_fuzz_mutator_empty_input_returns_empty() {
    let mut m = FuzzMutator::new(1);
    assert!(m.bit_flip(&[]).is_empty());
    assert!(m.byte_flip(&[]).is_empty());
    // insert_magic_value on empty returns just the magic value
    assert!(!m.insert_magic_value(&[]).is_empty());
}

// ── 17. FuzzCrashAnalyzer ──────────────────────────────────────────────────

#[test]
fn t55_crash_analyzer_lcg_dedup() {
    let mut a = FuzzCrashAnalyzer::new();
    let mut crashes = vec![];
    for v in lcg_seq(40) {
        crashes.push(v.to_le_bytes().to_vec());
    }
    // Add duplicates
    crashes.extend(crashes.clone());
    let dedup = a.deduplicate_crashes(crashes);
    assert_eq!(dedup.len(), 40);
}

#[test]
fn t56_crash_analyzer_classify_unique_then_duplicate() {
    let mut a = FuzzCrashAnalyzer::new();
    for v in lcg_seq(30) {
        let bytes = v.to_le_bytes();
        let first = a.classify_crash(&bytes);
        assert!(matches!(first, CrashType::Unique(_)));
        let second = a.classify_crash(&bytes);
        assert!(matches!(second, CrashType::Duplicate(_)));
    }
}

#[test]
fn t57_crash_analyzer_is_interesting_distinguishes() {
    let existing: Vec<Vec<u8>> = lcg_seq(30)
        .iter()
        .map(|v| v.to_le_bytes().to_vec())
        .collect();
    for e in &existing {
        assert!(!FuzzCrashAnalyzer::is_interesting(&existing, e));
    }
    // A genuinely new payload
    assert!(FuzzCrashAnalyzer::is_interesting(&existing, b"truly_new_payload"));
}

// ── 18. FuzzError display ──────────────────────────────────────────────────

#[test]
fn t58_fuzz_error_display() {
    let cases = [
        FuzzError::ExecutionError("e".into()),
        FuzzError::CoverageError("c".into()),
        FuzzError::InputError("i".into()),
        FuzzError::Timeout,
        FuzzError::CorpusError("k".into()),
        FuzzError::MinimizationError("m".into()),
    ];
    for c in cases {
        let s = format!("{c}");
        assert!(!s.is_empty());
    }
}
