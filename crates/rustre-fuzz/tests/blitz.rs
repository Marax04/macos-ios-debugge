//! Blitz integration tests for rustre-fuzz.
//!
//! Targets edge cases, invariants, and adversarial inputs not covered by the
//! crate's internal unit tests.

use std::time::Duration;

use rustre_fuzz::{
    CorpusMeta, Corpus, CoverageMap, CrashDeduplicator, CrashRecord, Dictionary, ExecutionResult,
    ExecutionStatus, FuzzCorpusManager, FuzzCrashAnalyzer, FuzzError, FuzzInput, FuzzMutator,
    FuzzResult, FuzzRng, FuzzerStats, InputQueue, Minimizer, MutationEngine, MutationStrategy,
    PowerSchedule, PowerScheduleKind, SharedCoverage, fnv1a,
};
use rustre_fuzz::grammar_fuzzer::{
    self, BuiltinGrammar, Expansion, Grammar, GrammarFuzzer, GrammarInstance, GrammarMutation,
    Term, builtin_grammar_http11, builtin_grammar_json, get_builtin_grammar, parse_bnf_grammar,
};

// ============================================================================
// fnv1a
// ============================================================================

#[test]
fn fnv1a_empty_is_offset_basis() {
    // Empty input must yield the FNV-1a 64-bit offset basis.
    assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
}

#[test]
fn fnv1a_single_byte_zero() {
    // 0x00 XORed with offset, then multiplied by FNV prime.
    let expected = 0xcbf2_9ce4_8422_2325u64.wrapping_mul(0x0000_0100_0000_01b3);
    assert_eq!(fnv1a(&[0]), expected);
}

#[test]
fn fnv1a_collisions_are_rare_on_small_set() {
    use std::collections::HashSet;
    let mut hs = HashSet::new();
    for i in 0u32..2000 {
        hs.insert(fnv1a(&i.to_le_bytes()));
    }
    assert_eq!(hs.len(), 2000);
}

// ============================================================================
// FuzzInput
// ============================================================================

#[test]
fn fuzz_input_derive_saturates_generation() {
    let mut inp = FuzzInput::new(0, vec![1]);
    inp.generation = u32::MAX;
    let child = inp.derive(1, vec![2]);
    assert_eq!(child.generation, u32::MAX, "generation must saturate, not overflow");
}

#[test]
fn fuzz_input_eq_ignores_nothing() {
    let a = FuzzInput::new(0, vec![1]);
    let b = FuzzInput::new(0, vec![1]);
    assert_eq!(a, b);
    let c = FuzzInput::new(1, vec![1]);
    assert_ne!(a, c);
}

#[test]
fn fuzz_input_serde_roundtrip() {
    let inp = FuzzInput::new_with_origin(42, vec![1, 2, 3], "test");
    let json = serde_json::to_string(&inp).unwrap();
    let back: FuzzInput = serde_json::from_str(&json).unwrap();
    assert_eq!(inp, back);
}

// ============================================================================
// FuzzResult / ExecutionStatus
// ============================================================================

#[test]
fn fuzz_result_normal_is_not_crash_or_interesting() {
    let r = FuzzResult::Normal;
    assert!(!r.is_crash());
    assert!(!r.is_interesting());
    assert!(r.is_normal());
}

#[test]
fn execution_status_timeout_is_hang_not_crash() {
    assert!(ExecutionStatus::Timeout.is_hang());
    assert!(!ExecutionStatus::Timeout.is_crash());
    assert!(!ExecutionStatus::Timeout.is_normal());
}

// ============================================================================
// CoverageMap
// ============================================================================

#[test]
fn coverage_map_zero_size() {
    let mut m = CoverageMap::new(0);
    assert_eq!(m.bits.len(), 0);
    assert_eq!(m.update(&[]), 0);
    assert!(m.is_empty());
    assert_eq!(m.total_bits_set(), 0);
}

#[test]
fn coverage_map_update_shorter_new_bits() {
    // new_bits shorter than map should not panic and only count what's there.
    let mut m = CoverageMap::new(8);
    let new_bits = vec![0xff, 0xff];
    let bits = m.update(&new_bits);
    assert_eq!(bits, 16);
}

#[test]
fn coverage_map_update_longer_new_bits() {
    // new_bits longer than map should not panic (truncated to map size).
    let mut m = CoverageMap::new(2);
    let new_bits = vec![0xff; 100];
    let bits = m.update(&new_bits);
    assert_eq!(bits, 16);
}

#[test]
fn coverage_map_hit_counts_saturate_at_255() {
    let mut m = CoverageMap::new(1);
    for _ in 0..300 {
        m.update(&[0b0000_0001]);
    }
    assert_eq!(m.hit_counts[0], 255, "hit_counts must saturate at u8::MAX");
}

#[test]
fn coverage_map_edge_hit_count_out_of_range() {
    let m = CoverageMap::new(1);
    // Edge index way beyond range — must return 0, not panic.
    assert_eq!(m.edge_hit_count(99999), 0);
}

#[test]
fn coverage_map_reset_clears_hit_counts() {
    let mut m = CoverageMap::new(2);
    m.update(&[0xff, 0xff]);
    m.reset();
    assert!(m.hit_counts.iter().all(|&c| c == 0));
    assert_eq!(m.bits_set_since_last_reset(), 0);
}

#[test]
fn coverage_map_cumulative_alias_matches() {
    let mut m = CoverageMap::new(2);
    m.update(&[0x0f, 0]);
    assert_eq!(m.cumulative_bits_set(), m.bits_set_since_last_reset());
}

#[test]
fn coverage_map_merge_with_self_is_idempotent() {
    let mut m = CoverageMap::new(4);
    m.update(&[0x0f, 0x0f, 0x0f, 0x0f]);
    let snap = m.clone();
    let novel = m.merge(&snap);
    assert_eq!(novel, 0);
}

// ============================================================================
// InputQueue
// ============================================================================

#[test]
#[should_panic(expected = "InputQueue::select called on empty queue")]
fn input_queue_select_empty_panics() {
    let mut q = InputQueue::new();
    let _ = q.select();
}

#[test]
fn input_queue_select_increments_executions() {
    let mut q = InputQueue::new();
    q.add(FuzzInput::new(0, vec![1]), false);
    let before = q.total_executions;
    let _ = q.select();
    assert_eq!(q.total_executions, before + 1);
}

#[test]
fn input_queue_remove_nonexistent() {
    let mut q = InputQueue::new();
    q.add(FuzzInput::new(0, vec![1]), false);
    assert!(q.remove(999).is_none());
    assert_eq!(q.len(), 1);
}

#[test]
fn input_queue_select_cursor_round_robin() {
    let mut queue = InputQueue::new();
    queue.add(FuzzInput::new(0, vec![1]), false);
    queue.add(FuzzInput::new(1, vec![2]), false);
    queue.add(FuzzInput::new(2, vec![3]), false);
    let first = queue.select_cursor().id;
    let second = queue.select_cursor().id;
    let third = queue.select_cursor().id;
    let fourth = queue.select_cursor().id;
    // After 3 calls we should cycle; fourth should equal first.
    assert_eq!(first, fourth);
    // and first, second, third should be distinct
    let mut all = vec![first, second, third];
    all.sort_unstable();
    assert_eq!(all, vec![0, 1, 2]);
}

// ============================================================================
// FuzzerStats
// ============================================================================

#[test]
fn fuzzer_stats_max_input_len_only_grows() {
    let mut s = FuzzerStats::new();
    s.record_execution(100);
    s.record_execution(10);
    assert_eq!(s.max_input_len, 100);
}

// ============================================================================
// Corpus
// ============================================================================

#[test]
fn corpus_prune_keeps_root() {
    let mut c = Corpus::new();
    let root = FuzzInput::new(0, vec![1]); // parent == None
    let mut child = FuzzInput::new(1, vec![2]);
    child.parent = Some(0);
    c.add_input(root, CorpusMeta::new(1, 0, Duration::ZERO));
    c.add_input(child, CorpusMeta::new(2, 0, Duration::ZERO));
    // prune below cov=5: child has 0, should be removed; root kept.
    let _removed = c.prune(5);
    assert!(c.inputs.iter().any(|i| i.id == 0), "root must be retained");
}

#[test]
fn corpus_unique_coverage_hashes_counts_distinct() {
    let mut c = Corpus::new();
    c.add_input(FuzzInput::new(0, vec![]), CorpusMeta::new(1, 0, Duration::ZERO));
    c.add_input(FuzzInput::new(1, vec![]), CorpusMeta::new(2, 0, Duration::ZERO));
    c.add_input(FuzzInput::new(2, vec![]), CorpusMeta::new(1, 0, Duration::ZERO));
    assert_eq!(c.unique_coverage_hashes(), 2);
}

#[test]
fn corpus_get_entry_missing_returns_none() {
    let c = Corpus::new();
    assert!(c.get_entry(123).is_none());
}

// ============================================================================
// CrashDeduplicator
// ============================================================================

#[test]
fn crash_dedup_iter_preserves_insertion_order() {
    let mut d = CrashDeduplicator::new();
    d.submit(vec![1], 11, None, 10);
    d.submit(vec![2], 11, None, 20);
    d.submit(vec![3], 11, None, 30);
    let ids: Vec<u64> = d.iter().map(|r| r.coverage_hash).collect();
    assert_eq!(ids, vec![10, 20, 30]);
}

#[test]
fn crash_dedup_duplicate_increments_occurrence() {
    let mut d = CrashDeduplicator::new();
    d.submit(vec![1], 11, None, 100);
    d.submit(vec![1], 11, None, 100);
    d.submit(vec![1], 11, None, 100);
    let mc = d.most_common().unwrap();
    assert_eq!(mc.occurrence_count, 3);
}

#[test]
fn crash_dedup_clear_resets_state() {
    let mut d = CrashDeduplicator::new();
    d.submit(vec![1], 11, None, 100);
    d.clear();
    // After clear, the same input should be considered new again.
    assert!(d.submit(vec![1], 11, None, 100));
}

#[test]
fn crash_record_set_stack_hash_changes_dedup_key() {
    let mut r = CrashRecord::new(0, vec![], 11, None, 0xAAAA);
    assert_eq!(r.dedup_key(), 0xAAAA);
    r.set_stack_hash(&[0x1, 0x2]);
    assert_ne!(r.dedup_key(), 0xAAAA);
}

// ============================================================================
// MutationStrategy
// ============================================================================

#[test]
fn mutation_strategy_all_names_unique() {
    use std::collections::HashSet;
    let names: HashSet<&str> = MutationStrategy::all().iter().map(|s| s.name()).collect();
    assert_eq!(names.len(), MutationStrategy::all().len());
}

#[test]
fn mutation_strategy_display_matches_name() {
    for &s in MutationStrategy::all() {
        assert_eq!(s.to_string(), s.name());
    }
}

#[test]
fn mutation_strategy_hash_consistent() {
    use std::collections::HashMap;
    let mut m: HashMap<MutationStrategy, u32> = HashMap::new();
    m.insert(MutationStrategy::BitFlip, 1);
    m.insert(MutationStrategy::BitFlip, 2);
    assert_eq!(m.len(), 1);
    assert_eq!(m[&MutationStrategy::BitFlip], 2);
}

// ============================================================================
// Dictionary
// ============================================================================

#[test]
fn dictionary_load_invalid_hex_returns_input_error() {
    let mut d = Dictionary::new();
    let err = d.load_from_text("x\"zz\"\n").unwrap_err();
    assert!(matches!(err, FuzzError::InputError(_)), "got {err:?}");
}

#[test]
fn dictionary_load_blank_and_comment_lines_skipped() {
    let mut d = Dictionary::new();
    let n = d.load_from_text("\n# a comment\n   \nhello\n").unwrap();
    assert_eq!(n, 1);
}

#[test]
fn dictionary_get_wrapping_with_idx_wraps() {
    let mut d = Dictionary::new();
    d.add(vec![1]);
    d.add(vec![2]);
    d.add(vec![3]);
    assert_eq!(d.get_wrapping(0).unwrap(), &[1]);
    assert_eq!(d.get_wrapping(3).unwrap(), &[1]);
    assert_eq!(d.get_wrapping(7).unwrap(), &[2]);
}

// ============================================================================
// MutationEngine
// ============================================================================

#[test]
fn engine_mutate_all_strategies_no_panic_empty_input() {
    let mut e = MutationEngine::with_seed(1);
    for &s in MutationStrategy::all() {
        let _ = e.mutate(&[], s);
    }
}

#[test]
fn engine_mutate_all_strategies_no_panic_single_byte() {
    let mut e = MutationEngine::with_seed(1);
    for &s in MutationStrategy::all() {
        let _ = e.mutate(&[0x42], s);
    }
}

#[test]
fn engine_dictionary_mutation_empty_dict_returns_copy() {
    let mut e = MutationEngine::with_seed(2);
    let input = vec![1, 2, 3];
    let out = e.mutate(&input, MutationStrategy::Dictionary);
    assert_eq!(out, input);
}

#[test]
fn engine_splice_two_empty_first() {
    let mut e = MutationEngine::with_seed(3);
    let out = e.splice_two(&[], &[1, 2, 3]);
    assert_eq!(out, vec![1, 2, 3]);
}

#[test]
fn engine_splice_two_empty_second() {
    let mut e = MutationEngine::with_seed(4);
    let out = e.splice_two(&[1, 2, 3], &[]);
    assert_eq!(out, vec![1, 2, 3]);
}

#[test]
fn engine_delete_respects_min_size() {
    let mut e = MutationEngine::with_seed(5);
    e.min_size = 5;
    let input = vec![0u8; 5];
    let out = e.mutate(&input, MutationStrategy::Delete);
    assert_eq!(out.len(), 5, "delete must not go below min_size");
}

#[test]
fn engine_insert_respects_max_size() {
    let mut e = MutationEngine::with_seed(6);
    e.max_size = 8;
    let input = vec![0u8; 8];
    let out = e.mutate(&input, MutationStrategy::Insert);
    assert_eq!(out, input, "insert at max size returns unchanged");
}

#[test]
fn engine_total_mutations_counts_all_calls() {
    let mut e = MutationEngine::with_seed(7);
    for _ in 0..50 {
        let _ = e.mutate(&[1, 2, 3, 4, 5, 6, 7, 8], MutationStrategy::Havoc);
    }
    assert_eq!(e.total_mutations, 50);
}

#[test]
fn engine_best_strategy_none_when_no_hits() {
    let e = MutationEngine::with_seed(8);
    assert!(e.best_strategy().is_none());
}

#[test]
fn engine_reverse_short_input_no_change() {
    let mut e = MutationEngine::with_seed(9);
    let out = e.mutate(&[0x42], MutationStrategy::Reverse);
    assert_eq!(out, vec![0x42]);
}

// ============================================================================
// PowerSchedule
// ============================================================================

#[test]
fn power_schedule_energy_always_ge_one() {
    for kind in [
        PowerScheduleKind::Uniform,
        PowerScheduleKind::CoverageFavored,
        PowerScheduleKind::Recency,
        PowerScheduleKind::Rare,
        PowerScheduleKind::AflFast,
    ] {
        let ps = PowerSchedule::new(kind);
        let meta = CorpusMeta::new(0, 0, Duration::ZERO);
        assert!(ps.energy(&meta, 0) >= 1, "kind {kind:?} returned <1");
        assert!(ps.energy(&meta, 100) >= 1);
    }
}

#[test]
fn power_schedule_zero_global_bits() {
    let ps = PowerSchedule::new(PowerScheduleKind::CoverageFavored);
    let m = CorpusMeta::new(0, 10, Duration::ZERO);
    let e = ps.energy(&m, 0);
    assert!(e >= 1);
}

#[test]
fn power_schedule_never_exceeds_max() {
    let mut ps = PowerSchedule::new(PowerScheduleKind::AflFast);
    ps.max_energy = 5;
    let meta = CorpusMeta::new(0, 1_000_000, Duration::from_nanos(1));
    assert!(ps.energy(&meta, 100) <= 5);
}

// ============================================================================
// Minimizer
// ============================================================================

#[test]
fn minimizer_returns_input_when_never_interesting() {
    let m = Minimizer::new(10);
    let input = vec![1u8, 2, 3, 4, 5];
    let mini = m.minimize(&input, |_| false);
    // Trimming never accepts → result is unchanged or smaller? Actually trim_pass
    // only accepts when interesting; thus original returned.
    assert_eq!(mini, input);
}

#[test]
fn minimizer_min_size_respected() {
    let mut m = Minimizer::new(20);
    m.min_size = 3;
    let mini = m.minimize(&[0u8; 10], |_| true);
    assert!(mini.len() >= 3);
}

#[test]
fn minimizer_tracked_rounds_ge_one() {
    let m = Minimizer::new(5);
    let (_out, rounds) = m.minimize_tracked(&[1u8, 2, 3, 4, 5, 6, 7, 8], |_| true);
    assert!(rounds >= 1);
}

// ============================================================================
// FuzzRng
// ============================================================================

#[test]
fn fuzz_rng_next_usize_zero_returns_zero() {
    let mut r = FuzzRng::new(123);
    assert_eq!(r.next_usize(0), 0);
}

#[test]
fn fuzz_rng_one_in_one_always_true() {
    let mut r = FuzzRng::new(7);
    for _ in 0..50 {
        assert!(r.one_in(1));
    }
}

#[test]
fn fuzz_rng_different_seeds_different_streams() {
    let mut a = FuzzRng::new(1);
    let mut b = FuzzRng::new(2);
    assert_ne!(a.next_u64(), b.next_u64());
}

// ============================================================================
// SharedCoverage (Send/Sync)
// ============================================================================

#[test]
fn shared_coverage_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SharedCoverage>();
}

#[test]
fn shared_coverage_concurrent_updates() {
    use std::sync::Arc;
    use std::thread;
    let sc = Arc::new(SharedCoverage::new(8));
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let sc = sc.clone();
            thread::spawn(move || {
                sc.update(&[1u8 << (i % 8); 8]);
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert!(sc.total_bits_set() > 0);
}

#[test]
fn shared_coverage_reset_works() {
    let sc = SharedCoverage::new(4);
    sc.update(&[0xff, 0xff, 0, 0]);
    sc.reset();
    assert_eq!(sc.total_bits_set(), 0);
}

// ============================================================================
// FuzzCorpusManager
// ============================================================================

#[test]
fn fcm_empty_state() {
    let m = FuzzCorpusManager::new();
    assert!(m.is_empty());
    assert_eq!(m.len(), 0);
}

#[test]
fn fcm_add_empty_input() {
    let mut m = FuzzCorpusManager::new();
    assert!(m.add(vec![]));
    assert!(!m.add(vec![]));
    assert_eq!(m.len(), 1);
}

#[test]
fn fcm_remove_redundant_no_op_when_empty() {
    let mut m = FuzzCorpusManager::new();
    assert_eq!(m.remove_redundant(), 0);
}

#[test]
fn fcm_load_from_nonexistent_dir_is_error() {
    let mut m = FuzzCorpusManager::new();
    let res = m.load_from_dir("c:/nonexistent_dir_for_rustre_fuzz_test_999");
    assert!(res.is_err());
}

#[test]
fn fcm_save_load_preserves_content() {
    let dir = std::env::temp_dir().join("rustre_fuzz_blitz_corpus");
    let _ = std::fs::remove_dir_all(&dir);
    let dir_s = dir.to_str().unwrap();
    let mut a = FuzzCorpusManager::new();
    a.add(vec![1, 2, 3]);
    a.add(vec![9, 8, 7, 6]);
    a.save_to_dir(dir_s).unwrap();

    let mut b = FuzzCorpusManager::new();
    let n = b.load_from_dir(dir_s).unwrap();
    assert_eq!(n, 2);
    assert_eq!(b.len(), 2);

    // Re-loading should return 0 new because they'd be duplicates.
    let n2 = b.load_from_dir(dir_s).unwrap();
    assert_eq!(n2, 0);
}

// ============================================================================
// FuzzMutator (standalone primitives)
// ============================================================================

#[test]
fn fuzz_mutator_bit_flip_empty_returns_empty() {
    let mut m = FuzzMutator::new(1);
    assert!(m.bit_flip(&[]).is_empty());
}

#[test]
fn fuzz_mutator_byte_flip_empty_returns_empty() {
    let mut m = FuzzMutator::new(2);
    assert!(m.byte_flip(&[]).is_empty());
}

#[test]
fn fuzz_mutator_splice_both_empty() {
    let mut m = FuzzMutator::new(3);
    assert!(m.splice(&[], &[]).is_empty());
}

#[test]
fn fuzz_mutator_insert_magic_increases_length() {
    let mut m = FuzzMutator::new(4);
    let input = vec![0u8; 4];
    let out = m.insert_magic_value(&input);
    assert!(out.len() > input.len());
}

#[test]
fn fuzz_mutator_determinism_same_seed() {
    let mut a = FuzzMutator::new(99);
    let mut b = FuzzMutator::new(99);
    let input = vec![1, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(a.havoc(&input, 5), b.havoc(&input, 5));
}

#[test]
fn fuzz_mutator_havoc_zero_iterations_unchanged() {
    let mut m = FuzzMutator::new(5);
    let input = vec![1, 2, 3];
    assert_eq!(m.havoc(&input, 0), input);
}

// ============================================================================
// FuzzCrashAnalyzer
// ============================================================================

#[test]
fn analyzer_empty_input_is_unique_then_duplicate() {
    use rustre_fuzz::CrashType;
    let mut a = FuzzCrashAnalyzer::new();
    let first = a.classify_crash(&[]);
    let second = a.classify_crash(&[]);
    assert!(matches!(first, CrashType::Unique(_)));
    assert!(matches!(second, CrashType::Duplicate(_)));
}

#[test]
fn analyzer_deduplicate_empty_input() {
    let mut a = FuzzCrashAnalyzer::new();
    let out = a.deduplicate_crashes(vec![]);
    assert!(out.is_empty());
}

#[test]
fn analyzer_deduplicate_preserves_order() {
    let mut a = FuzzCrashAnalyzer::new();
    let inputs = vec![vec![3u8], vec![1u8], vec![2u8], vec![1u8]];
    let out = a.deduplicate_crashes(inputs);
    assert_eq!(out, vec![vec![3u8], vec![1u8], vec![2u8]]);
}

#[test]
fn analyzer_is_interesting_empty_existing() {
    assert!(FuzzCrashAnalyzer::is_interesting(&[], &[1, 2, 3]));
}

// ============================================================================
// ExecutionResult constructors
// ============================================================================

#[test]
fn execution_result_constructors_set_time() {
    let n = ExecutionResult::normal(Duration::from_millis(42));
    assert_eq!(n.execution_time, Duration::from_millis(42));
    let c = ExecutionResult::crash(11, Some(0xff), Duration::from_millis(7));
    assert_eq!(c.execution_time, Duration::from_millis(7));
    assert!(c.status.is_crash());
}

// ============================================================================
// grammar_fuzzer
// ============================================================================

#[test]
fn parse_bnf_grammar_empty_text() {
    let g = parse_bnf_grammar("");
    assert!(g.rules.is_empty());
}

#[test]
fn parse_bnf_grammar_basic_rule() {
    let g = parse_bnf_grammar("greeting ::= \"hello\" | \"hi\"\n");
    assert!(g.has_rule("greeting"));
    assert_eq!(g.rules["greeting"].len(), 2);
}

#[test]
fn parse_bnf_grammar_skips_comments_and_blanks() {
    let g = parse_bnf_grammar("# comment\n\nfoo ::= \"x\"\n");
    assert!(g.has_rule("foo"));
    assert!(!g.has_rule("# comment"));
}

#[test]
fn parse_bnf_grammar_malformed_line_skipped() {
    // No ::= → should be skipped, not panic.
    let g = parse_bnf_grammar("this is not a rule\nfoo ::= \"x\"\n");
    assert_eq!(g.rules.len(), 1);
    assert!(g.has_rule("foo"));
}

#[test]
fn grammar_new_is_empty() {
    let g = Grammar::new();
    assert!(g.rules.is_empty());
    assert!(!g.has_rule("anything"));
}

#[test]
fn grammar_add_rule_overwrites() {
    let mut g = Grammar::new();
    g.add_rule("r", vec![Expansion::single(Term::terminal("a"))]);
    g.add_rule("r", vec![Expansion::single(Term::terminal("b"))]);
    assert_eq!(g.rules["r"].len(), 1);
}

#[test]
fn grammar_instance_zero_seed_replaced() {
    let g = builtin_grammar_json();
    let mut inst = GrammarInstance::new(g, 0);
    // Should not get stuck producing nothing forever and not panic.
    let s = inst.generate("value", 4);
    let _ = s;
}

#[test]
fn grammar_instance_missing_start_returns_empty() {
    let g = Grammar::new();
    let mut inst = GrammarInstance::new(g, 42);
    assert_eq!(inst.generate("nonexistent", 3), "");
}

#[test]
fn grammar_fuzzer_generate_corpus_count() {
    let mut f = GrammarFuzzer::new(builtin_grammar_http11(), "request", 5, 1);
    let v = f.generate_corpus(7);
    assert_eq!(v.len(), 7);
}

#[test]
fn grammar_fuzzer_generated_http_contains_method() {
    let mut f = GrammarFuzzer::new(builtin_grammar_http11(), "request", 5, 1);
    let req = f.generate_one();
    let methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"];
    assert!(
        methods.iter().any(|m| req.starts_with(m)),
        "generated HTTP request must start with a method, got {req:?}"
    );
}

#[test]
fn grammar_fuzzer_generated_json_nonempty() {
    let mut f = GrammarFuzzer::new(builtin_grammar_json(), "value", 4, 7);
    let v = f.generate_one();
    assert!(!v.is_empty());
}

#[test]
fn grammar_get_builtin_grammars_all_nonempty() {
    for g in [
        get_builtin_grammar(BuiltinGrammar::Http11Request),
        get_builtin_grammar(BuiltinGrammar::JsonValue),
        get_builtin_grammar(BuiltinGrammar::SqlSelect),
        get_builtin_grammar(BuiltinGrammar::XmlDocument),
        get_builtin_grammar(BuiltinGrammar::CommandLine),
    ] {
        assert!(!g.rules.is_empty());
    }
}

#[test]
fn grammar_module_generate_corpus_unknown_falls_back_to_json() {
    // Per source: unknown name falls back to JSON-style grammar.
    let v = grammar_fuzzer::generate_corpus("nonexistent_grammar_name", 3, 42);
    assert_eq!(v.len(), 3);
}

#[test]
fn grammar_mutation_does_not_panic_on_empty() {
    let mut g = Grammar::new();
    let mut rng = 12345u64;
    GrammarMutation::mutate_grammar(&mut g, &mut rng); // empty rules → no-op
    assert!(g.rules.is_empty());
}

#[test]
fn grammar_mutation_alters_a_terminal() {
    let mut g = Grammar::new();
    g.add_rule(
        "r",
        vec![Expansion::single(Term::terminal("orig"))],
    );
    let mut rng = 1u64;
    GrammarMutation::mutate_grammar(&mut g, &mut rng);
    // Should have appended __mutated to the terminal.
    if let Term::Terminal(s) = &g.rules["r"][0].terms[0] {
        assert!(s.contains("__mutated"), "got {s:?}");
    } else {
        panic!("expected Terminal");
    }
}

#[test]
fn grammar_term_repeat_min_eq_max_works() {
    // Bug surface: Term::Repeat uses `max - min`; equal values should be fine.
    let mut g = Grammar::new();
    g.add_rule(
        "r",
        vec![Expansion::single(Term::repeat(Term::terminal("x"), 3, 3))],
    );
    let mut inst = GrammarInstance::new(g, 42);
    let out = inst.generate("r", 5);
    assert_eq!(out, "xxx");
}

#[test]
fn grammar_term_optional_eventually_present_and_absent() {
    let mut g = Grammar::new();
    g.add_rule(
        "r",
        vec![Expansion::single(Term::optional(Term::terminal("Q")))],
    );
    let mut inst = GrammarInstance::new(g, 1);
    let mut saw_empty = false;
    let mut saw_q = false;
    for _ in 0..200 {
        let s = inst.generate("r", 5);
        if s.is_empty() {
            saw_empty = true;
        } else if s == "Q" {
            saw_q = true;
        }
        if saw_empty && saw_q {
            break;
        }
    }
    assert!(saw_empty && saw_q, "Optional must produce both branches");
}

#[test]
fn grammar_term_choice_picks_one() {
    let mut g = Grammar::new();
    g.add_rule(
        "r",
        vec![Expansion::single(Term::choice(vec![
            Term::terminal("A"),
            Term::terminal("B"),
        ]))],
    );
    let mut inst = GrammarInstance::new(g, 1);
    for _ in 0..20 {
        let s = inst.generate("r", 3);
        assert!(s == "A" || s == "B", "got {s:?}");
    }
}
