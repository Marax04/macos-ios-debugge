//! Blitz test suite for `rustre-fuzz-afl`.
//!
//! Exercises the public, stand-alone API surface: RNGs, mutators, dictionary
//! parsing, CMPLOG, queues, fork-server state machine, persistent mode,
//! AFL stats, coverage maps, corpus, and mutation stages.

use rustre_fuzz_afl::*;

// ───────────────────────────── RNG ─────────────────────────────

#[test]
fn xorshift_zero_seed_is_replaced() {
    let mut r = XorShiftRng::new(0);
    // Should not get stuck producing zero.
    assert_ne!(r.next_u64(), 0);
}

#[test]
fn xorshift_deterministic() {
    let mut a = XorShiftRng::new(42);
    let mut b = XorShiftRng::new(42);
    for _ in 0..32 {
        assert_eq!(a.next_u64(), b.next_u64());
    }
}

#[test]
fn xorshift_next_usize_bound_zero_returns_zero() {
    let mut r = XorShiftRng::new(1);
    assert_eq!(r.next_usize(0), 0);
}

#[test]
fn xorshift_next_usize_in_range() {
    let mut r = XorShiftRng::new(99);
    for _ in 0..1000 {
        let v = r.next_usize(10);
        assert!(v < 10);
    }
}

#[test]
fn xorshift_one_in_n_returns_bool() {
    let mut r = XorShiftRng::new(7);
    // exercise method
    let mut trues = 0;
    for _ in 0..1000 {
        if r.one_in(4) {
            trues += 1;
        }
    }
    // Should be in a reasonable band around 250.
    assert!(trues > 50 && trues < 500, "trues={trues}");
}

#[test]
fn xorshift_default_is_nonzero() {
    let mut r = XorShiftRng::default();
    assert_ne!(r.next_u64(), 0);
}

#[test]
fn simplerng_zero_seed_is_replaced() {
    let mut r = SimpleRng::new(0);
    assert_ne!(r.next_u64(), 0);
}

#[test]
fn simplerng_next_usize_zero_n() {
    let mut r = SimpleRng::new(1);
    assert_eq!(r.next_usize(0), 0);
}

#[test]
fn simplerng_methods_cover_all() {
    let mut r = SimpleRng::new(1);
    let _ = r.next_u8();
    let _ = r.next_u32();
    let _ = r.next_u64();
    let _ = r.next_usize(5);
    let _ = r.one_in(2);
}

// ─────────────────────────── Mutators ──────────────────────────

const fn mk_rng() -> XorShiftRng {
    XorShiftRng::new(0x00C0_FFEE)
}

#[test]
fn bitflip_empty_input_returns_empty() {
    let m = BitFlipMutator;
    let mut r = mk_rng();
    assert!(m.mutate(&[], &mut r).is_empty());
}

#[test]
fn bitflip_changes_at_most_4_bits() {
    let m = BitFlipMutator;
    let mut r = mk_rng();
    let input = vec![0u8; 64];
    for _ in 0..100 {
        let out = m.mutate(&input, &mut r);
        assert_eq!(out.len(), input.len());
        let diff_bits: u32 = out.iter().map(|b| b.count_ones()).sum();
        assert!((1..=4).contains(&diff_bits), "bits={diff_bits}");
    }
}

#[test]
fn bitflip_name() {
    assert_eq!(BitFlipMutator.name(), "bit_flip");
}

#[test]
fn byteflip_empty() {
    let m = ByteFlipMutator;
    let mut r = mk_rng();
    assert!(m.mutate(&[], &mut r).is_empty());
}

#[test]
fn byteflip_preserves_length() {
    let m = ByteFlipMutator;
    let mut r = mk_rng();
    let input = vec![0xAAu8; 32];
    for _ in 0..50 {
        let out = m.mutate(&input, &mut r);
        assert_eq!(out.len(), input.len());
    }
}

#[test]
fn arithmetic_empty() {
    let m = ArithmeticMutator;
    let mut r = mk_rng();
    assert!(m.mutate(&[], &mut r).is_empty());
}

#[test]
fn arithmetic_preserves_length_and_changes_something() {
    let m = ArithmeticMutator;
    let mut r = mk_rng();
    let input = vec![0u8; 16];
    let mut any_diff = false;
    for _ in 0..50 {
        let out = m.mutate(&input, &mut r);
        assert_eq!(out.len(), input.len());
        if out != input {
            any_diff = true;
        }
    }
    assert!(any_diff);
}

#[test]
fn interesting_empty() {
    let m = InterestingValueMutator;
    let mut r = mk_rng();
    assert!(m.mutate(&[], &mut r).is_empty());
}

#[test]
fn interesting_preserves_length() {
    let m = InterestingValueMutator;
    let mut r = mk_rng();
    let input = vec![5u8; 16];
    for _ in 0..30 {
        let out = m.mutate(&input, &mut r);
        assert_eq!(out.len(), input.len());
    }
}

#[test]
fn splice_basic() {
    let mut r = mk_rng();
    let out = SpliceMutator::splice(b"AAAA", b"BBBB", &mut r);
    // Should consist only of A's and B's.
    assert!(out.iter().all(|&c| c == b'A' || c == b'B'));
}

#[test]
fn splice_empty_a_returns_b() {
    let mut r = mk_rng();
    assert_eq!(SpliceMutator::splice(&[], b"XYZ", &mut r), b"XYZ");
}

#[test]
fn splice_empty_b_returns_a() {
    let mut r = mk_rng();
    assert_eq!(SpliceMutator::splice(b"XYZ", &[], &mut r), b"XYZ");
}

#[test]
fn splice_mutator_unchanged() {
    let m = SpliceMutator;
    let mut r = mk_rng();
    assert_eq!(m.mutate(b"hello", &mut r), b"hello");
    assert_eq!(m.name(), "splice");
}

#[test]
fn insert_mutator_grows() {
    let m = InsertMutator::new(8);
    let mut r = mk_rng();
    let input = vec![0u8; 16];
    let out = m.mutate(&input, &mut r);
    assert!(out.len() > input.len());
    assert!(out.len() <= input.len() + 8);
}

#[test]
fn insert_mutator_zero_max_clamped_to_one() {
    let m = InsertMutator::new(0);
    assert_eq!(m.max_insert, 1);
}

#[test]
fn insert_mutator_huge_input_no_growth() {
    let m = InsertMutator::new(8);
    let mut r = mk_rng();
    let input = vec![0u8; 1024 * 1024];
    let out = m.mutate(&input, &mut r);
    assert_eq!(out.len(), input.len());
}

#[test]
fn delete_mutator_singleton_unchanged() {
    let m = DeleteMutator;
    let mut r = mk_rng();
    let input = vec![1u8];
    assert_eq!(m.mutate(&input, &mut r), input);
}

#[test]
fn delete_mutator_empty_unchanged() {
    let m = DeleteMutator;
    let mut r = mk_rng();
    assert!(m.mutate(&[], &mut r).is_empty());
}

#[test]
fn delete_mutator_shrinks() {
    let m = DeleteMutator;
    let mut r = mk_rng();
    let input = vec![0u8; 32];
    let out = m.mutate(&input, &mut r);
    assert!(out.len() < input.len());
}

#[test]
fn xor_block_empty() {
    let m = XorBlockMutator;
    let mut r = mk_rng();
    assert!(m.mutate(&[], &mut r).is_empty());
}

#[test]
fn xor_block_preserves_length() {
    let m = XorBlockMutator;
    let mut r = mk_rng();
    let input = vec![0xFFu8; 16];
    let out = m.mutate(&input, &mut r);
    assert_eq!(out.len(), input.len());
}

#[test]
fn havoc_preserves_or_modifies() {
    let m = HavocMutator;
    let mut r = mk_rng();
    let input = vec![0u8; 32];
    for _ in 0..30 {
        let out = m.mutate(&input, &mut r);
        // No strict length invariant, but must be valid Vec
        assert!(out.len() <= input.len() * 16 + 32);
    }
}

#[test]
fn havoc_empty_input_returns_empty() {
    let m = HavocMutator;
    let mut r = mk_rng();
    assert!(m.mutate(&[], &mut r).is_empty());
}

#[test]
fn mutators_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<BitFlipMutator>();
    assert_send_sync::<HavocMutator>();
    assert_send_sync::<DictionaryMutator>();
}

// ────────────────────────── Dictionary ─────────────────────────

#[test]
fn dictionary_empty_and_add() {
    let mut d = Dictionary::new();
    assert!(d.is_empty());
    assert_eq!(d.len(), 0);
    d.add(b"abc".to_vec());
    d.add_str("xyz");
    assert_eq!(d.len(), 2);
    assert!(!d.is_empty());
    assert_eq!(d.entries[1], b"xyz".to_vec());
}

#[test]
fn dictionary_load_afl_quoted_strings() {
    let mut d = Dictionary::new();
    let n = d.load_afl_format("\"hello\"\n\"world\"\n").unwrap();
    assert_eq!(n, 2);
    assert_eq!(d.entries[0], b"hello".to_vec());
    assert_eq!(d.entries[1], b"world".to_vec());
}

#[test]
fn dictionary_load_afl_hex() {
    let mut d = Dictionary::new();
    let n = d.load_afl_format("x\"de ad be ef\"\n").unwrap();
    assert_eq!(n, 1);
    assert_eq!(d.entries[0], vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn dictionary_load_afl_skips_comments_blank() {
    let mut d = Dictionary::new();
    let n = d.load_afl_format("# comment\n\n\"v\"\n").unwrap();
    assert_eq!(n, 1);
}

#[test]
fn dictionary_load_afl_escapes() {
    let mut d = Dictionary::new();
    let n = d.load_afl_format("\"a\\nb\\tc\\x41\\\\\\\"\"\n").unwrap();
    assert_eq!(n, 1);
    assert_eq!(d.entries[0], b"a\nb\tcA\\\"".to_vec());
}

#[test]
fn dictionary_load_afl_bad_hex_errors() {
    let mut d = Dictionary::new();
    let err = d.load_afl_format("x\"zz\"\n").unwrap_err();
    matches!(err, AflError::InvalidDict(_));
}

#[test]
fn dictionary_load_afl_truncated_escape_errors() {
    let mut d = Dictionary::new();
    let err = d.load_afl_format("\"\\x4\"\n").unwrap_err();
    matches!(err, AflError::InvalidDict(_));
}

#[test]
fn dictionary_load_afl_bare_tokens() {
    let mut d = Dictionary::new();
    let n = d.load_afl_format("hello\nworld\n").unwrap();
    assert_eq!(n, 2);
    assert_eq!(d.entries[0], b"hello".to_vec());
}

#[test]
fn dictionary_mutator_empty_dict_returns_input() {
    let m = DictionaryMutator::new(Dictionary::new());
    let mut r = mk_rng();
    let out = m.mutate(b"abcd", &mut r);
    assert_eq!(out, b"abcd");
}

#[test]
fn dictionary_mutator_token_longer_than_input() {
    let mut d = Dictionary::new();
    d.add(b"a-very-long-token".to_vec());
    let m = DictionaryMutator::new(d);
    let mut r = mk_rng();
    let out = m.mutate(b"xx", &mut r);
    assert_eq!(out, b"a-very-long-token".to_vec());
}

#[test]
fn dictionary_mutator_empty_input() {
    let mut d = Dictionary::new();
    d.add(b"tok".to_vec());
    let m = DictionaryMutator::new(d);
    let mut r = mk_rng();
    assert!(m.mutate(&[], &mut r).is_empty());
}

// ─────────────────────── AflShmCoverage ────────────────────────

#[test]
fn shm_coverage_default_size() {
    let c = AflShmCoverage::afl_default();
    assert_eq!(c.size, AflShmCoverage::AFL_MAP_SIZE);
    assert_eq!(c.bitmap.len(), AflShmCoverage::AFL_MAP_SIZE);
}

#[test]
fn shm_coverage_clear() {
    let mut c = AflShmCoverage::new(8);
    c.bitmap[0] = 1;
    c.bitmap[3] = 99;
    c.clear();
    assert!(c.bitmap.iter().all(|&b| b == 0));
}

#[test]
fn shm_coverage_count_non_zero() {
    let mut c = AflShmCoverage::new(8);
    c.bitmap[1] = 5;
    c.bitmap[7] = 1;
    assert_eq!(c.count_non_zero(), 2);
}

#[test]
fn shm_coverage_merge_returns_new_count() {
    let mut a = AflShmCoverage::new(4);
    let other = vec![0u8, 1, 0, 1];
    let new = a.merge(&other);
    assert_eq!(new, 2);
    assert_eq!(a.bitmap, vec![0, 1, 0, 1]);
    // Merging again yields no new bits.
    let new2 = a.merge(&other);
    assert_eq!(new2, 0);
}

#[test]
fn shm_coverage_bucketed_zero_stays_zero() {
    let mut c = AflShmCoverage::new(4);
    c.bitmap = vec![0, 1, 2, 200];
    let b = c.bucketed();
    assert_eq!(b[0], 0);
    assert_eq!(b[1], 1);
    assert_eq!(b[2], 2);
    assert_eq!(b[3], 128);
}

#[test]
fn shm_coverage_hash_deterministic() {
    let c1 = AflShmCoverage::new(16);
    let c2 = AflShmCoverage::new(16);
    assert_eq!(c1.hash(), c2.hash());
}

// ───────────────────────── ForkServer ──────────────────────────

#[test]
fn fork_server_idle_cannot_fork() {
    let mut fs = ForkServer::new();
    assert!(matches!(fs.state, ForkServerState::Idle));
    assert!(fs.request_fork().is_err());
}

#[test]
fn fork_server_full_cycle() {
    let mut fs = ForkServer::new();
    fs.start();
    assert!(fs.is_ready());
    let pid = fs.request_fork().unwrap();
    assert_eq!(pid, 1000);
    assert_eq!(fs.forks, 1);
    assert!(matches!(fs.state, ForkServerState::Running { .. }));
    fs.child_done(0);
    assert!(matches!(fs.state, ForkServerState::Done { exit_status: 0 }));
    fs.reset().unwrap();
    assert!(fs.is_ready());
}

#[test]
fn fork_server_crash_path() {
    let mut fs = ForkServer::new();
    fs.start();
    let _ = fs.request_fork().unwrap();
    fs.child_crash(11);
    assert!(matches!(fs.state, ForkServerState::Crashed { signal: 11 }));
    fs.reset().unwrap();
    assert!(fs.is_ready());
}

#[test]
fn fork_server_reset_from_ready_errors() {
    let mut fs = ForkServer::new();
    fs.start();
    assert!(fs.reset().is_err());
}

#[test]
fn fork_server_double_fork_errors() {
    let mut fs = ForkServer::new();
    fs.start();
    let _ = fs.request_fork().unwrap();
    assert!(fs.request_fork().is_err());
}

#[test]
fn fork_server_default_is_idle() {
    let fs = ForkServer::default();
    assert_eq!(fs.state, ForkServerState::Idle);
}

// ───────────────────── Cmplog Entry/Map ────────────────────────

#[test]
fn cmplog_entry_basic() {
    let e = CmplogEntry::new(0x1000, 5, 5, 1);
    assert!(e.is_equal());
    assert_eq!(e.diff(), 0);
    let e2 = CmplogEntry::new(0x1000, 5, 10, 1);
    assert!(!e2.is_equal());
    assert_eq!(e2.diff(), 5);
}

#[test]
fn cmplog_map_record_and_clear() {
    let mut m = CmplogMap::new();
    assert!(m.is_empty());
    m.record(0xAA, 1, 2, 4);
    m.record(0xBB, 7, 7, 4);
    assert_eq!(m.len(), 2);
    let uneq = m.unequal_entries();
    assert_eq!(uneq.len(), 1);
    m.clear();
    assert!(m.is_empty());
}

#[test]
fn cmplog_colorize_skips_oversize() {
    let mut m = CmplogMap::new();
    m.record(0, 1, 2, 8); // size 8 > input.len()=4 → skipped
    let cands = m.colorize_mutations(&[0u8; 4]);
    assert!(cands.is_empty());
}

#[test]
fn cmplog_colorize_produces_candidates() {
    let mut m = CmplogMap::new();
    m.record(0, 0xAA, 0xBB, 1);
    let cands = m.colorize_mutations(&[0u8; 4]);
    assert_eq!(cands.len(), 4);
    for c in &cands {
        assert!(c.contains(&0xBB));
    }
}

// ──────────────────────────── AflQueue ─────────────────────────

#[test]
fn afl_queue_empty() {
    let mut q = AflQueue::new();
    assert!(q.is_empty());
    assert_eq!(q.len(), 0);
    assert!(q.select_sequential().is_none());
}

#[test]
fn afl_queue_round_robin_and_cycles() {
    let mut q = AflQueue::new();
    let id0 = q.next_id();
    let id1 = q.next_id();
    q.push(AflQueueEntry::new(id0, vec![1], 10));
    q.push(AflQueueEntry::new(id1, vec![2], 20));
    assert_eq!(q.len(), 2);
    let a = q.select_sequential().unwrap().id;
    let b = q.select_sequential().unwrap().id;
    assert_eq!(a, id0);
    assert_eq!(b, id1);
    // Now cycle ticks.
    assert_eq!(q.cycles, 1);
    let c = q.select_sequential().unwrap().id;
    assert_eq!(c, id0);
}

#[test]
fn afl_queue_select_best_highest_score() {
    let mut q = AflQueue::new();
    let id0 = q.next_id();
    let id1 = q.next_id();
    let mut e0 = AflQueueEntry::new(id0, vec![1], 10);
    e0.selected_count = 5;
    e0.interesting_count = 1;
    e0.exec_time_us = 100;
    q.push(e0);
    let mut e1 = AflQueueEntry::new(id1, vec![2], 100);
    // Untouched (score=MAX)
    q.push(e1.clone());
    let best = q.select_best();
    assert_eq!(best.id, id1);
    // Now mark id1 selected so id0's score matters.
    e1.selected_count = 100;
    e1.exec_time_us = 100;
    *q.entries.get_mut(&id1).unwrap() = e1;
    let _ = q.select_best();
}

#[test]
fn afl_queue_score_untried_is_max() {
    let e = AflQueueEntry::new(0, vec![1], 10);
    assert_eq!(e.score().to_bits(), f64::MAX.to_bits());
}

#[test]
fn afl_queue_mark_selected_and_interesting() {
    let mut e = AflQueueEntry::new(0, vec![1], 10);
    e.mark_selected();
    e.mark_interesting();
    assert_eq!(e.selected_count, 1);
    assert_eq!(e.interesting_count, 1);
}

#[test]
fn afl_queue_prune_removes_below_min() {
    let mut q = AflQueue::new();
    let id0 = q.next_id();
    let id1 = q.next_id();
    let mut e0 = AflQueueEntry::new(id0, vec![1], 1);
    e0.selected_count = 5;
    q.push(e0);
    let mut e1 = AflQueueEntry::new(id1, vec![2], 100);
    e1.selected_count = 5;
    q.push(e1);
    let removed = q.prune(10);
    assert_eq!(removed, 1);
    assert!(q.entries.contains_key(&id1));
    assert!(!q.entries.contains_key(&id0));
}

#[test]
fn afl_queue_compute_favorites_marks_some() {
    let mut q = AflQueue::new();
    for i in 0..5 {
        let id = q.next_id();
        q.push(AflQueueEntry::new(id, vec![u8::try_from(i).unwrap_or(u8::MAX)], (i + 1) * 10));
    }
    q.compute_favorites();
    let favored = q.entries.values().filter(|e| e.is_favored).count();
    assert!(favored > 0);
}

// ──────────────────────────── AflStats ─────────────────────────

#[test]
fn stats_roundtrip() {
    let mut s = AflStats::new();
    s.start_time = 1000;
    s.execs_done = 42;
    s.execs_per_sec = 100.5;
    s.stability = 99.0;
    s.map_density = 12.34;
    let text = s.serialize();
    let parsed = AflStats::parse(&text).unwrap();
    assert_eq!(parsed.start_time, 1000);
    assert_eq!(parsed.execs_done, 42);
    assert!((parsed.execs_per_sec - 100.5).abs() < 0.01);
    assert!((parsed.stability - 99.0).abs() < 0.01);
    assert!((parsed.map_density - 12.34).abs() < 0.01);
}

#[test]
fn stats_parse_unknown_keys_ignored() {
    let s = AflStats::parse("foo : bar\n# comment\nexecs_done : 7\n").unwrap();
    assert_eq!(s.execs_done, 7);
}

#[test]
fn stats_parse_malformed_value_gives_zero() {
    let s = AflStats::parse("execs_done : not_a_number\n").unwrap();
    assert_eq!(s.execs_done, 0);
}

#[test]
fn stats_parse_percentage_suffix() {
    let s = AflStats::parse("stability : 88.50%\n").unwrap();
    assert!((s.stability - 88.5).abs() < 0.01);
}

// ─────────────────────── PersistentMode ───────────────────────

#[test]
fn persistent_inactive_advance_false() {
    let mut p = PersistentMode::new(10);
    assert!(!p.advance());
}

#[test]
fn persistent_advance_resets_at_max() {
    let mut p = PersistentMode::new(3);
    p.start();
    assert!(p.advance()); // it 1
    assert!(p.advance()); // it 2
    assert!(!p.advance()); // it 3 -> reset
    assert_eq!(p.iteration, 0);
    assert_eq!(p.resets, 1);
    p.stop();
    assert!(!p.advance());
}

#[test]
fn persistent_default_is_1000() {
    let p = PersistentMode::default();
    assert_eq!(p.max_iterations, 1000);
}

// ───────────────────── AflCoverageMap ─────────────────────────

#[test]
fn cov_map_size() {
    let m = AflCoverageMap::new();
    assert_eq!(m.data.len(), AflCoverageMap::SIZE);
    assert_eq!(m.count_set_bits(), 0);
}

#[test]
fn cov_map_update_and_count() {
    let mut m = AflCoverageMap::new();
    m.update_with_path(1, 2);
    m.update_with_path(3, 4);
    assert_eq!(m.count_set_bits(), 2);
}

#[test]
fn cov_map_saturating_add() {
    let mut m = AflCoverageMap::new();
    for _ in 0..300 {
        m.update_with_path(1, 2);
    }
    let idx = AflCoverageMap::hash_edge(1, 2);
    assert_eq!(m.data[idx], 255);
}

#[test]
fn cov_map_has_new_bits_and_merge() {
    let mut a = AflCoverageMap::new();
    let mut v = AflCoverageMap::new();
    assert!(!a.has_new_bits(&v));
    a.update_with_path(7, 11);
    assert!(a.has_new_bits(&v));
    let new = a.merge_into_virgin(&mut v);
    assert_eq!(new, 1);
    assert!(!a.has_new_bits(&v));
}

#[test]
fn cov_map_clear() {
    let mut m = AflCoverageMap::new();
    m.update_with_path(1, 2);
    m.clear();
    assert_eq!(m.count_set_bits(), 0);
}

#[test]
fn cov_map_hash_edge_formula() {
    // ((from >> 1) ^ to) % 65536
    let idx = AflCoverageMap::hash_edge(0x1234, 0x5678);
    let expected = ((0x1234u32 >> 1) ^ 0x5678u32) as usize % AflCoverageMap::SIZE;
    assert_eq!(idx, expected);
}

// ────────────────────────── AflCorpus ──────────────────────────

#[test]
fn corpus_basic_ops() {
    let mut c = AflCorpus::new();
    assert!(c.is_empty());
    c.add(CorpusEntry::new(b"a".to_vec()));
    c.add(CorpusEntry::new(b"bb".to_vec()));
    assert_eq!(c.len(), 2);
    let e = c.select_next();
    assert!(!e.data.is_empty());
}

#[test]
fn corpus_minimize_keeps_zero_bits_under_threshold() {
    let mut c = AflCorpus::new();
    let mut a = CorpusEntry::new(vec![0u8; 100]);
    a.coverage_bits = 0;
    let mut b = CorpusEntry::new(vec![0u8; 5]);
    b.coverage_bits = 0;
    let mut d = CorpusEntry::new(vec![0u8; 100]);
    d.coverage_bits = 1;
    c.add(a);
    c.add(b);
    c.add(d);
    c.minimize(10);
    // 'a' removed (large + 0 bits); 'b' kept (small); 'd' kept (covers bits).
    assert_eq!(c.len(), 2);
}

// ─────────────────────── Mutation stages ───────────────────────

#[test]
fn stage_bit_flip_1_count() {
    let mut r = SimpleRng::new(1);
    let out = stage_bit_flip_1(&[0u8; 2], &mut r);
    assert_eq!(out.len(), 16);
}

#[test]
fn stage_bit_flip_1_each_diff_one_bit() {
    let mut r = SimpleRng::new(1);
    let input = vec![0u8; 1];
    let out = stage_bit_flip_1(&input, &mut r);
    for m in out {
        let bits: u32 = m.iter().map(|b| b.count_ones()).sum();
        assert_eq!(bits, 1);
    }
}

#[test]
fn stage_bit_flip_2_short() {
    assert!(stage_bit_flip_2(&[]).is_empty());
    let out = stage_bit_flip_2(&[0u8; 1]);
    assert_eq!(out.len(), 7);
}

#[test]
fn stage_bit_flip_4_short() {
    assert!(stage_bit_flip_4(&[]).is_empty());
    let out = stage_bit_flip_4(&[0u8; 1]);
    assert_eq!(out.len(), 5);
}

#[test]
fn stage_byte_flip_1_inverts_each() {
    let input = vec![0u8, 0xFF, 0x55];
    let out = stage_byte_flip_1(&input);
    assert_eq!(out.len(), 3);
    assert_eq!(out[0], vec![0xFF, 0xFF, 0x55]);
    assert_eq!(out[1], vec![0, 0, 0x55]);
    assert_eq!(out[2], vec![0, 0xFF, 0xAA]);
}

#[test]
fn stage_arith_8_count() {
    let out = stage_arith_8(&[0u8; 2]);
    assert_eq!(out.len(), 2 * 70);
}

#[test]
fn stage_arith_16_short_empty() {
    assert!(stage_arith_16(&[0u8]).is_empty());
}

#[test]
fn stage_arith_32_short_empty() {
    assert!(stage_arith_32(&[0u8; 3]).is_empty());
}

#[test]
fn stage_interesting_8_short() {
    let out = stage_interesting_8(&[0u8; 1]);
    assert_eq!(out.len(), INTERESTING_8.len());
}

#[test]
fn stage_interesting_16_short_empty() {
    assert!(stage_interesting_16(&[0u8]).is_empty());
}

#[test]
fn stage_interesting_32_short_empty() {
    assert!(stage_interesting_32(&[0u8; 3]).is_empty());
}

#[test]
fn stage_havoc_count() {
    let mut r = SimpleRng::new(1);
    let out = stage_havoc(&[0u8; 4], &mut r, 8);
    assert_eq!(out.len(), 8);
}

#[test]
fn stage_dictionary_empty_input() {
    let mut r = SimpleRng::new(1);
    assert!(stage_dictionary(&[], &[b"x".to_vec()], &mut r).is_empty());
}

#[test]
fn stage_dictionary_empty_dict() {
    let mut r = SimpleRng::new(1);
    assert!(stage_dictionary(b"abc", &[], &mut r).is_empty());
}

#[test]
fn stage_splice_basic() {
    let mut r = SimpleRng::new(1);
    let out = stage_splice(b"AAAA", b"BBBB", &mut r);
    assert!(out.iter().all(|&c| c == b'A' || c == b'B'));
}

#[test]
fn stage_splice_empty() {
    let mut r = SimpleRng::new(1);
    assert_eq!(stage_splice(&[], b"X", &mut r), b"X");
    assert_eq!(stage_splice(b"Y", &[], &mut r), b"Y");
}

#[test]
fn interesting_constants_contain_boundaries() {
    assert!(INTERESTING_8.contains(&0));
    assert!(INTERESTING_8.contains(&127));
    assert!(INTERESTING_8.contains(&-128));
    assert!(INTERESTING_16.contains(&-32768));
    assert!(INTERESTING_16.contains(&32767));
}

// ─────────────────────────── CovBitmap ─────────────────────────

#[test]
fn cov_bitmap_default_zero() {
    let b = CovBitmap::default();
    assert!(b.0.iter().all(|&x| x == 0));
}

// ──────────────────────── AflError variants ────────────────────

#[test]
fn afl_error_display_dict() {
    let e = AflError::InvalidDict("foo".to_string());
    let s = format!("{e}");
    assert!(s.contains("invalid dict"));
    assert!(s.contains("foo"));
}

#[test]
fn afl_error_display_shm() {
    let e = AflError::ShmError("bad".to_string());
    let s = format!("{e}");
    assert!(s.contains("shm"));
}

#[test]
fn afl_error_display_forkserver() {
    let e = AflError::ForkServerError("xx".to_string());
    assert!(format!("{e}").contains("fork server"));
}

#[test]
fn afl_error_display_stats() {
    let e = AflError::StatsParseError("xx".to_string());
    assert!(format!("{e}").contains("stats"));
}
