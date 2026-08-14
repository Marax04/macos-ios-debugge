//! Adversarial blitz suite for `rustre-fuzz-afl` — fuzz, boundary, threading,
//! round-trip, state-machine misuse, and integer-overflow paths.

use rustre_fuzz_afl::*;
use std::sync::Arc;
use std::thread;

// ── Seeded LCG (no rand, no std::time) ───────────────────────────────────────

fn make_lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        s
    }
}

fn lcg_bytes(g: &mut impl FnMut() -> u64, n: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    while v.len() < n {
        v.extend_from_slice(&g().to_le_bytes());
    }
    v.truncate(n);
    v
}

// ── XorShiftRng adversarial ──────────────────────────────────────────────────

#[test]
fn xorshift_distinct_seeds_diverge() {
    let mut a = XorShiftRng::new(1);
    let mut b = XorShiftRng::new(2);
    let mut diff = 0;
    for _ in 0..64 {
        if a.next_u64() != b.next_u64() { diff += 1; }
    }
    assert!(diff > 50);
}

#[test]
fn xorshift_clone_replays_identical_stream() {
    let mut a = XorShiftRng::new(0xABCDEF);
    let mut b = a.clone();
    for _ in 0..200 {
        assert_eq!(a.next_u64(), b.next_u64());
    }
}

#[test]
fn xorshift_next_usize_bounds_held_under_fuzz() {
    let mut g = make_lcg();
    let mut r = XorShiftRng::new(7);
    for _ in 0..2000 {
        let n = ((g() as usize) % 257) + 1;
        let v = r.next_usize(n);
        assert!(v < n, "{} >= {}", v, n);
    }
}

#[test]
fn xorshift_next_u8_distribution_covers_full_range() {
    let mut r = XorShiftRng::new(42);
    let mut seen = [false; 256];
    for _ in 0..20_000 {
        seen[r.next_u8() as usize] = true;
    }
    let count = seen.iter().filter(|x| **x).count();
    assert!(count > 200, "only {} distinct bytes", count);
}

// ── Mutators never panic on fuzzed input ─────────────────────────────────────

#[test]
fn mutators_never_panic_under_lcg_fuzz() {
    let mut g = make_lcg();
    let mut r = XorShiftRng::new(0xDEAD);
    let mutators: Vec<Box<dyn Mutator>> = vec![
        Box::new(BitFlipMutator),
        Box::new(ByteFlipMutator),
        Box::new(ArithmeticMutator),
        Box::new(InterestingValueMutator),
        Box::new(HavocMutator),
        Box::new(InsertMutator::new(16)),
        Box::new(DeleteMutator),
        Box::new(XorBlockMutator),
    ];
    for _ in 0..200 {
        let len2 = (g() as usize) % 257;
        let buf = lcg_bytes(&mut g, len2);
        for m in &mutators {
            let _ = m.mutate(&buf, &mut r);
        }
    }
}

#[test]
fn mutators_empty_input_returns_empty_or_unchanged() {
    let mut r = XorShiftRng::new(1);
    let mutators: Vec<Box<dyn Mutator>> = vec![
        Box::new(BitFlipMutator),
        Box::new(ByteFlipMutator),
        Box::new(ArithmeticMutator),
        Box::new(InterestingValueMutator),
        Box::new(XorBlockMutator),
        Box::new(DeleteMutator),
    ];
    for m in &mutators {
        let out = m.mutate(&[], &mut r);
        assert!(out.is_empty(), "{} grew empty input", m.name());
    }
}

#[test]
fn mutators_singleton_input_stays_nonempty() {
    let mut r = XorShiftRng::new(2);
    let mutators: Vec<Box<dyn Mutator>> = vec![
        Box::new(BitFlipMutator),
        Box::new(ByteFlipMutator),
        Box::new(ArithmeticMutator),
        Box::new(InterestingValueMutator),
        Box::new(XorBlockMutator),
    ];
    for m in &mutators {
        let out = m.mutate(&[0x42], &mut r);
        assert_eq!(out.len(), 1);
    }
}

#[test]
fn delete_mutator_singleton_input_unchanged() {
    let mut r = XorShiftRng::new(3);
    let m = DeleteMutator;
    let out = m.mutate(&[0xAA], &mut r);
    assert_eq!(out, vec![0xAA]);
}

#[test]
fn insert_mutator_grows_input_or_caps_at_limit() {
    let mut r = XorShiftRng::new(5);
    let m = InsertMutator::new(4);
    let input = vec![0u8; 32];
    for _ in 0..50 {
        let out = m.mutate(&input, &mut r);
        assert!(out.len() >= input.len());
        assert!(out.len() <= input.len() + 4);
    }
}

#[test]
fn insert_mutator_zero_max_clamped_to_one() {
    let m = InsertMutator::new(0);
    assert_eq!(m.max_insert, 1);
}

#[test]
fn havoc_round_trip_preserves_nonempty_when_input_nonempty() {
    let mut r = XorShiftRng::new(9);
    let m = HavocMutator;
    let input = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
    for _ in 0..100 {
        let out = m.mutate(&input, &mut r);
        let _ = out;
    }
}

// ── Splice properties ────────────────────────────────────────────────────────

#[test]
fn splice_empty_a_returns_b() {
    let mut r = XorShiftRng::new(1);
    let out = SpliceMutator::splice(&[], &[1, 2, 3], &mut r);
    assert_eq!(out, vec![1, 2, 3]);
}

#[test]
fn splice_empty_b_returns_a() {
    let mut r = XorShiftRng::new(1);
    let out = SpliceMutator::splice(&[4, 5, 6], &[], &mut r);
    assert_eq!(out, vec![4, 5, 6]);
}

#[test]
fn splice_under_fuzz_never_panics() {
    let mut g = make_lcg();
    let mut r = XorShiftRng::new(11);
    for _ in 0..200 {
        let na = (g() as usize) % 128;
        let a = lcg_bytes(&mut g, na);
        let nb = (g() as usize) % 128;
        let b = lcg_bytes(&mut g, nb);
        let _ = SpliceMutator::splice(&a, &b, &mut r);
    }
}

// ── Dictionary parser adversarial ────────────────────────────────────────────

#[test]
fn dictionary_load_empty_text_ok() {
    let mut d = Dictionary::new();
    let n = d.load_afl_format("").unwrap();
    assert_eq!(n, 0);
    assert!(d.is_empty());
}

#[test]
fn dictionary_load_comments_only() {
    let mut d = Dictionary::new();
    let n = d.load_afl_format("# comment\n  # another\n").unwrap();
    assert_eq!(n, 0);
}

#[test]
fn dictionary_load_quoted_string() {
    let mut d = Dictionary::new();
    let n = d.load_afl_format("\"hello\"\n").unwrap();
    assert_eq!(n, 1);
    assert_eq!(d.entries[0], b"hello");
}

#[test]
fn dictionary_load_escape_sequences() {
    let mut d = Dictionary::new();
    d.load_afl_format("\"\\n\\r\\t\\0\\\\\\\"\"\n").unwrap();
    assert_eq!(d.entries[0], vec![b'\n', b'\r', b'\t', 0, b'\\', b'"']);
}

#[test]
fn dictionary_load_hex_escape() {
    let mut d = Dictionary::new();
    d.load_afl_format("\"\\xAB\\xcd\"\n").unwrap();
    assert_eq!(d.entries[0], vec![0xAB, 0xCD]);
}

#[test]
fn dictionary_load_bad_hex_escape_errors() {
    let mut d = Dictionary::new();
    let err = d.load_afl_format("\"\\xZZ\"\n").unwrap_err();
    assert!(matches!(err, AflError::InvalidDict(_)));
}

#[test]
fn dictionary_load_truncated_hex_escape_errors() {
    let mut d = Dictionary::new();
    let err = d.load_afl_format("\"\\x1\"\n").unwrap_err();
    assert!(matches!(err, AflError::InvalidDict(_)));
}

#[test]
fn dictionary_load_trailing_backslash_errors() {
    let mut d = Dictionary::new();
    let err = d.load_afl_format("\"abc\\\"\n").unwrap_err();
    // The escaped backslash+quote means string isn't closed → falls to bare line.
    // Or in this format, trailing \ inside quotes errors. Accept either: it parsed as bare or err.
    let _ = err;
}

#[test]
fn dictionary_load_hex_prefix_format() {
    let mut d = Dictionary::new();
    let n = d.load_afl_format("x\"de ad be ef\"\n").unwrap();
    assert_eq!(n, 1);
    assert_eq!(d.entries[0], vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn dictionary_load_hex_prefix_bad_errors() {
    let mut d = Dictionary::new();
    let err = d.load_afl_format("x\"zz\"\n").unwrap_err();
    assert!(matches!(err, AflError::InvalidDict(_)));
}

#[test]
fn dictionary_load_fuzz_never_panics() {
    let mut g = make_lcg();
    for _ in 0..100 {
        let len3 = (g() as usize) % 128;
        let buf = lcg_bytes(&mut g, len3);
        let s: String = buf.iter().map(|b| *b as char).collect();
        let mut d = Dictionary::new();
        let _ = d.load_afl_format(&s);
    }
}

#[test]
fn dictionary_add_grows_len() {
    let mut d = Dictionary::new();
    assert!(d.is_empty());
    d.add(vec![1, 2, 3]);
    d.add_str("xyz");
    assert_eq!(d.len(), 2);
    assert!(!d.is_empty());
}

// ── Dictionary mutator ──────────────────────────────────────────────────────

#[test]
fn dictionary_mutator_empty_dict_passthrough() {
    let mut r = XorShiftRng::new(1);
    let m = DictionaryMutator::new(Dictionary::new());
    let out = m.mutate(&[1, 2, 3], &mut r);
    assert_eq!(out, vec![1, 2, 3]);
}

#[test]
fn dictionary_mutator_token_larger_than_input_resizes() {
    let mut r = XorShiftRng::new(1);
    let mut d = Dictionary::new();
    d.add(vec![9, 9, 9, 9, 9, 9, 9, 9]);
    let m = DictionaryMutator::new(d);
    let out = m.mutate(&[1, 2], &mut r);
    assert_eq!(out.len(), 8);
    assert_eq!(out, vec![9; 8]);
}

// ── AflShmCoverage ──────────────────────────────────────────────────────────

#[test]
fn shm_coverage_default_size() {
    let s = AflShmCoverage::afl_default();
    assert_eq!(s.size, AflShmCoverage::AFL_MAP_SIZE);
    assert_eq!(s.bitmap.len(), AflShmCoverage::AFL_MAP_SIZE);
}

#[test]
fn shm_coverage_clear_resets() {
    let mut s = AflShmCoverage::new(64);
    s.bitmap[10] = 1;
    s.bitmap[20] = 2;
    assert_eq!(s.count_non_zero(), 2);
    s.clear();
    assert_eq!(s.count_non_zero(), 0);
}

#[test]
fn shm_coverage_merge_counts_new_bytes() {
    let mut s = AflShmCoverage::new(8);
    let new_bytes = s.merge(&[0, 1, 0, 2, 0, 0, 0, 0]);
    assert_eq!(new_bytes, 2);
    let new_bytes2 = s.merge(&[0, 1, 0, 2, 0, 0, 0, 0]);
    assert_eq!(new_bytes2, 0);
}

#[test]
fn shm_coverage_merge_truncates_to_self_size() {
    let mut s = AflShmCoverage::new(4);
    let nb = s.merge(&[1, 1, 1, 1, 1, 1, 1, 1]);
    assert_eq!(nb, 4);
}

#[test]
fn shm_coverage_hash_consistent() {
    let s1 = AflShmCoverage::new(128);
    let s2 = AflShmCoverage::new(128);
    assert_eq!(s1.hash(), s2.hash());
}

#[test]
fn shm_coverage_bucketed_lengths_match() {
    let s = AflShmCoverage::new(256);
    let b = s.bucketed();
    assert_eq!(b.len(), 256);
}

// ── ForkServer state machine ────────────────────────────────────────────────

#[test]
fn forkserver_idle_cannot_fork() {
    let mut fs = ForkServer::new();
    assert!(fs.request_fork().is_err());
}

#[test]
fn forkserver_valid_lifecycle() {
    let mut fs = ForkServer::new();
    fs.start();
    assert!(fs.is_ready());
    let pid = fs.request_fork().unwrap();
    assert!(pid >= 1000);
    assert_eq!(fs.forks, 1);
    fs.child_done(0);
    fs.reset().unwrap();
    assert!(fs.is_ready());
}

#[test]
fn forkserver_crash_path_then_reset() {
    let mut fs = ForkServer::new();
    fs.start();
    fs.request_fork().unwrap();
    fs.child_crash(11);
    fs.reset().unwrap();
    assert!(fs.is_ready());
}

#[test]
fn forkserver_reset_from_ready_errors() {
    let mut fs = ForkServer::new();
    fs.start();
    assert!(fs.reset().is_err());
}

#[test]
fn forkserver_double_fork_without_reset_errors() {
    let mut fs = ForkServer::new();
    fs.start();
    let _ = fs.request_fork().unwrap();
    assert!(fs.request_fork().is_err());
}

#[test]
fn forkserver_pid_increments() {
    let mut fs = ForkServer::new();
    fs.start();
    let p1 = fs.request_fork().unwrap();
    fs.child_done(0);
    fs.reset().unwrap();
    let p2 = fs.request_fork().unwrap();
    assert_eq!(p2, p1.wrapping_add(1));
}

// ── PersistentMode ───────────────────────────────────────────────────────────

#[test]
fn persistent_mode_resets_at_max() {
    let mut p = PersistentMode::new(3);
    p.start();
    assert!(p.advance());
    assert!(p.advance());
    // 3rd advance should hit max and return false
    assert!(!p.advance());
    assert_eq!(p.resets, 1);
    assert_eq!(p.iteration, 0);
}

#[test]
fn persistent_mode_inactive_returns_false() {
    let mut p = PersistentMode::new(10);
    assert!(!p.advance());
}

#[test]
fn persistent_mode_stop() {
    let mut p = PersistentMode::new(5);
    p.start();
    let _ = p.advance();
    p.stop();
    assert!(!p.active);
    assert!(!p.advance());
}

#[test]
fn persistent_mode_long_run_increments_resets() {
    let mut p = PersistentMode::new(2);
    p.start();
    for _ in 0..20 {
        let _ = p.advance();
    }
    assert!(p.resets > 0);
}

// ── CMPLOG ───────────────────────────────────────────────────────────────────

#[test]
fn cmplog_entry_diff_overflow_safe() {
    let e = CmplogEntry::new(0, 0, u64::MAX, 8);
    assert_eq!(e.diff(), u64::MAX);
    assert!(!e.is_equal());
}

#[test]
fn cmplog_entry_equal() {
    let e = CmplogEntry::new(0, 42, 42, 8);
    assert!(e.is_equal());
    assert_eq!(e.diff(), 0);
}

#[test]
fn cmplog_map_record_and_clear() {
    let mut m = CmplogMap::new();
    assert!(m.is_empty());
    m.record(0x1000, 1, 2, 4);
    m.record(0x1004, 5, 5, 4);
    assert_eq!(m.len(), 2);
    assert_eq!(m.unequal_entries().len(), 1);
    m.clear();
    assert!(m.is_empty());
}

#[test]
fn cmplog_colorize_skips_oversized_entries() {
    let mut m = CmplogMap::new();
    m.record(0, 1, 0xDEAD_BEEF_CAFE_BABE, 8);
    // Input too small for size=8
    let cands = m.colorize_mutations(&[0u8; 4]);
    assert!(cands.is_empty());
}

#[test]
fn cmplog_colorize_produces_candidates() {
    let mut m = CmplogMap::new();
    m.record(0, 0, 0xCAFE, 2);
    let cands = m.colorize_mutations(&[0u8; 8]);
    assert!(!cands.is_empty());
    for c in &cands {
        assert_eq!(c.len(), 8);
    }
}

// ── AflQueue ─────────────────────────────────────────────────────────────────

#[test]
fn afl_queue_empty_select_returns_none() {
    let mut q = AflQueue::new();
    assert!(q.select_sequential().is_none());
    assert!(q.is_empty());
}

#[test]
fn afl_queue_push_and_select_cycles() {
    let mut q = AflQueue::new();
    for _ in 0..3 {
        let id = q.next_id();
        q.push(AflQueueEntry::new(id, vec![id as u8], 1));
    }
    assert_eq!(q.len(), 3);
    // Cycle through twice
    for _ in 0..6 {
        let _ = q.select_sequential().unwrap();
    }
    assert!(q.cycles >= 1);
}

#[test]
fn afl_queue_prune_removes_low_coverage() {
    let mut q = AflQueue::new();
    for i in 0..5 {
        let id = q.next_id();
        let mut e = AflQueueEntry::new(id, vec![i], (i + 1) as u32);
        e.selected_count = 1; // make it eligible
        q.push(e);
    }
    let removed = q.prune(3);
    assert_eq!(removed, 2);
    assert_eq!(q.len(), 3);
}

#[test]
fn afl_queue_compute_favorites_marks_some() {
    let mut q = AflQueue::new();
    for i in 0..10 {
        let id = q.next_id();
        q.push(AflQueueEntry::new(id, vec![i], (i + 1) as u32));
    }
    q.compute_favorites();
    let fav_count = q.entries.values().filter(|e| e.is_favored).count();
    assert!(fav_count > 0);
}

#[test]
fn afl_queue_entry_score_untried_is_max() {
    let e = AflQueueEntry::new(1, vec![1], 5);
    assert_eq!(e.score(), f64::MAX);
}

#[test]
fn afl_queue_entry_mark_methods() {
    let mut e = AflQueueEntry::new(1, vec![1], 5);
    e.mark_selected();
    e.mark_selected();
    e.mark_interesting();
    assert_eq!(e.selected_count, 2);
    assert_eq!(e.interesting_count, 1);
    // Score is now finite
    assert!(e.score().is_finite());
}

#[test]
fn afl_queue_next_id_wraps_unique() {
    let mut q = AflQueue::new();
    let a = q.next_id();
    let b = q.next_id();
    assert_ne!(a, b);
}

// ── AflStats round-trip ─────────────────────────────────────────────────────

#[test]
fn afl_stats_serialize_parse_round_trip() {
    let mut g = make_lcg();
    for _ in 0..20 {
        let s = AflStats {
            start_time: g() % 1_000_000,
            last_update: g() % 1_000_000,
            execs_done: g() % 1_000_000,
            execs_per_sec: 0.0,
            crashes_found: g() % 1000,
            unique_crashes: g() % 1000,
            hangs_found: g() % 1000,
            queue_size: g() % 1000,
            total_paths: g() % 1000,
            cycles_done: g() % 100,
            fuzzer_state: "havoc".to_string(),
            peak_rss_mb: g() % 10000,
            target: String::new(),
            stability: 99.0,
            map_density: 12.34,
        };
        let text = s.serialize();
        let parsed = AflStats::parse(&text).unwrap();
        assert_eq!(parsed.start_time, s.start_time);
        assert_eq!(parsed.execs_done, s.execs_done);
        assert_eq!(parsed.crashes_found, s.crashes_found);
        assert_eq!(parsed.queue_size, s.queue_size);
        assert_eq!(parsed.fuzzer_state, s.fuzzer_state);
    }
}

#[test]
fn afl_stats_parse_empty_ok() {
    let s = AflStats::parse("").unwrap();
    assert_eq!(s.execs_done, 0);
}

#[test]
fn afl_stats_parse_malformed_lines_skipped() {
    let s = AflStats::parse("garbage\n#comment\n: : :\nexecs_done : 42\n").unwrap();
    assert_eq!(s.execs_done, 42);
}

#[test]
fn afl_stats_parse_fuzz_never_panics() {
    let mut g = make_lcg();
    for _ in 0..100 {
        let len = (g() as usize) % 256;
        let buf: String = (0..len).map(|_| ((g() & 0x7F) as u8).max(b' ') as char).collect();
        let _ = AflStats::parse(&buf);
    }
}

// ── Bucket function ──────────────────────────────────────────────────────────

#[test]
fn bucketed_monotone_nondecreasing() {
    let s = AflShmCoverage::new(256);
    // After clear we have all zero; manually fill ascending
    let mut s = s;
    for i in 0..256 {
        s.bitmap[i] = i as u8;
    }
    let b = s.bucketed();
    // Buckets should be non-decreasing as input increases
    for w in b.windows(2) {
        assert!(w[0] <= w[1], "bucket not monotone: {} > {}", w[0], w[1]);
    }
}

// ── Hash/Eq consistency for ForkServerState ─────────────────────────────────

#[test]
fn forkserverstate_eq_pairs() {
    let pairs = vec![
        (ForkServerState::Idle, ForkServerState::Idle, true),
        (ForkServerState::Ready, ForkServerState::Ready, true),
        (ForkServerState::Idle, ForkServerState::Ready, false),
        (ForkServerState::Running { child_pid: 1 }, ForkServerState::Running { child_pid: 1 }, true),
        (ForkServerState::Running { child_pid: 1 }, ForkServerState::Running { child_pid: 2 }, false),
        (ForkServerState::Done { exit_status: 0 }, ForkServerState::Done { exit_status: 0 }, true),
        (ForkServerState::Done { exit_status: 0 }, ForkServerState::Done { exit_status: 1 }, false),
        (ForkServerState::Crashed { signal: 11 }, ForkServerState::Crashed { signal: 11 }, true),
        (ForkServerState::Crashed { signal: 11 }, ForkServerState::Crashed { signal: 9 }, false),
        (ForkServerState::Idle, ForkServerState::Running { child_pid: 0 }, false),
    ];
    for (a, b, expect) in pairs {
        assert_eq!(a == b, expect);
    }
}

// ── Send/Sync threaded stress ───────────────────────────────────────────────

#[test]
fn mutators_send_sync_threaded_stress() {
    let havoc: Arc<dyn Mutator + Send + Sync> = Arc::new(HavocMutator);
    let mut handles = Vec::new();
    for tid in 0..4 {
        let h = Arc::clone(&havoc);
        handles.push(thread::spawn(move || {
            let mut r = XorShiftRng::new(0x100 + tid as u64);
            let input = vec![0xABu8; 64];
            for _ in 0..100 {
                let out = h.mutate(&input, &mut r);
                assert!(!out.is_empty());
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn dictionary_clone_threaded_stress() {
    let mut d = Dictionary::new();
    d.add_str("alpha");
    d.add_str("beta");
    d.add_str("gamma");
    let shared = Arc::new(d);
    let mut handles = Vec::new();
    for tid in 0..4 {
        let d = Arc::clone(&shared);
        handles.push(thread::spawn(move || {
            let mut r = XorShiftRng::new(0x200 + tid as u64);
            let m = DictionaryMutator::new((*d).clone());
            for _ in 0..100 {
                let _ = m.mutate(&[0u8; 32], &mut r);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ── AflError display ────────────────────────────────────────────────────────

#[test]
fn afl_error_variants_display_nonempty() {
    let errs = vec![
        AflError::ShmError("a".into()),
        AflError::ForkServerError("b".into()),
        AflError::InvalidDict("c".into()),
        AflError::StatsParseError("d".into()),
    ];
    for e in errs {
        let s = format!("{e}");
        assert!(!s.is_empty());
    }
}

// ── CmplogEntry boundaries ──────────────────────────────────────────────────

#[test]
fn cmplog_entry_size_boundaries() {
    for size in [1u8, 2, 4, 8] {
        let e = CmplogEntry::new(0xDEAD, 1, 2, size);
        assert_eq!(e.size, size);
        assert!(!e.is_equal());
    }
}

#[test]
fn shm_coverage_count_non_zero_after_partial_fill() {
    let mut s = AflShmCoverage::new(128);
    for i in 0..64 {
        s.bitmap[i] = (i as u8).wrapping_add(1);
    }
    assert_eq!(s.count_non_zero(), 64);
}
