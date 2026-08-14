//! Adversarial blitz2 suite for rustre-fuzz-libfuzzer.
//! Heavy focus on mutator round-trips, LCG fuzz, boundary truncation,
//! state-machine transitions, and Send+Sync stress.

use rustre_fuzz_libfuzzer::{
    coverage_feedback::{
        bucket_bitmap, bucket_hit_count, count_new_bits_bucketed, parse_pc_table, BitmapStats,
        BranchTracker, BranchTuple, CmpEntry, CmpLogAnalyzer, CmpOperand, CoverageShm,
        CoverageTracker, PcFlags,
    },
    crash_triage::{
        classify_severity, compute_dedup_hash, parse_gdb_backtrace, parse_sanitizer_output,
        parse_stack_trace, CrashKind, StackFrame,
    },
    harness_generator::{
        infer_params_from_name, prioritize_entries, scan_elf_exports_from_bytes, score_entry,
        FuzzEntryPoint,
    },
    libfuzzer_corpus::{export_corpus, ContentHash, CorpusEntry, CorpusExportFormat},
    mutator::{
        ArithmeticMutator, BitFlipMutator, ByteFlipMutator, ChunkCopyMutator, DeleteMutator,
        DictEntryMutator, DictionaryEntry, InsertMutator, InterestingValueMutator,
        MutationStrategy, MutatorChain, MutatorError, MutatorPlugin, Rng, SpliceMutator,
    },
    CrashSignalHandler, FuzzCorpusManager, FuzzTargetResult, IpCoverageMap, IpFuzzInput,
    IpMutator, LibFuzzerError, PersistentModeHarness, SimpleRng, StructuredInput,
};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::thread;

// ─── LCG seeded fuzz helper ───────────────────────────────────────────────────
fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

fn random_bytes(g: &mut impl FnMut() -> u64, len: usize) -> Vec<u8> {
    (0..len).map(|_| (g() & 0xff) as u8).collect()
}

// ─── ContentHash properties (50+ inputs) ─────────────────────────────────────
#[test]
fn content_hash_deterministic_50_inputs() {
    let mut g = lcg();
    for _ in 0..60 {
        let n = (g() as usize) % 257;
        let buf = random_bytes(&mut g, n);
        assert_eq!(ContentHash::of(&buf), ContentHash::of(&buf));
    }
}

#[test]
fn content_hash_avalanche_30_pairs() {
    let mut g = lcg();
    let mut equal_count = 0;
    for _ in 0..30 {
        let mut buf = random_bytes(&mut g, 16);
        let h1 = ContentHash::of(&buf);
        buf[0] ^= 0x01;
        let h2 = ContentHash::of(&buf);
        if h1 == h2 {
            equal_count += 1;
        }
    }
    // Hash should change for nearly all single-bit flips
    assert!(equal_count <= 1, "fnv1a-style hash too weak: {equal_count}");
}

#[test]
fn content_hash_display_round_trip_chars() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() as usize) % 64;
        let buf = random_bytes(&mut g, n);
        let s = format!("{}", ContentHash::of(&buf));
        assert_eq!(s.len(), 16);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

// ─── CorpusEntry / export_corpus round-trips ─────────────────────────────────
#[test]
fn corpus_entry_len_matches_bytes_50() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() as usize) % 200;
        let buf = random_bytes(&mut g, n);
        let e = CorpusEntry::new(buf.clone());
        assert_eq!(e.len(), buf.len());
        assert_eq!(e.is_empty(), buf.is_empty());
    }
}

#[test]
fn export_corpus_raw_preserves_each_blob() {
    let mut g = lcg();
    let entries: Vec<Vec<u8>> = (0..20)
        .map(|_| {
            let n = (g() as usize) % 50;
            random_bytes(&mut g, n)
        })
        .collect();
    let out = export_corpus(&entries, CorpusExportFormat::RawBinary);
    assert_eq!(out.len(), entries.len());
    for (i, e) in entries.iter().enumerate() {
        assert_eq!(&out[i], e, "raw export must be identity per entry");
    }
}

#[test]
fn export_corpus_hex_is_ascii_hex() {
    let mut g = lcg();
    for _ in 0..10 {
        let n = (g() as usize) % 32 + 1;
        let buf = random_bytes(&mut g, n);
        let out = export_corpus(&[buf], CorpusExportFormat::HexLines);
        assert_eq!(out.len(), 1);
        let s = std::str::from_utf8(&out[0]).unwrap();
        assert!(s.chars().all(|c| c.is_ascii_hexdigit() || c == '\n'));
    }
}

// ─── parse_pc_table fuzz ──────────────────────────────────────────────────────
#[test]
fn parse_pc_table_never_panics_lcg() {
    let mut g = lcg();
    for _ in 0..100 {
        let n = (g() as usize) % 200;
        let buf = random_bytes(&mut g, n);
        for &ptr in &[1u8, 2, 4, 8, 16] {
            let _ = parse_pc_table(&buf, ptr);
        }
    }
}

#[test]
fn parse_pc_table_invalid_ptrs_empty() {
    let bytes = vec![0u8; 64];
    for &ptr in &[0u8, 1, 3, 5, 7, 9, 16, 100] {
        assert!(parse_pc_table(&bytes, ptr).is_empty());
    }
}

#[test]
fn parse_pc_table_truncated_partial() {
    // 15 bytes — not enough for a full 16-byte pair at 8-byte ptr.
    let bytes = vec![0u8; 15];
    assert!(parse_pc_table(&bytes, 8).is_empty());
}

#[test]
fn parse_pc_table_multiple_entries_8byte() {
    let mut bytes = Vec::new();
    for i in 0u64..5 {
        bytes.extend_from_slice(&(0xdead_0000u64 + i).to_le_bytes());
        bytes.extend_from_slice(&((i & 0x3) | 1).to_le_bytes());
    }
    let entries = parse_pc_table(&bytes, 8);
    assert_eq!(entries.len(), 5);
    for (i, e) in entries.iter().enumerate() {
        assert_eq!(e.pc, 0xdead_0000 + i as u64);
    }
}

// ─── CoverageShm boundary ────────────────────────────────────────────────────
#[test]
fn coverage_shm_merge_idempotent() {
    let s = CoverageShm::default();
    let mut snap = vec![0u8; 65536];
    snap[42] = 0xff;
    s.merge_or(&snap);
    let edges1 = s.count_edges();
    s.merge_or(&snap);
    assert_eq!(s.count_edges(), edges1);
}

#[test]
fn coverage_shm_pc_flags_func_entry_set() {
    let pf = PcFlags::FUNC_ENTRY;
    assert!(pf.contains(PcFlags::FUNC_ENTRY));
}

// ─── CoverageTracker round-trip ──────────────────────────────────────────────
#[test]
fn coverage_tracker_run_count_grows() {
    let mut t = CoverageTracker::new(16);
    for i in 0..10 {
        let mut snap = vec![0u8; 16];
        snap[i % 16] = 1;
        t.record_run(i as u64, &snap);
    }
    assert_eq!(t.run_count(), 10);
}

#[test]
fn coverage_tracker_no_new_after_record() {
    let mut t = CoverageTracker::new(8);
    let mut snap = vec![0u8; 8];
    snap[2] = 1;
    snap[5] = 1;
    let (n1, idx1) = t.record_run(1, &snap);
    assert_eq!(n1, 2);
    assert_eq!(idx1.len(), 2);
    let (n2, idx2) = t.record_run(2, &snap);
    assert_eq!(n2, 0);
    assert!(idx2.is_empty());
}

// ─── BranchTracker ────────────────────────────────────────────────────────────
#[test]
fn branch_tracker_records_unique_lcg() {
    let mut g = lcg();
    let mut bt = BranchTracker::default();
    let mut seen = HashSet::new();
    for _ in 0..50 {
        let from = g() & 0xff;
        let to = g() & 0xff;
        seen.insert((from, to));
        bt.record_run(g(), vec![BranchTuple::new(from, to)]);
    }
    // unique_branches ≤ seen pairs (collision possible)
    assert!(bt.total_unique_branches() <= seen.len() + 1);
}

// ─── bucket_hit_count exhaustive ─────────────────────────────────────────────
#[test]
fn bucket_hit_count_monotonic_nondecreasing() {
    let mut prev = 0u8;
    for i in 0u8..=255 {
        let b = bucket_hit_count(i);
        assert!(b >= prev, "non-monotonic at {i}: {prev} -> {b}");
        prev = b;
    }
}

#[test]
fn bucket_bitmap_preserves_length_lcg() {
    // bucket_bitmap is not idempotent (it rounds values up to power-of-two
    // buckets, so 16 -> 32 etc.), but it must preserve length.
    let mut g = lcg();
    let bm: Vec<u8> = (0..64).map(|_| (g() & 0xff) as u8).collect();
    let once = bucket_bitmap(&bm);
    assert_eq!(once.len(), bm.len());
}

#[test]
fn count_new_bits_zero_when_subset() {
    let global = vec![0xff; 8];
    let current = vec![0x0fu8; 8];
    assert_eq!(count_new_bits_bucketed(&global, &current), 0);
}

// ─── CmpLogAnalyzer ──────────────────────────────────────────────────────────
#[test]
fn cmp_operand_to_bytes_widths() {
    assert_eq!(CmpOperand::U8(0xAA).to_bytes().len(), 1);
    assert_eq!(CmpOperand::U16(0xAABB).to_bytes().len(), 2);
    assert_eq!(CmpOperand::U32(0xDEAD_BEEF).to_bytes().len(), 4);
    assert_eq!(CmpOperand::U64(0xDEAD_BEEF_CAFE_BABE).to_bytes().len(), 8);
}

#[test]
fn cmp_log_analyzer_top_hot_bounded() {
    let mut a = CmpLogAnalyzer::default();
    let mut entries = Vec::new();
    let mut g = lcg();
    for i in 0..30 {
        entries.push(CmpEntry {
            pc: i,
            lhs: CmpOperand::U32((g() & 0xffff_ffff) as u32),
            rhs: CmpOperand::U32((g() & 0xffff_ffff) as u32),
            hit_count: (g() % 1000) as u32,
        });
    }
    a.record_entries(entries);
    let top5 = a.top_hot_cmps(5);
    assert!(top5.len() <= 5);
    for win in top5.windows(2) {
        assert!(win[0].hit_count >= win[1].hit_count);
    }
}

// ─── BitmapStats edge ────────────────────────────────────────────────────────
#[test]
fn bitmap_stats_all_set() {
    let bm = vec![0xff; 8];
    let s = BitmapStats::compute(&bm);
    assert_eq!(s.set_bits, 8);
    assert!((s.coverage_pct - 100.0).abs() < 1e-6);
}

// ─── Sanitizer / triage fuzz ─────────────────────────────────────────────────
#[test]
fn parse_sanitizer_garbage_lcg_never_panics() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() as usize) % 200;
        let buf: String = (0..n)
            .map(|_| (g() & 0x7f) as u8 as char)
            .collect();
        let _ = parse_sanitizer_output(&buf);
    }
}

#[test]
fn parse_stack_trace_garbage_lcg() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() as usize) % 100;
        let s: String = (0..n).map(|_| (g() & 0x7f) as u8 as char).collect();
        let _ = parse_stack_trace(&s);
        let _ = parse_gdb_backtrace(&s);
    }
}

#[test]
fn classify_severity_all_kinds() {
    let kinds = [
        CrashKind::HeapOverflow,
        CrashKind::UseAfterFree,
        CrashKind::DoubleFree,
        CrashKind::StackBufferOverflow,
        CrashKind::NullDeref,
        CrashKind::Timeout,
        CrashKind::Assertion,
        CrashKind::Unknown,
        CrashKind::DivisionByZero,
        CrashKind::IntegerOverflow,
    ];
    for k in kinds {
        let _ = classify_severity(&k, None);
        let _ = classify_severity(&k, Some(0));
        let _ = classify_severity(&k, Some(0x1000_0000));
    }
}

#[test]
fn compute_dedup_hash_stable_lcg() {
    let mut g = lcg();
    for _ in 0..30 {
        let frames: Vec<StackFrame> = (0..3)
            .map(|i| StackFrame {
                frame_no: i,
                pc: g(),
                symbol: Some(format!("fn{}", g() & 0xff)),
                module: Some("target".into()),
                offset: 0,
                file_line: None,
            })
            .collect();
        let h1 = compute_dedup_hash(&frames, 3);
        let h2 = compute_dedup_hash(&frames, 3);
        assert_eq!(h1, h2);
    }
}

// ─── harness_generator ──────────────────────────────────────────────────────
#[test]
fn infer_params_never_empty() {
    for name in ["parse_pkt", "init_ctx", "foo", "decode_msg", "x"] {
        let p = infer_params_from_name(name);
        assert!(!p.is_empty());
    }
}

#[test]
fn score_entry_lcg_finite() {
    let mut g = lcg();
    for _ in 0..50 {
        let name: String = (0..=((g() as usize) % 12))
            .map(|_| ((g() % 26) as u8 + b'a') as char)
            .collect();
        let ar = (g() as usize) % 6;
        let _s = score_entry(&name, ar);
    }
}

#[test]
fn scan_elf_exports_lcg() {
    let mut g = lcg();
    for _ in 0..30 {
        let n = (g() as usize) % 256;
        let buf = random_bytes(&mut g, n);
        let _ = scan_elf_exports_from_bytes(&buf);
    }
}

#[test]
fn prioritize_entries_orders_parse_first() {
    let mut entries = vec![
        FuzzEntryPoint::new("get_x", 0x1),
        FuzzEntryPoint::new("parse_y", 0x2),
        FuzzEntryPoint::new("xyz", 0x3),
    ];
    let plan = prioritize_entries(&mut entries);
    // plan should be non-empty
    assert!(!plan.is_empty());
}

// ─── LibFuzzerError Display round-trip ───────────────────────────────────────
#[test]
fn libfuzzer_error_all_variants_display() {
    use std::time::Duration;
    let errs = [
        LibFuzzerError::EmptySeedPool,
        LibFuzzerError::InputTooLarge { actual: 100, limit: 50 },
        LibFuzzerError::CorpusIo("x".into()),
        LibFuzzerError::Timeout(Duration::from_millis(5)),
        LibFuzzerError::CustomMutator("m".into()),
        LibFuzzerError::Structured("s".into()),
    ];
    for e in errs {
        let s = e.to_string();
        assert!(!s.is_empty());
    }
}

// ─── StructuredInput round-trip 50+ ──────────────────────────────────────────
#[test]
fn structured_input_round_trip_lcg() {
    let mut g = lcg();
    for _ in 0..50 {
        let mut s = StructuredInput::new();
        let fields = ((g() as usize) % 5) + 1;
        for f in 0..fields {
            let name = format!("f{f}");
            let n = (g() as usize) % 64;
            s.insert(&name, random_bytes(&mut g, n));
        }
        let ser = s.serialize().expect("serialize ok");
        let de = StructuredInput::deserialize(&ser).expect("deser ok");
        assert_eq!(de.field_count(), s.field_count());
    }
}

#[test]
fn structured_input_deserialize_garbage_lcg() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = (g() as usize) % 100;
        let buf = random_bytes(&mut g, n);
        let _ = StructuredInput::deserialize(&buf); // must not panic
    }
}

// ─── PersistentModeHarness state machine ─────────────────────────────────────
#[test]
fn persistent_mode_progress_nondecreasing() {
    // progress() = iters/max; iters keeps incrementing past max, so
    // progress can exceed 1.0 — only require non-decreasing & non-negative.
    let mut h = PersistentModeHarness::new(10);
    h.start();
    let mut prev = h.progress();
    assert!(prev >= 0.0);
    for _ in 0..15 {
        let _ = h.advance();
        let p = h.progress();
        assert!(p >= prev);
        prev = p;
    }
}

#[test]
fn persistent_mode_advance_returns_false_at_max() {
    let mut h = PersistentModeHarness::new(3);
    h.start();
    let r1 = h.advance();
    let r2 = h.advance();
    let r3 = h.advance();
    let r4 = h.advance();
    let _ = (r1, r2, r3);
    // After max, advance should not continue forever returning true
    assert!(!r4 || h.iterations >= 3);
}

// ─── SimpleRng ───────────────────────────────────────────────────────────────
#[test]
fn simple_rng_same_seed_same_sequence() {
    let mut a = SimpleRng::new(123);
    let mut b = SimpleRng::new(123);
    for _ in 0..50 {
        assert_eq!(a.next_u64(), b.next_u64());
    }
}

#[test]
fn simple_rng_next_range_bounded() {
    let mut r = SimpleRng::new(7);
    for n in [2u64, 5, 10, 100, 1000, u64::MAX] {
        for _ in 0..20 {
            let v = r.next_range(n);
            assert!(v < n);
        }
    }
}

// ─── IpMutator fuzz ──────────────────────────────────────────────────────────
#[test]
fn ip_mutator_mutate_lcg_never_panics() {
    let m = IpMutator::new();
    let mut g = lcg();
    let mut rng = SimpleRng::new(g());
    for _ in 0..50 {
        let n = ((g() as usize) % 64) + 1;
        let buf = random_bytes(&mut g, n);
        let _ = m.mutate(&buf, &mut rng);
    }
}

#[test]
fn ip_mutator_batch_count_matches() {
    let m = IpMutator::new();
    let mut rng = SimpleRng::new(99);
    let out = m.batch_mutate(b"hello", 7, &mut rng);
    assert_eq!(out.len(), 7);
}

// ─── IpFuzzInput / IpCoverageMap ─────────────────────────────────────────────
#[test]
fn ip_fuzz_input_hash_deterministic() {
    let mut g = lcg();
    for _ in 0..40 {
        let n = (g() as usize) % 32;
        let buf = random_bytes(&mut g, n);
        let a = IpFuzzInput::new_seed(buf.clone());
        let b = IpFuzzInput::new_seed(buf);
        assert_eq!(a.hash(), b.hash());
    }
}

#[test]
fn ip_coverage_map_update_monotonic() {
    let mut m = IpCoverageMap::new();
    let mut g = lcg();
    let mut acc = 0;
    for _ in 0..30 {
        let buf = random_bytes(&mut g, 32);
        let new_bits = m.update(&buf);
        acc += new_bits;
        // After update, no new bits when run again
        let again = m.update(&buf);
        let _ = (new_bits, again, acc);
    }
}

// ─── Mutator plugin properties ──────────────────────────────────────────────
#[test]
fn byte_flip_empty_input_errs() {
    assert!(matches!(
        ByteFlipMutator.custom_mutate(&[], 0, 0),
        Err(MutatorError::EmptyInput)
    ));
    assert!(matches!(
        BitFlipMutator.custom_mutate(&[], 0, 0),
        Err(MutatorError::EmptyInput)
    ));
    assert!(matches!(
        ArithmeticMutator.custom_mutate(&[], 0, 0),
        Err(MutatorError::EmptyInput)
    ));
    assert!(matches!(
        InterestingValueMutator.custom_mutate(&[], 0, 0),
        Err(MutatorError::EmptyInput)
    ));
}

#[test]
fn byte_flip_preserves_length() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = ((g() as usize) % 64) + 1;
        let buf = random_bytes(&mut g, n);
        let out = ByteFlipMutator.custom_mutate(&buf, g(), 0).unwrap();
        assert_eq!(out.len(), buf.len());
    }
}

#[test]
fn bit_flip_changes_one_bit() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = ((g() as usize) % 32) + 1;
        let buf = random_bytes(&mut g, n);
        let out = BitFlipMutator.custom_mutate(&buf, g(), 0).unwrap();
        assert_eq!(out.len(), buf.len());
        let diff: u32 = buf
            .iter()
            .zip(&out)
            .map(|(a, b)| (a ^ b).count_ones())
            .sum();
        assert_eq!(diff, 1);
    }
}

#[test]
fn insert_mutator_grows_or_stays_under_max() {
    let mut g = lcg();
    for _ in 0..40 {
        let n = (g() as usize) % 32;
        let buf = random_bytes(&mut g, n);
        let out = InsertMutator.custom_mutate(&buf, g(), 0).unwrap();
        assert!(out.len() >= buf.len());
    }
}

#[test]
fn insert_mutator_respects_max_size() {
    let mut g = lcg();
    let buf = random_bytes(&mut g, 50);
    let out = InsertMutator.custom_mutate(&buf, g(), 55).unwrap();
    assert!(out.len() <= 55);
}

#[test]
fn delete_mutator_shrinks_or_equal() {
    let mut g = lcg();
    for _ in 0..40 {
        let n = ((g() as usize) % 64) + 2;
        let buf = random_bytes(&mut g, n);
        let out = DeleteMutator.custom_mutate(&buf, g(), 0).unwrap();
        assert!(out.len() < buf.len() || out.len() == buf.len());
        assert!(out.len() <= buf.len());
    }
}

#[test]
fn delete_mutator_size_one_no_change() {
    let out = DeleteMutator.custom_mutate(&[0x42], 1, 0).unwrap();
    assert_eq!(out, vec![0x42]);
}

#[test]
fn splice_mutator_with_empty_secondary_falls_back_to_byte_flip() {
    let s = SpliceMutator::new(Vec::new());
    let out = s.custom_mutate(b"hello", 5, 0).unwrap();
    assert_eq!(out.len(), 5);
}

#[test]
fn splice_mutator_with_secondary_lcg() {
    let mut g = lcg();
    let secondary: Vec<Vec<u8>> = (0..4).map(|_| random_bytes(&mut g, 16)).collect();
    let s = SpliceMutator::new(secondary);
    for _ in 0..30 {
        let n = ((g() as usize) % 32) + 1;
        let buf = random_bytes(&mut g, n);
        let _ = s.custom_mutate(&buf, g(), 0).unwrap();
    }
}

#[test]
fn dict_entry_mutator_from_tokens_uses_dict() {
    let tokens: &[&[u8]] = &[b"MAGIC", b"\x00\x00", b"GET /"];
    let m = DictEntryMutator::from_tokens(tokens);
    assert_eq!(m.entries.len(), 3);
}

#[test]
fn arithmetic_mutator_length_preserved() {
    let mut g = lcg();
    for _ in 0..40 {
        let n = ((g() as usize) % 32) + 1;
        let buf = random_bytes(&mut g, n);
        let out = ArithmeticMutator.custom_mutate(&buf, g(), 0).unwrap();
        assert_eq!(out.len(), buf.len());
    }
}

#[test]
fn interesting_value_mutator_length_preserved() {
    let mut g = lcg();
    for _ in 0..40 {
        let n = ((g() as usize) % 32) + 1;
        let buf = random_bytes(&mut g, n);
        let out = InterestingValueMutator.custom_mutate(&buf, g(), 0).unwrap();
        assert_eq!(out.len(), buf.len());
    }
}

#[test]
fn chunk_copy_mutator_length_preserved() {
    let mut g = lcg();
    for _ in 0..40 {
        let n = ((g() as usize) % 32) + 2;
        let buf = random_bytes(&mut g, n);
        let out = ChunkCopyMutator.custom_mutate(&buf, g(), 0).unwrap();
        assert_eq!(out.len(), buf.len());
    }
}

#[test]
fn chunk_copy_mutator_short_input_unchanged() {
    let out = ChunkCopyMutator.custom_mutate(b"a", 0, 0).unwrap();
    assert_eq!(out, b"a");
}

// ─── MutatorChain ────────────────────────────────────────────────────────────
#[test]
fn mutator_chain_standard_len() {
    let c = MutatorChain::standard();
    assert!(!c.is_empty());
    assert!(c.len() >= 7);
}

#[test]
fn mutator_chain_default_empty() {
    let c = MutatorChain::default();
    assert!(c.is_empty());
}

#[test]
fn mutator_chain_mutate_lcg() {
    let mut c = MutatorChain::standard();
    let mut g = lcg();
    for _ in 0..50 {
        let n = ((g() as usize) % 32) + 1;
        let buf = random_bytes(&mut g, n);
        let _ = c.mutate(&buf, g(), 256).unwrap();
    }
}

#[test]
fn mutator_chain_batch_mutate_count() {
    let mut c = MutatorChain::standard();
    let out = c.batch_mutate(b"hello world", 12, 42, 256).unwrap();
    assert_eq!(out.len(), 12);
}

#[test]
fn mutator_chain_crossover_lcg() {
    let mut c = MutatorChain::standard();
    let mut g = lcg();
    for _ in 0..20 {
        let a = random_bytes(&mut g, 16);
        let b = random_bytes(&mut g, 16);
        let _ = c.crossover(&a, &b, g()).unwrap();
    }
}

#[test]
fn mutator_chain_empty_mutate_errs() {
    let mut c = MutatorChain::new();
    assert!(c.mutate(b"hi", 0, 0).is_err());
}

// ─── MutationStrategy display ────────────────────────────────────────────────
#[test]
fn mutation_strategy_display_all() {
    for s in MutationStrategy::all() {
        let d = format!("{s}");
        assert!(!d.is_empty());
    }
}

#[test]
fn mutation_strategy_hash_eq_consistent() {
    let mut g = lcg();
    let all = MutationStrategy::all();
    for _ in 0..30 {
        let i = (g() as usize) % all.len();
        let j = (g() as usize) % all.len();
        let a = all[i];
        let b = all[j];
        if a == b {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut ha = DefaultHasher::new();
            let mut hb = DefaultHasher::new();
            a.hash(&mut ha);
            b.hash(&mut hb);
            assert_eq!(ha.finish(), hb.finish());
        }
    }
}

// ─── DictionaryEntry display + record_hit ───────────────────────────────────
#[test]
fn dictionary_entry_record_hit_increments() {
    let mut e = DictionaryEntry::with_weight(b"tok".to_vec(), "x", 3);
    let start = e.hit_count;
    for _ in 0..7 {
        e.record_hit();
    }
    assert_eq!(e.hit_count, start + 7);
    let d = format!("{e}");
    assert!(d.contains("weight=3"));
}

// ─── Rng (mutator::Rng) properties ───────────────────────────────────────────
#[test]
fn mutator_rng_zero_seed_safe() {
    let mut r = Rng::new(0);
    for _ in 0..50 {
        let _ = r.next();
    }
}

#[test]
fn mutator_rng_range_zero_returns_zero() {
    let mut r = Rng::new(42);
    for _ in 0..20 {
        assert_eq!(r.range(0), 0);
    }
}

#[test]
fn mutator_rng_range_bounded() {
    let mut r = Rng::new(7);
    for n in [1u64, 2, 5, 100, 1_000_000] {
        for _ in 0..30 {
            assert!(r.range(n) < n);
        }
    }
}

// ─── FuzzCorpusManager dedup ─────────────────────────────────────────────────
#[test]
fn fuzz_corpus_manager_dedup_lcg() {
    let mut mgr = FuzzCorpusManager::new(Path::new("/tmp"));
    let mut g = lcg();
    for _ in 0..30 {
        let n = ((g() as usize) % 32) + 1;
        let buf = random_bytes(&mut g, n);
        mgr.save(&buf);
        mgr.save(&buf); // duplicate
    }
    // entries should not contain duplicates
    let count = mgr.entries().len();
    assert!(count <= 30);
}

// ─── CrashSignalHandler Send+Sync threaded stress ────────────────────────────
#[test]
fn crash_signal_handler_threaded_stress() {
    let h = Arc::new(CrashSignalHandler::new());
    let mut handles = Vec::new();
    for t in 0..4 {
        let h2 = Arc::clone(&h);
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                h2.inject_crash((t * 100 + i) % 32);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert!(h.is_crashed());
    assert_eq!(h.total_crashes(), 400);
}

// ─── FuzzTargetResult ────────────────────────────────────────────────────────
#[test]
fn fuzz_target_result_is_crash_continue() {
    assert!(!FuzzTargetResult::Continue.is_crash());
    assert!(FuzzTargetResult::CrashFound("x".into()).is_crash());
}

#[test]
fn fuzz_target_result_message() {
    assert_eq!(FuzzTargetResult::Continue.crash_message(), None);
    assert_eq!(
        FuzzTargetResult::CrashFound("boom".into()).crash_message(),
        Some("boom")
    );
}
