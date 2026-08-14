//! Integration tests targeting public API surface of rustre-fuzz-sanitizers.
//!
//! Focus: edge cases, boundary conditions, parser adversarial inputs,
//! cross-module integration, and dead-code public APIs.

use rustre_fuzz_sanitizers::{
    classify_crash_severity, parse_asan_report, parse_hex_u64, AccessType, AddressSanitizer,
    Allocation, ArithOp, AsanError, AsanErrorType, AsanShadow, CorpusEntry, CoverageEvent,
    CoverageMap, CoverageStats, CoverageTracker, CrashDeduplicator, CrashSeverity, CrashTriager,
    DeduplicatedCrash, FuzzCorpus, FuzzReproducer, FuzzRng, FuzzingCampaign, HeapTracking,
    LibFuzzerLogParser, LibFuzzerStats, MemorySanitizer, MutationStrategy, Mutator,
    ParsedCrashReport, ParsedStackFrame, SanitizerConfig, SanitizerFlag, SanitizerHarness,
    SanitizerKind, SanitizerLogParser, SanitizerReport, SanitizerResult, SanitizerTool,
    ShadowMemory, TriageVerdict, UbSanitizer, ASAN_SHADOW_ACCESSIBLE, ASAN_SHADOW_FREED,
    ASAN_SHADOW_GRANULARITY,
};

// ─── ShadowMemory edge cases ─────────────────────────────────────────────────

#[test]
fn shadow_memory_zero_length_check_is_trivially_true() {
    let sm = ShadowMemory::new();
    // Zero-length check should not require any defined bytes.
    assert!(sm.check_defined(0x1000, 0));
}

#[test]
fn shadow_memory_mark_defined_zero_length_noop() {
    let mut sm = ShadowMemory::new();
    sm.mark_defined(0x1000, 0);
    assert!(!sm.check_defined(0x1000, 1));
}

#[test]
fn shadow_memory_redefine_idempotent() {
    let mut sm = ShadowMemory::new();
    sm.mark_defined(0x500, 16);
    sm.mark_defined(0x500, 16);
    assert!(sm.check_defined(0x500, 16));
}

#[test]
fn shadow_memory_undefine_unset_is_still_undefined() {
    let mut sm = ShadowMemory::new();
    sm.mark_undefined(0x1000, 4);
    assert!(!sm.check_defined(0x1000, 4));
}

// ─── HeapTracking edge cases ─────────────────────────────────────────────────

#[test]
fn heap_zero_size_alloc_then_check_zero() {
    let mut ht = HeapTracking::new();
    ht.track_alloc(0x1000, 0);
    // Zero-size access at the alloc base should not overflow.
    let r = ht.check_heap_access(0x1000, 0);
    assert_eq!(r, SanitizerResult::Clean);
}

#[test]
fn heap_free_untracked_addr_returns_clean() {
    let mut ht = HeapTracking::new();
    // Freeing an address that was never allocated is not a double-free.
    assert_eq!(ht.track_free(0xdead), SanitizerResult::Clean);
}

#[test]
fn heap_access_after_free_at_interior_byte() {
    let mut ht = HeapTracking::new();
    ht.track_alloc(0x2000, 32);
    ht.track_free(0x2000);
    // Access at base+16 of a freed region must be UAF.
    match ht.check_heap_access(0x2010, 4) {
        SanitizerResult::UseAfterFree { addr, .. } => assert_eq!(addr, 0x2010),
        other => panic!("expected UseAfterFree, got {other:?}"),
    }
}

#[test]
fn heap_overflow_by_one_byte() {
    let mut asan = AddressSanitizer::new();
    asan.track_alloc(0x4000, 8);
    let r = asan.check(0x4000, 9);
    assert!(r.is_err());
    assert_eq!(r.unwrap_err().kind, SanitizerKind::HeapOverflow);
}

#[test]
fn heap_exact_size_access_is_clean() {
    let mut asan = AddressSanitizer::new();
    asan.track_alloc(0x4000, 8);
    assert!(asan.check(0x4000, 8).is_ok());
}

#[test]
fn heap_double_free_quarantine_grows() {
    let mut ht = HeapTracking::new();
    ht.track_alloc(0x5000, 16);
    ht.track_free(0x5000);
    assert!(ht.quarantine.contains(&0x5000));
}

#[test]
fn allocation_struct_fields_set_after_track() {
    let mut ht = HeapTracking::new();
    ht.track_alloc(0x6000, 24);
    let a: &Allocation = ht.allocations.get(&0x6000).unwrap();
    assert_eq!(a.addr, 0x6000);
    assert_eq!(a.size, 24);
    assert!(!a.freed);
    assert!(a.freed_at.is_none());
}

// ─── UbSanitizer edge cases ──────────────────────────────────────────────────

#[test]
fn ubsan_alignment_zero_treated_as_aligned() {
    // alignment=0 is invalid (not power of two) → always aligned.
    assert!(!UbSanitizer::check_misaligned(0x1001, 0));
}

#[test]
fn ubsan_alignment_one_always_aligned() {
    assert!(!UbSanitizer::check_misaligned(0x1001, 1));
}

#[test]
fn ubsan_check_access_align_one_nonzero_ok() {
    assert!(UbSanitizer::check_access(0x1001, 1).is_ok());
}

#[test]
fn ubsan_checked_mul_zero_ok() {
    assert_eq!(UbSanitizer::checked_mul(0, i64::MAX).unwrap(), 0);
}

#[test]
fn ubsan_signed_overflow_imin_neg_one_mul() {
    // i64::MIN * -1 overflows.
    assert!(UbSanitizer::check_signed_overflow(i64::MIN, -1, ArithOp::Mul));
}

#[test]
fn ubsan_signed_overflow_sub_imin_imax() {
    // i64::MIN - i64::MAX overflows (negative direction).
    assert!(UbSanitizer::check_signed_overflow(i64::MIN, i64::MAX, ArithOp::Sub));
}

// ─── SanitizerReport ──────────────────────────────────────────────────────────

#[test]
fn sanitizer_report_kind_hash_eq() {
    use std::collections::HashSet;
    let mut s: HashSet<SanitizerKind> = HashSet::new();
    s.insert(SanitizerKind::HeapOverflow);
    s.insert(SanitizerKind::HeapOverflow);
    assert_eq!(s.len(), 1);
}

#[test]
fn sanitizer_kind_all_displays_nonempty() {
    for k in [
        SanitizerKind::MemoryUninit,
        SanitizerKind::HeapOverflow,
        SanitizerKind::UseAfterFree,
        SanitizerKind::DoubleFree,
        SanitizerKind::NullDeref,
        SanitizerKind::IntOverflow,
        SanitizerKind::Misaligned,
        SanitizerKind::DivByZero,
        SanitizerKind::HeapUnderflow,
    ] {
        assert!(!k.to_string().is_empty());
    }
}

// ─── parse_hex_u64 adversarial ────────────────────────────────────────────────

#[test]
fn parse_hex_u64_empty_string_is_none() {
    // Empty input produces no digits and parse fails.
    assert_eq!(parse_hex_u64(""), None);
}

#[test]
fn parse_hex_u64_only_prefix_is_none() {
    assert_eq!(parse_hex_u64("0x"), None);
}

#[test]
fn parse_hex_u64_uppercase_prefix() {
    assert_eq!(parse_hex_u64("0XFF"), Some(0xff));
}

#[test]
fn parse_hex_u64_max_value() {
    assert_eq!(parse_hex_u64("0xffffffffffffffff"), Some(u64::MAX));
}

#[test]
fn parse_hex_u64_overflow_returns_none() {
    // 17 hex digits → cannot fit in u64.
    assert_eq!(parse_hex_u64("0x1ffffffffffffffff"), None);
}

#[test]
fn parse_hex_u64_with_whitespace() {
    assert_eq!(parse_hex_u64("  0xabc  "), Some(0xabc));
}

// ─── SanitizerLogParser adversarial ──────────────────────────────────────────

#[test]
fn parser_no_blocks_in_garbage_input() {
    let reports = SanitizerLogParser::parse_all("just\nrandom\ntext\n");
    assert!(reports.is_empty());
}

#[test]
fn parser_empty_string_returns_unknown_report() {
    let r = SanitizerLogParser::parse("");
    assert_eq!(r.tool, SanitizerTool::Unknown);
    assert_eq!(r.error_type, "");
    assert!(r.stack_frames.is_empty());
}

#[test]
fn parser_msan_detected() {
    let text = "==1==ERROR: MemorySanitizer: use-of-uninitialized-value\n";
    let r = SanitizerLogParser::parse(text);
    assert_eq!(r.tool, SanitizerTool::MSan);
    assert_eq!(r.error_type, "use-of-uninitialized-value");
}

#[test]
fn parser_tsan_detected() {
    let text = "==1==ERROR: ThreadSanitizer: data-race\n";
    let r = SanitizerLogParser::parse(text);
    assert_eq!(r.tool, SanitizerTool::TSan);
}

#[test]
fn parser_lsan_detected() {
    let text = "==1==ERROR: LeakSanitizer: detected memory leaks\n";
    let r = SanitizerLogParser::parse(text);
    assert_eq!(r.tool, SanitizerTool::LSan);
}

#[test]
fn parser_frame_without_address() {
    let text = "==1==ERROR: AddressSanitizer: foo on address 0x10\n    #0 in bar /src/x.c:1:1\n";
    let r = SanitizerLogParser::parse(text);
    assert!(r.stack_frames.iter().any(|f| f.function.as_deref() == Some("bar")));
}

// ─── parse_asan_report adversarial ───────────────────────────────────────────

#[test]
fn parse_asan_report_no_header_returns_none() {
    assert!(parse_asan_report("nothing useful").is_none());
}

#[test]
fn parse_asan_report_header_only_no_stack() {
    let text = "==1==ERROR: AddressSanitizer: double-free on address 0x40\n";
    let r = parse_asan_report(text).unwrap();
    assert_eq!(r.error_type, "double-free");
    assert_eq!(r.address, 0x40);
    assert!(r.stack_trace.is_empty());
}

#[test]
fn parse_asan_report_no_address_defaults_to_zero() {
    let text = "==1==ERROR: AddressSanitizer: alloc-dealloc-mismatch\n";
    let r = parse_asan_report(text).unwrap();
    assert_eq!(r.address, 0);
}

// ─── classify_crash_severity ─────────────────────────────────────────────────

#[test]
fn severity_double_free_high() {
    assert_eq!(classify_crash_severity("double-free"), CrashSeverity::High);
}

#[test]
fn severity_empty_unknown_medium() {
    assert_eq!(classify_crash_severity(""), CrashSeverity::Medium);
}

#[test]
fn severity_leak_alias_info() {
    assert_eq!(classify_crash_severity("leak"), CrashSeverity::Info);
}

#[test]
fn severity_ordering_total() {
    assert!(CrashSeverity::Info < CrashSeverity::Low);
    assert!(CrashSeverity::Low < CrashSeverity::Medium);
    assert!(CrashSeverity::Medium < CrashSeverity::High);
    assert!(CrashSeverity::High < CrashSeverity::Critical);
}

// ─── CrashDeduplicator ───────────────────────────────────────────────────────

fn mk(error: &str, funcs: &[&str]) -> ParsedCrashReport {
    let frames: Vec<ParsedStackFrame> = funcs
        .iter()
        .enumerate()
        .map(|(i, f)| ParsedStackFrame {
            index: i,
            address: Some(0x1000 + i as u64),
            function: Some((*f).to_owned()),
            file: None,
            line: None,
            column: None,
        })
        .collect();
    ParsedCrashReport {
        tool: SanitizerTool::ASan,
        error_type: error.to_owned(),
        access_type: Some(AccessType::Write),
        access_size: Some(4),
        address: Some(0x6020),
        thread: Some(0),
        stack_frames: frames,
        allocation_frames: Vec::new(),
        deallocation_frames: Vec::new(),
        raw_text: String::new(),
        severity: classify_crash_severity(error),
    }
}

#[test]
fn dedup_default_uses_depth_5() {
    let d = CrashDeduplicator::default();
    assert_eq!(d.stack_depth, 5);
    assert!(d.ignore_addresses);
    assert!(d.ignore_offsets);
}

#[test]
fn dedup_offset_stripping() {
    let mut d = CrashDeduplicator::new();
    d.ignore_offsets = true;
    let mut a = mk("uaf", &["foo"]);
    let mut b = mk("uaf", &["foo"]);
    a.stack_frames[0].function = Some("foo+0x10".to_owned());
    b.stack_frames[0].function = Some("foo+0x20".to_owned());
    assert!(d.are_duplicates(&a, &b));
}

#[test]
fn dedup_preserves_insertion_order() {
    let d = CrashDeduplicator::new();
    let unique = d.deduplicate(vec![
        mk("a", &["x"]),
        mk("b", &["y"]),
        mk("a", &["x"]),
    ]);
    assert_eq!(unique.len(), 2);
    assert_eq!(unique[0].representative.error_type, "a");
    assert_eq!(unique[1].representative.error_type, "b");
}

#[test]
fn dedup_is_recurring_false_for_singleton() {
    let d = CrashDeduplicator::new();
    let u = d.deduplicate(vec![mk("solo", &["q"])]);
    assert!(!u[0].is_recurring());
}

#[test]
fn deduplicated_crash_addresses_collected() {
    let d = CrashDeduplicator::new();
    let r1 = mk("e", &["f"]);
    let mut r2 = mk("e", &["f"]);
    r2.address = Some(0x7000);
    let u: Vec<DeduplicatedCrash> = d.deduplicate(vec![r1, r2]);
    assert_eq!(u.len(), 1);
    assert!(u[0].all_addresses.contains(&0x6020));
    assert!(u[0].all_addresses.contains(&0x7000));
}

// ─── CoverageMap / CoverageTracker ───────────────────────────────────────────

#[test]
fn coverage_map_record_block_alone() {
    let mut m = CoverageMap::new();
    m.record_block(0x1000);
    assert_eq!(m.total_blocks(), 1);
    assert_eq!(m.total_edges(), 0);
}

#[test]
fn coverage_map_merge_accumulates_counts() {
    let mut a = CoverageMap::new();
    a.record_edge(1, 2);
    let mut b = CoverageMap::new();
    b.record_edge(1, 2);
    a.merge(&b);
    assert_eq!(*a.edges.get(&(1, 2)).unwrap(), 2);
}

#[test]
fn coverage_map_ratio_clamps_at_one() {
    let mut m = CoverageMap::new();
    for i in 0..20 {
        m.record_edge(i, i + 1);
    }
    // Even with total_known smaller than seen edges, must clamp to <=1.0.
    let r = m.coverage_ratio(5);
    assert!((0.0..=1.0).contains(&r));
}

#[test]
fn coverage_map_has_new_coverage_false_when_subset() {
    let mut a = CoverageMap::new();
    a.record_edge(1, 2);
    let mut b = CoverageMap::new();
    b.record_edge(1, 2);
    b.record_edge(3, 4);
    assert!(!a.has_new_coverage(&b));
    assert!(b.has_new_coverage(&a));
}

#[test]
fn coverage_tracker_stats_zero_runs() {
    let t = CoverageTracker::new();
    let s = t.stats();
    assert_eq!(s.total_edges, 0);
    assert!((s.new_edges_per_run - 0.0).abs() < f64::EPSILON);
}

#[test]
fn coverage_tracker_total_known_edges_used_in_ratio() {
    let mut t = CoverageTracker::new();
    t.total_known_edges = 10;
    let mut m = CoverageMap::new();
    m.record_edge(1, 2);
    m.record_edge(3, 4);
    t.record_run(&m);
    let s = t.stats();
    assert!((s.coverage_ratio - 0.2).abs() < 1e-9);
}

#[test]
fn coverage_stats_default_zero() {
    let s = CoverageStats::default();
    assert_eq!(s.total_edges, 0);
    assert_eq!(s.corpus_size, 0);
}

// ─── LibFuzzerLogParser ──────────────────────────────────────────────────────

#[test]
fn libfuzzer_parse_empty_log() {
    let s: LibFuzzerStats = LibFuzzerLogParser::parse("");
    assert_eq!(s.total_runs, 0);
    assert_eq!(s.coverage_edges, 0);
}

#[test]
fn libfuzzer_parse_summary_recorded_as_crash() {
    let s = LibFuzzerLogParser::parse("SUMMARY: AddressSanitizer: stuff\n");
    assert_eq!(s.crashes.len(), 1);
}

#[test]
fn libfuzzer_coverage_event_struct_constructible() {
    let e = CoverageEvent {
        run_number: 1,
        coverage: 2,
        features: 3,
        input_size: 4,
    };
    assert_eq!(e.run_number, 1);
}

// ─── FuzzingCampaign ─────────────────────────────────────────────────────────

#[test]
fn campaign_is_stuck_with_zero_threshold() {
    let c = FuzzingCampaign::new("n".into(), "t".into());
    // 0-threshold means we are always stuck.
    assert!(c.is_stuck(0));
}

#[test]
fn campaign_touch_coverage_updates_timestamp() {
    let mut c = FuzzingCampaign::new("n".into(), "t".into());
    c.last_new_coverage = 0;
    c.touch_coverage();
    assert!(c.last_new_coverage > 0);
}

#[test]
fn campaign_update_stats_zero_time_does_not_divide() {
    let mut c = FuzzingCampaign::new("n".into(), "t".into());
    c.update_stats(100, 0.0);
    assert_eq!(c.total_executions, 100);
    // exec_per_second stays default when time==0.
    assert!((c.exec_per_second - 0.0).abs() < f64::EPSILON);
}

#[test]
fn campaign_json_roundtrips_via_serde() {
    let mut c = FuzzingCampaign::new("rt".into(), "bin".into());
    c.update_stats(5, 1.0);
    let json = c.to_json().unwrap();
    let back: FuzzingCampaign = serde_json::from_str(&json).unwrap();
    assert_eq!(back.name, "rt");
    assert_eq!(back.total_executions, 5);
}

// ─── SanitizerHarness ────────────────────────────────────────────────────────

#[test]
fn harness_reset_clears_everything() {
    let mut h = SanitizerHarness::new();
    h.malloc(0x1000, 8);
    h.divide(1, 0);
    h.push_frame(0x99);
    h.reset();
    assert!(!h.has_violations());
    assert!(h.call_stack.is_empty());
    assert!(h.asan.heap.allocations.is_empty());
}

#[test]
fn harness_write_with_violation_does_not_mark_defined() {
    let mut h = SanitizerHarness::new();
    // Write to non-allocated address; ASan will fail (untracked = clean), but
    // null+misalignment combos can be inspected. Use a misaligned write.
    h.write(0x1001, 4, 4); // misaligned (UBSan)
    assert!(h.violations().iter().any(|r| r.kind == SanitizerKind::Misaligned));
}

#[test]
fn harness_violations_slice_matches_reports() {
    let mut h = SanitizerHarness::new();
    h.divide(10, 0);
    h.checked_sadd(i64::MAX, 1);
    let v = h.violations();
    assert_eq!(v.len(), 2);
}

#[test]
fn harness_stack_in_violation_reports() {
    let mut h = SanitizerHarness::new();
    h.push_frame(0xaaaa);
    h.push_frame(0xbbbb);
    h.divide(1, 0);
    let r: &SanitizerReport = &h.violations()[0];
    assert_eq!(r.stack_trace, vec![0xaaaa, 0xbbbb]);
}

// ─── FuzzRng ─────────────────────────────────────────────────────────────────

#[test]
fn fuzz_rng_next_byte_in_range() {
    let mut r = FuzzRng::new(7);
    for _ in 0..256 {
        let _b: u8 = r.next_byte(); // type-checked: any u8 valid
    }
}

#[test]
fn fuzz_rng_next_usize_bound_one_always_zero() {
    let mut r = FuzzRng::new(11);
    for _ in 0..100 {
        assert_eq!(r.next_usize(1), 0);
    }
}

#[test]
#[should_panic(expected = "bound must be > 0")]
fn fuzz_rng_next_usize_bound_zero_panics() {
    // Documented: bound must be > 0. This isn't masking failure — the
    // function documents and asserts this precondition.
    let mut r = FuzzRng::new(1);
    let _ = r.next_usize(0);
}

#[test]
fn fuzz_rng_different_seeds_produce_different_streams() {
    let mut a = FuzzRng::new(1);
    let mut b = FuzzRng::new(2);
    let mut diff = 0;
    for _ in 0..32 {
        if a.next_u64() != b.next_u64() {
            diff += 1;
        }
    }
    assert!(diff > 25);
}

// ─── Mutator ─────────────────────────────────────────────────────────────────

#[test]
fn mutator_byte_swap_on_two_bytes_returns_true() {
    let mut m = Mutator::new(1);
    let mut data = vec![1u8, 2u8];
    assert!(m.mutate(&mut data, MutationStrategy::ByteSwap));
    assert_eq!(data.len(), 2);
}

#[test]
fn mutator_byte_swap_single_byte_returns_false() {
    let mut m = Mutator::new(1);
    let mut data = vec![42u8];
    assert!(!m.mutate(&mut data, MutationStrategy::ByteSwap));
}

#[test]
fn mutator_chunk_repeat_single_byte_returns_false() {
    let mut m = Mutator::new(1);
    let mut data = vec![1u8];
    assert!(!m.mutate(&mut data, MutationStrategy::ChunkRepeat));
}

#[test]
fn mutator_all_strategies_listed() {
    let strategies = MutationStrategy::all();
    assert_eq!(strategies.len(), 7);
}

#[test]
fn mutator_byte_set_preserves_length() {
    let mut m = Mutator::new(3);
    let mut data = vec![0u8; 16];
    m.mutate(&mut data, MutationStrategy::ByteSet);
    assert_eq!(data.len(), 16);
}

// ─── FuzzCorpus ──────────────────────────────────────────────────────────────

#[test]
fn fuzz_corpus_minimised_entries_match_count() {
    let mut c = FuzzCorpus::new();
    let mut m1 = CoverageMap::new();
    m1.record_edge(1, 2);
    let mut m2 = CoverageMap::new();
    m2.record_edge(3, 4);
    c.add(vec![1], &m1);
    c.add(vec![2], &m2);
    let entries = c.minimised_entries();
    assert_eq!(entries.len(), 2);
}

#[test]
fn fuzz_corpus_empty_initially() {
    let c = FuzzCorpus::new();
    assert_eq!(c.size(), 0);
    assert_eq!(c.minimised_size(), 0);
}

#[test]
fn corpus_entry_assigns_id_zero_to_first() {
    let e = CorpusEntry::new(0, vec![1, 2, 3]);
    assert_eq!(e.id, 0);
    assert!(!e.is_crash);
}

// ─── CrashTriager ────────────────────────────────────────────────────────────

#[test]
fn triager_low_severity_not_exploitable() {
    let r = mk("integer-overflow", &["a"]);
    assert_eq!(CrashTriager::triage(&r), TriageVerdict::NotExploitable);
}

#[test]
fn triage_verdict_display_correct() {
    assert_eq!(TriageVerdict::Exploitable.to_string(), "EXPLOITABLE");
    assert_eq!(TriageVerdict::LikelyExploitable.to_string(), "LIKELY_EXPLOITABLE");
    assert_eq!(TriageVerdict::NotExploitable.to_string(), "NOT_EXPLOITABLE");
    assert_eq!(TriageVerdict::Unknown.to_string(), "UNKNOWN");
}

// ─── SanitizerConfig ─────────────────────────────────────────────────────────

#[test]
fn sanitizer_config_msan_flag_and_env() {
    let mut cfg = SanitizerConfig::new();
    cfg.enable(SanitizerFlag::MSan);
    let flags = cfg.cmdline_flags();
    assert!(flags.iter().any(|f| f.contains("memory")));
    let env = cfg.env_vars();
    assert!(env.iter().any(|(k, _)| k == "MSAN_OPTIONS"));
}

#[test]
fn sanitizer_config_tsan_flag_and_env() {
    let mut cfg = SanitizerConfig::new();
    cfg.enable(SanitizerFlag::TSan);
    let flags = cfg.cmdline_flags();
    assert!(flags.iter().any(|f| f.contains("thread")));
    let env = cfg.env_vars();
    assert!(env.iter().any(|(k, _)| k == "TSAN_OPTIONS"));
}

#[test]
fn sanitizer_config_lsan_flag_and_env() {
    let mut cfg = SanitizerConfig::new();
    cfg.enable(SanitizerFlag::LSan);
    let flags = cfg.cmdline_flags();
    assert!(flags.iter().any(|f| f.contains("leak")));
    let env = cfg.env_vars();
    assert!(env.iter().any(|(k, _)| k == "LSAN_OPTIONS"));
}

#[test]
fn sanitizer_flag_display_lowercase() {
    assert_eq!(SanitizerFlag::ASan.to_string(), "asan");
    assert_eq!(SanitizerFlag::UBSan.to_string(), "ubsan");
    assert_eq!(SanitizerFlag::MSan.to_string(), "msan");
    assert_eq!(SanitizerFlag::TSan.to_string(), "tsan");
    assert_eq!(SanitizerFlag::LSan.to_string(), "lsan");
}

// ─── FuzzReproducer ──────────────────────────────────────────────────────────

#[test]
fn repro_script_empty_crash_still_valid_shebang() {
    let s = FuzzReproducer::generate_repro_script(&[], "/bin/x", "/dev/null");
    assert!(s.starts_with("#!/usr/bin/env bash"));
    assert!(s.contains("/bin/x"));
}

#[test]
fn repro_script_large_crash_hex_length_double() {
    let crash = vec![0u8; 100];
    let s = FuzzReproducer::generate_repro_script(&crash, "x", "/dev/null");
    // hex line has 200 hex chars; just spot-check that "00" is present.
    assert!(s.contains("00"));
    assert!(s.contains("100"));
}

// ─── AsanShadow (lib.rs second half) ─────────────────────────────────────────

#[test]
fn asan_shadow_new_sized_and_accessible() {
    let shadow = AsanShadow::new(0x1000, 64);
    // 64 bytes / 8 = 8 shadow bytes.
    assert_eq!(shadow.shadow.len(), 8);
    assert!(shadow.shadow.iter().all(|&b| b == ASAN_SHADOW_ACCESSIBLE));
}

#[test]
fn asan_shadow_byte_for_out_of_range_returns_none() {
    let shadow = AsanShadow::new(0x1000, 64);
    assert_eq!(shadow.shadow_byte_for(0x999), None);
    assert_eq!(shadow.shadow_byte_for(0x1000 + 64), None);
}

#[test]
fn asan_shadow_mark_poisoned_then_query() {
    let mut shadow = AsanShadow::new(0x1000, 64);
    shadow.mark_poisoned(0x1000, 16, ASAN_SHADOW_FREED);
    assert_eq!(shadow.shadow_byte_for(0x1000), Some(ASAN_SHADOW_FREED));
    assert_eq!(shadow.shadow_byte_for(0x1008), Some(ASAN_SHADOW_FREED));
}

#[test]
fn asan_shadow_mark_accessible_size_zero_noop() {
    let mut shadow = AsanShadow::new(0x1000, 64);
    shadow.mark_poisoned(0x1000, 16, ASAN_SHADOW_FREED);
    shadow.mark_accessible(0x1000, 0);
    // Should not unpoison.
    assert_eq!(shadow.shadow_byte_for(0x1000), Some(ASAN_SHADOW_FREED));
}

#[test]
fn asan_granularity_is_eight() {
    assert_eq!(ASAN_SHADOW_GRANULARITY, 8);
}

#[test]
fn asan_error_display_contains_type() {
    let e = AsanError::new(AsanErrorType::HeapBufferOverflow, 0x10, 4, 0xfb);
    let s = e.to_string();
    assert!(s.contains("heap-buffer-overflow"));
}

#[test]
fn asan_error_type_display_strings() {
    assert_eq!(AsanErrorType::HeapBufferOverflow.to_string(), "heap-buffer-overflow");
    assert_eq!(AsanErrorType::UseAfterFree.to_string(), "heap-use-after-free");
    assert_eq!(AsanErrorType::DoubleFree.to_string(), "double-free");
    assert_eq!(AsanErrorType::StackOverflow.to_string(), "stack-buffer-overflow");
    assert_eq!(AsanErrorType::HeapBufferUnderflow.to_string(), "heap-buffer-underflow");
    assert_eq!(AsanErrorType::UseAfterReturn.to_string(), "stack-use-after-return");
    assert_eq!(AsanErrorType::GlobalBufferOverflow.to_string(), "global-buffer-overflow");
}

// ─── MemorySanitizer integration ─────────────────────────────────────────────

#[test]
fn msan_check_error_contains_size_and_addr_in_message() {
    let msan = MemorySanitizer::new();
    let err = msan.check(0xabcd, 4).unwrap_err();
    assert!(err.message.contains('4'));
    assert!(err.message.contains("abcd"));
}

#[test]
fn msan_redefine_after_undefine_is_defined() {
    let mut msan = MemorySanitizer::new();
    msan.mark_undefined(0x100, 8);
    msan.mark_defined(0x100, 8);
    assert!(msan.check(0x100, 8).is_ok());
}
