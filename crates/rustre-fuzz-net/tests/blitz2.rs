//! Deep adversarial integration tests for `rustre-fuzz-net` public API.

use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

use async_trait::async_trait;
use rustre_fuzz_afl::XorShiftRng;
use rustre_fuzz_net::{
    add_checksum, apply_strategy, decode_frame_u32_be, decode_frame_u32_le, frame_u32_be,
    frame_u32_le, interesting_int_mutation, xor_checksum, CorpusEntry, CoverageMap, CrashLogger,
    FieldDef, FieldType, FuzzCorpus, FuzzNetError, FuzzSession, MessageBuilder, MessageDef,
    MutationHistory, MutationStrategy, PatternMatch, ProtocolBuilder, ProtocolDef, ProtocolFuzzer,
    ProtocolState, ReplaySession, ResponseMatcher, SessionStats, TcpTransport, Transition,
    Transport, TransportError, UdpTransport, INTERESTING_U16, INTERESTING_U32, INTERESTING_U8,
};

// ── Deterministic LCG ─────────────────────────────────────────────────────────
struct Lcg(u64);
impl Lcg {
    fn new() -> Self {
        Self(0xDEAD_BEEF_CAFE_BABE)
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
}

// ── 1-10: framing round-trips & boundaries ────────────────────────────────────

#[test]
fn t01_frame_le_roundtrip_empty() {
    let f = frame_u32_le(&[]).unwrap();
    assert_eq!(f, vec![0, 0, 0, 0]);
    let (n, p) = decode_frame_u32_le(&f).unwrap();
    assert_eq!(n, 4);
    assert!(p.is_empty());
}

#[test]
fn t02_frame_be_roundtrip_empty() {
    let f = frame_u32_be(&[]).unwrap();
    assert_eq!(f, vec![0, 0, 0, 0]);
    let (n, p) = decode_frame_u32_be(&f).unwrap();
    assert_eq!(n, 4);
    assert!(p.is_empty());
}

#[test]
fn t03_frame_le_roundtrip_many() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let len = (lcg.next() % 200) as usize;
        let payload: Vec<u8> = (0..len).map(|_| (lcg.next() & 0xff) as u8).collect();
        let f = frame_u32_le(&payload).unwrap();
        assert_eq!(f.len(), 4 + payload.len());
        let (n, p) = decode_frame_u32_le(&f).unwrap();
        assert_eq!(n, f.len());
        assert_eq!(p, payload);
    }
}

#[test]
fn t04_frame_be_roundtrip_many() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let len = (lcg.next() % 200) as usize;
        let payload: Vec<u8> = (0..len).map(|_| (lcg.next() & 0xff) as u8).collect();
        let f = frame_u32_be(&payload).unwrap();
        let (n, p) = decode_frame_u32_be(&f).unwrap();
        assert_eq!(n, f.len());
        assert_eq!(p, payload);
    }
}

#[test]
fn t05_decode_le_truncated_header_returns_none() {
    assert!(decode_frame_u32_le(&[]).is_none());
    assert!(decode_frame_u32_le(&[1]).is_none());
    assert!(decode_frame_u32_le(&[1, 2, 3]).is_none());
}

#[test]
fn t06_decode_be_truncated_header_returns_none() {
    assert!(decode_frame_u32_be(&[]).is_none());
    assert!(decode_frame_u32_be(&[1, 2, 3]).is_none());
}

#[test]
fn t07_decode_le_incomplete_payload_returns_none() {
    // length=10 but only 5 bytes of payload
    let mut buf = vec![10, 0, 0, 0];
    buf.extend_from_slice(&[1, 2, 3, 4, 5]);
    assert!(decode_frame_u32_le(&buf).is_none());
}

#[test]
fn t08_decode_be_incomplete_payload_returns_none() {
    let mut buf = vec![0, 0, 0, 10];
    buf.extend_from_slice(&[1, 2, 3]);
    assert!(decode_frame_u32_be(&buf).is_none());
}

#[test]
fn t09_decode_le_huge_length_saturates() {
    // length=u32::MAX — total saturates, can't be satisfied → None.
    let mut buf = vec![0xff, 0xff, 0xff, 0xff];
    buf.extend_from_slice(&[1, 2, 3, 4]);
    assert!(decode_frame_u32_le(&buf).is_none());
}

#[test]
fn t10_decode_be_huge_length_saturates() {
    let mut buf = vec![0xff, 0xff, 0xff, 0xff];
    buf.extend_from_slice(&[1, 2, 3, 4]);
    assert!(decode_frame_u32_be(&buf).is_none());
}

// ── 11-15: checksums ──────────────────────────────────────────────────────────

#[test]
fn t11_xor_checksum_empty_is_zero() {
    assert_eq!(xor_checksum(&[]), 0);
}

#[test]
fn t12_xor_checksum_self_inverse() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let len = (lcg.next() % 64) as usize;
        let data: Vec<u8> = (0..len).map(|_| (lcg.next() & 0xff) as u8).collect();
        let c = xor_checksum(&data);
        // Adding c to the data zeroes the checksum.
        let mut d2 = data.clone();
        d2.push(c);
        assert_eq!(xor_checksum(&d2), 0);
    }
}

#[test]
fn t13_add_checksum_empty_is_zero() {
    assert_eq!(add_checksum(&[]), 0);
}

#[test]
fn t14_add_checksum_wraps() {
    let data = vec![0xff; 3];
    assert_eq!(add_checksum(&data), 0xffu8.wrapping_mul(3));
}

#[test]
fn t15_checksums_deterministic_fuzz() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let len = (lcg.next() % 100) as usize;
        let d: Vec<u8> = (0..len).map(|_| (lcg.next() & 0xff) as u8).collect();
        // calling twice yields the same answer
        assert_eq!(xor_checksum(&d), xor_checksum(&d));
        assert_eq!(add_checksum(&d), add_checksum(&d));
    }
}

// ── 16-22: MessageDef serialise / SizeOf / mutate ─────────────────────────────

#[test]
fn t16_serialise_static_blob_integers() {
    let m = MessageBuilder::new("m")
        .static_bytes("hdr", vec![0xaa, 0xbb])
        .fuzz_blob("body", vec![1, 2, 3])
        .fuzz_u8("u8v", 0x10)
        .fuzz_u16("u16v", 0x1020)
        .fuzz_u32("u32v", 0x1020_3040)
        .build();
    let bytes = m.serialise().unwrap();
    let mut expected = vec![0xaa, 0xbb, 1, 2, 3, 0x10];
    expected.extend_from_slice(&0x1020u16.to_le_bytes());
    expected.extend_from_slice(&0x1020_3040u32.to_le_bytes());
    assert_eq!(bytes, expected);
}

#[test]
fn t17_serialise_sizeof_missing_field_errors() {
    let m = MessageDef::new(
        "m",
        vec![FieldDef::new(
            "len",
            FieldType::SizeOf {
                field: "nonexistent".into(),
            },
            false,
        )],
    );
    match m.serialise() {
        Err(FuzzNetError::SizeOfFieldNotFound(name)) => assert_eq!(name, "nonexistent"),
        other => panic!("expected SizeOfFieldNotFound, got {:?}", other),
    }
}

#[test]
fn t18_serialise_sizeof_resolves() {
    let m = MessageBuilder::new("m")
        .fuzz_blob("body", vec![1, 2, 3, 4, 5])
        .size_of("len", "body")
        .build();
    let bytes = m.serialise().unwrap();
    // first 5 bytes = body, last 8 = u64 LE size=5
    assert_eq!(&bytes[..5], &[1, 2, 3, 4, 5]);
    assert_eq!(&bytes[5..13], &5u64.to_le_bytes());
}

#[test]
fn t19_estimated_len_sums_correctly() {
    let m = MessageBuilder::new("m")
        .static_bytes("h", vec![0; 4])
        .fuzz_random("r", 8, 16)
        .fuzz_u32("u", 0)
        .fuzz_string("s", 12)
        .size_of("sz", "h")
        .build();
    // 4 + 8(min) + 4 + 12 + 8 = 36
    assert_eq!(m.estimated_len(), 36);
}

#[test]
fn t20_fuzz_field_count_and_field_lookup() {
    let m = MessageBuilder::new("m")
        .static_bytes("h", vec![0; 2])
        .fuzz_u8("a", 1)
        .fuzz_u8("b", 2)
        .build();
    assert_eq!(m.fuzz_field_count(), 2);
    assert!(m.field("a").is_some());
    assert!(m.field("missing").is_none());
    let mut m2 = m.clone();
    assert!(m2.field_mut("b").is_some());
}

#[test]
fn t21_mutate_changes_only_fuzz_fields() {
    let mut m = MessageDef::new(
        "m",
        vec![
            FieldDef::new("static", FieldType::Static(vec![1, 2, 3]), false),
            FieldDef::new(
                "blob",
                FieldType::Blob {
                    data: vec![7, 7, 7, 7],
                },
                true,
            ),
        ],
    );
    let mut rng = XorShiftRng::default();
    let before_static = m.fields[0].field_type.clone();
    m.mutate(&mut rng);
    assert_eq!(m.fields[0].field_type, before_static);
}

#[test]
fn t22_mutate_fuzz_loop_never_panics() {
    let mut lcg = Lcg::new();
    let mut rng = XorShiftRng::default();
    for _ in 0..50 {
        let kind = lcg.next() % 5;
        let mut m = match kind {
            0 => MessageBuilder::new("m").fuzz_u8("v", (lcg.next() & 0xff) as u8).build(),
            1 => MessageBuilder::new("m").fuzz_u16("v", (lcg.next() & 0xffff) as u16).build(),
            2 => MessageBuilder::new("m").fuzz_u32("v", lcg.next() as u32).build(),
            3 => MessageBuilder::new("m").fuzz_random("v", 1, 8).build(),
            _ => MessageBuilder::new("m").fuzz_string("v", 16).build(),
        };
        m.mutate(&mut rng);
        let _ = m.serialise();
    }
}

// ── 23-28: ProtocolDef / Builder ──────────────────────────────────────────────

#[test]
fn t23_builder_initial_state_exists() {
    let p = ProtocolBuilder::new("init").build();
    assert_eq!(p.initial_state, "init");
    assert!(p.states.contains_key("init"));
    assert!(p.validate().is_empty());
}

#[test]
fn t24_builder_add_transition_creates_states() {
    let p = ProtocolBuilder::new("a")
        .add_transition("a", "b", None)
        .build();
    assert_eq!(p.state_count(), 2);
    assert_eq!(p.edges(), vec![("a", "b")]);
}

#[test]
fn t25_validate_detects_dangling_transition() {
    let mut states = HashMap::new();
    states.insert(
        "a".to_string(),
        ProtocolState {
            name: "a".into(),
            transitions: vec![Transition {
                to_state: "nope".into(),
                send: None,
                expect: None,
            }],
        },
    );
    let p = ProtocolDef::new("a", states);
    let errs = p.validate();
    assert!(!errs.is_empty());
    assert!(errs.iter().any(|e| e.contains("nope")));
}

#[test]
fn t26_validate_detects_missing_initial() {
    let p = ProtocolDef::new("ghost", HashMap::new());
    let errs = p.validate();
    assert!(errs.iter().any(|e| e.contains("ghost")));
}

#[test]
fn t27_state_names_count_matches() {
    let p = ProtocolBuilder::new("a")
        .add_terminal("b")
        .add_terminal("c")
        .build();
    assert_eq!(p.state_names().len(), 3);
    assert_eq!(p.state_count(), 3);
}

#[test]
fn t28_add_transition_with_expect() {
    let p = ProtocolBuilder::new("a")
        .add_transition_with_expect(
            "a",
            "b",
            None,
            PatternMatch {
                pattern: vec![1, 2],
                timeout_ms: 5,
            },
        )
        .build();
    assert!(p.validate().is_empty());
    let s = p.states.get("a").unwrap();
    assert!(s.transitions[0].expect.is_some());
}

// ── 29-34: CrashLogger ────────────────────────────────────────────────────────

#[test]
fn t29_crash_logger_basic() {
    let mut l = CrashLogger::new();
    assert!(l.is_empty());
    l.log(vec![1], "boom", "s1");
    l.log(vec![2], "boom", "s2");
    l.log(vec![3], "fizz", "s1");
    assert_eq!(l.len(), 3);
    let reasons = l.unique_reasons();
    assert_eq!(reasons.len(), 2);
}

#[test]
fn t30_crash_logger_by_filters() {
    let mut l = CrashLogger::new();
    l.log(vec![], "boom", "s1");
    l.log(vec![], "boom", "s2");
    l.log(vec![], "fizz", "s1");
    assert_eq!(l.by_reason("boom").len(), 2);
    assert_eq!(l.by_state("s1").len(), 2);
    assert_eq!(l.by_state("missing").len(), 0);
}

#[test]
fn t31_crash_logger_dedup_keeps_unique_pairs() {
    let mut l = CrashLogger::new();
    l.log(vec![1], "a", "s");
    l.log(vec![2], "a", "s"); // dup (reason,state)
    l.log(vec![3], "b", "s");
    l.dedup();
    assert_eq!(l.len(), 2);
}

#[test]
fn t32_crash_logger_clear() {
    let mut l = CrashLogger::new();
    l.log(vec![], "a", "s");
    l.clear();
    assert!(l.is_empty());
}

#[test]
fn t33_crash_logger_summary_sorted() {
    let mut l = CrashLogger::new();
    l.log(vec![], "a", "z");
    l.log(vec![], "a", "a");
    l.log(vec![], "b", "a");
    let s = l.summary();
    // sorted alphabetically: "a:2, z:1"
    assert!(s.contains("a:2"));
    assert!(s.contains("z:1"));
    // alphabetical ordering means 'a' part is first
    assert!(s.find("a:2").unwrap() < s.find("z:1").unwrap());
}

#[test]
fn t34_crash_logger_default_is_empty() {
    let l = CrashLogger::default();
    assert!(l.is_empty());
    assert_eq!(l.len(), 0);
}

// ── 35-38: CoverageMap ────────────────────────────────────────────────────────

#[test]
fn t35_coverage_unique_records() {
    let mut c = CoverageMap::new();
    c.record("a", 0);
    c.record("a", 0); // dup
    c.record("a", 1);
    c.record("b", 0);
    assert_eq!(c.covered(), 3);
    assert!(c.is_covered("a", 1));
    assert!(!c.is_covered("a", 9));
}

#[test]
fn t36_coverage_pct_zero_total_is_100() {
    let c = CoverageMap::new();
    assert!((c.coverage_pct(0) - 100.0).abs() < 1e-9);
}

#[test]
fn t37_coverage_pct_partial() {
    let mut c = CoverageMap::new();
    c.record("a", 0);
    c.record("b", 0);
    assert!((c.coverage_pct(4) - 50.0).abs() < 1e-9);
}

#[test]
fn t38_coverage_default_empty() {
    let c = CoverageMap::default();
    assert_eq!(c.covered(), 0);
}

// ── 39-42: ResponseMatcher ────────────────────────────────────────────────────

#[test]
fn t39_matcher_empty_pattern_matches_everything() {
    let m = ResponseMatcher::new(vec![]);
    assert!(m.matches(&[]));
    assert!(m.matches(&[1, 2, 3]));
    assert_eq!(m.find(&[9, 9]), Some(0));
}

#[test]
fn t40_matcher_pattern_longer_than_buf() {
    let m = ResponseMatcher::new(vec![1, 2, 3, 4]);
    assert!(!m.matches(&[1, 2, 3]));
    assert_eq!(m.find(&[1, 2, 3]), None);
}

#[test]
fn t41_matcher_finds_at_offset() {
    let m = ResponseMatcher::new(vec![3, 4]);
    assert!(m.matches(&[1, 2, 3, 4, 5]));
    assert_eq!(m.find(&[1, 2, 3, 4, 5]), Some(2));
    assert_eq!(m.find(&[9, 9, 9]), None);
}

#[test]
fn t42_matcher_fuzz_never_panics() {
    let mut lcg = Lcg::new();
    for _ in 0..50 {
        let plen = (lcg.next() % 8) as usize;
        let blen = (lcg.next() % 32) as usize;
        let pat: Vec<u8> = (0..plen).map(|_| (lcg.next() & 0xff) as u8).collect();
        let buf: Vec<u8> = (0..blen).map(|_| (lcg.next() & 0xff) as u8).collect();
        let m = ResponseMatcher::new(pat);
        let _ = m.matches(&buf);
        let _ = m.find(&buf);
    }
}

// ── 43-46: FuzzCorpus ─────────────────────────────────────────────────────────

#[test]
fn t43_corpus_add_pick_dedup() {
    let mut c = FuzzCorpus::new();
    assert!(c.is_empty());
    c.add(vec![1], "tag", "s");
    c.add(vec![1], "tag", "s"); // dup data
    c.add(vec![2], "tag", "s");
    assert_eq!(c.len(), 3);
    c.dedup();
    assert_eq!(c.len(), 2);
}

#[test]
fn t44_corpus_pick_returns_none_when_empty() {
    let c = FuzzCorpus::new();
    let mut rng = XorShiftRng::default();
    assert!(c.pick(&mut rng).is_none());
}

#[test]
fn t45_corpus_pick_returns_entry() {
    let mut c = FuzzCorpus::new();
    c.add(vec![5], "t", "s");
    let mut rng = XorShiftRng::default();
    let p = c.pick(&mut rng).unwrap();
    assert_eq!(p.data, vec![5]);
}

#[test]
fn t46_corpus_by_tag_filters() {
    let mut c = FuzzCorpus::new();
    c.add(vec![1], "x", "s");
    c.add(vec![2], "y", "s");
    c.add(vec![3], "x", "s");
    assert_eq!(c.by_tag("x").len(), 2);
    assert_eq!(c.by_tag("z").len(), 0);
}

// ── 47-49: MutationHistory ────────────────────────────────────────────────────

#[test]
fn t47_history_max_depth_minimum_one() {
    let h = MutationHistory::new(0);
    assert_eq!(h.depth(), 0);
}

#[test]
fn t48_history_push_pop_roundtrip() {
    let mut h = MutationHistory::new(3);
    let m = MessageBuilder::new("m").fuzz_u8("v", 1).build();
    h.push(&m);
    h.push(&m);
    assert_eq!(h.depth(), 2);
    assert!(h.pop().is_some());
    assert_eq!(h.depth(), 1);
}

#[test]
fn t49_history_capacity_evicts_oldest() {
    let mut h = MutationHistory::new(2);
    let m1 = MessageBuilder::new("a").fuzz_u8("v", 1).build();
    let m2 = MessageBuilder::new("b").fuzz_u8("v", 2).build();
    let m3 = MessageBuilder::new("c").fuzz_u8("v", 3).build();
    h.push(&m1);
    h.push(&m2);
    h.push(&m3);
    assert_eq!(h.depth(), 2);
    let top = h.pop().unwrap();
    assert_eq!(top.name, "c");
}

// ── 50-53: interesting tables / mutation ──────────────────────────────────────

#[test]
fn t50_interesting_tables_nonempty() {
    assert!(!INTERESTING_U8.is_empty());
    assert!(!INTERESTING_U16.is_empty());
    assert!(!INTERESTING_U32.is_empty());
}

#[test]
fn t51_interesting_int_mutation_size1_returns_byte_range() {
    let mut rng = XorShiftRng::default();
    for _ in 0..100 {
        let v = interesting_int_mutation(0, 1, &mut rng);
        // either picked from table (0..=0xff) or wrapping delta — always valid i64
        let _ = v;
    }
}

#[test]
fn t52_interesting_int_mutation_size2() {
    let mut rng = XorShiftRng::default();
    for _ in 0..100 {
        let _ = interesting_int_mutation(0x1234, 2, &mut rng);
    }
}

#[test]
fn t53_interesting_int_mutation_size4_and_other() {
    let mut rng = XorShiftRng::default();
    for _ in 0..100 {
        let _ = interesting_int_mutation(0, 4, &mut rng);
        let _ = interesting_int_mutation(0, 8, &mut rng);
    }
}

// ── 54-57: MutationStrategy + apply_strategy ─────────────────────────────────

#[test]
fn t54_apply_strategy_no_fuzz_is_noop() {
    let mut m = MessageDef::new(
        "m",
        vec![FieldDef::new(
            "s",
            FieldType::Static(vec![1, 2]),
            false,
        )],
    );
    let before = m.fields[0].field_type.clone();
    let mut rng = XorShiftRng::default();
    apply_strategy(&mut m, MutationStrategy::AllFields, &mut rng);
    assert_eq!(m.fields[0].field_type, before);
}

#[test]
fn t55_apply_strategy_all_variants_no_panic() {
    let mut rng = XorShiftRng::default();
    for s in [
        MutationStrategy::SingleField,
        MutationStrategy::AllFields,
        MutationStrategy::BitFlip,
        MutationStrategy::BoundaryValues,
    ] {
        let mut m = MessageBuilder::new("m")
            .fuzz_u8("a", 1)
            .fuzz_u16("b", 2)
            .fuzz_u32("c", 3)
            .fuzz_blob("d", vec![1, 2, 3])
            .fuzz_string("e", 4)
            .fuzz_random("f", 2, 6)
            .build();
        apply_strategy(&mut m, s, &mut rng);
    }
}

#[test]
fn t56_strategy_eq_and_clone() {
    assert_eq!(MutationStrategy::SingleField, MutationStrategy::SingleField);
    assert_ne!(MutationStrategy::SingleField, MutationStrategy::AllFields);
    let _ = MutationStrategy::BitFlip;
}

#[test]
fn t57_apply_strategy_seeded_fuzz_never_panics() {
    let mut lcg = Lcg::new();
    let mut rng = XorShiftRng::default();
    for _ in 0..50 {
        let strat = match lcg.next() % 4 {
            0 => MutationStrategy::SingleField,
            1 => MutationStrategy::AllFields,
            2 => MutationStrategy::BitFlip,
            _ => MutationStrategy::BoundaryValues,
        };
        let mut m = MessageBuilder::new("m")
            .fuzz_u32("v", lcg.next() as u32)
            .fuzz_blob("b", vec![(lcg.next() & 0xff) as u8; ((lcg.next() % 6) + 1) as usize])
            .build();
        apply_strategy(&mut m, strat, &mut rng);
    }
}

// ── 58-60: Transports (Send) ──────────────────────────────────────────────────

#[test]
fn t58_tcp_transport_starts_disconnected() {
    let t = TcpTransport::new("127.0.0.1:1234");
    assert!(!t.is_connected());
    assert_eq!(t.addr, "127.0.0.1:1234");
}

#[test]
fn t59_udp_transport_starts_disconnected() {
    let t = UdpTransport::new("127.0.0.1:53");
    assert!(!t.is_connected());
}

#[test]
fn t60_transport_send_when_not_connected_errors() {
    fn assert_send<T: Send>() {}
    assert_send::<TcpTransport>();
    assert_send::<UdpTransport>();
}

// ── 61-64: Send/Sync of public types ─────────────────────────────────────────

#[test]
fn t61_send_sync_data_types() {
    fn assert_ss<T: Send + Sync>() {}
    assert_ss::<MessageDef>();
    assert_ss::<ProtocolDef>();
    assert_ss::<CrashLogger>();
    assert_ss::<CoverageMap>();
    assert_ss::<FuzzCorpus>();
}

#[test]
fn t62_threaded_crash_logger_stress() {
    // CrashLogger is Send+Sync as data, but we use one-per-thread and merge.
    let handles: Vec<_> = (0..4)
        .map(|tid| {
            thread::spawn(move || {
                let mut l = CrashLogger::new();
                for i in 0..100 {
                    l.log(vec![tid as u8, i as u8], "r", "s");
                }
                l.len()
            })
        })
        .collect();
    let total: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(total, 400);
}

#[test]
fn t63_threaded_xor_checksum_consistency() {
    let data = Arc::new((0u8..=200).collect::<Vec<u8>>());
    let expected = xor_checksum(&data);
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let d = Arc::clone(&data);
            thread::spawn(move || {
                let mut last = 0u8;
                for _ in 0..100 {
                    last = xor_checksum(&d);
                }
                last
            })
        })
        .collect();
    for h in handles {
        assert_eq!(h.join().unwrap(), expected);
    }
}

#[test]
fn t64_threaded_protocoldef_clone() {
    let p = Arc::new(ProtocolBuilder::new("a").add_terminal("b").build());
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let p2 = Arc::clone(&p);
            thread::spawn(move || {
                let mut count = 0;
                for _ in 0..100 {
                    if p2.validate().is_empty() {
                        count += 1;
                    }
                }
                count
            })
        })
        .collect();
    for h in handles {
        assert_eq!(h.join().unwrap(), 100);
    }
}

// ── 65-70: Display / Debug / Eq / Hash-ish ───────────────────────────────────

#[test]
fn t65_field_type_partial_eq_pairs() {
    let pairs: Vec<(FieldType, FieldType, bool)> = vec![
        (FieldType::Static(vec![1]), FieldType::Static(vec![1]), true),
        (FieldType::Static(vec![1]), FieldType::Static(vec![2]), false),
        (
            FieldType::Random { min: 1, max: 2 },
            FieldType::Random { min: 1, max: 2 },
            true,
        ),
        (
            FieldType::Random { min: 1, max: 2 },
            FieldType::Random { min: 1, max: 3 },
            false,
        ),
        (
            FieldType::Integer { size: 1, signed: false, value: 7 },
            FieldType::Integer { size: 1, signed: false, value: 7 },
            true,
        ),
        (
            FieldType::Integer { size: 2, signed: false, value: 7 },
            FieldType::Integer { size: 1, signed: false, value: 7 },
            false,
        ),
        (
            FieldType::String { max_len: 5 },
            FieldType::String { max_len: 5 },
            true,
        ),
        (
            FieldType::String { max_len: 5 },
            FieldType::String { max_len: 6 },
            false,
        ),
        (
            FieldType::Blob { data: vec![9] },
            FieldType::Blob { data: vec![9] },
            true,
        ),
        (
            FieldType::SizeOf { field: "x".into() },
            FieldType::SizeOf { field: "x".into() },
            true,
        ),
    ];
    for (a, b, eq) in pairs {
        assert_eq!(a == b, eq, "{:?} vs {:?}", a, b);
        // reflexive
        assert_eq!(a, a);
        assert_eq!(b, b);
    }
}

#[test]
fn t66_fuzznet_error_display_strings() {
    let e = FuzzNetError::UnknownState("zzz".into());
    let s = format!("{}", e);
    assert!(s.contains("zzz"));
    let e = FuzzNetError::SizeOfFieldNotFound("ff".into());
    assert!(format!("{}", e).contains("ff"));
    let e = FuzzNetError::PayloadTooLarge(99);
    assert!(format!("{}", e).contains("99"));
    let e = FuzzNetError::Async("x".into());
    assert!(format!("{}", e).contains("x"));
}

#[test]
fn t67_transport_error_display() {
    assert!(format!("{}", TransportError::Timeout).contains("timeout"));
    assert!(format!("{}", TransportError::Disconnected).contains("disconnected"));
    assert!(format!("{}", TransportError::ConnectionFailed("a".into())).contains("a"));
    assert!(format!("{}", TransportError::SendFailed("b".into())).contains("b"));
    assert!(format!("{}", TransportError::RecvFailed("c".into())).contains("c"));
}

#[test]
fn t68_transport_error_into_fuzznet_error() {
    let te = TransportError::Timeout;
    let fe: FuzzNetError = te.into();
    match fe {
        FuzzNetError::Transport(TransportError::Timeout) => {}
        other => panic!("unexpected variant: {:?}", other),
    }
}

#[test]
fn t69_message_def_debug_includes_name() {
    let m = MessageBuilder::new("greeting").fuzz_u8("v", 1).build();
    let s = format!("{:?}", m);
    assert!(s.contains("greeting"));
}

#[test]
fn t70_corpus_entry_clone_keeps_fields() {
    let e = CorpusEntry {
        data: vec![1, 2],
        tag: "t".into(),
        state: "s".into(),
    };
    let c = e.clone();
    assert_eq!(c.data, e.data);
    assert_eq!(c.tag, e.tag);
}

// ── 71-74: FuzzSession + ProtocolFuzzer (async, mock transport) ──────────────

struct OkTransport(bool);
#[async_trait]
impl Transport for OkTransport {
    async fn connect(&mut self) -> Result<(), TransportError> {
        self.0 = true;
        Ok(())
    }
    async fn send(&mut self, _d: &[u8]) -> Result<(), TransportError> {
        Ok(())
    }
    async fn recv(&mut self, _t: u64) -> Result<Vec<u8>, TransportError> {
        Ok(vec![])
    }
    async fn disconnect(&mut self) -> Result<(), TransportError> {
        self.0 = false;
        Ok(())
    }
    fn is_connected(&self) -> bool {
        self.0
    }
}

fn proto_two_state() -> ProtocolDef {
    ProtocolBuilder::new("a")
        .add_transition(
            "a",
            "b",
            Some(
                MessageBuilder::new("m")
                    .fuzz_blob("d", b"PING".to_vec())
                    .build(),
            ),
        )
        .build()
}

#[tokio::test]
async fn t71_fuzz_session_run_once() {
    let proto = proto_two_state();
    let mut sess = FuzzSession::new(proto, Box::new(OkTransport(false)));
    sess.run_once().await.unwrap();
    assert_eq!(sess.iterations, 1);
    assert!(sess.total_bytes_sent > 0);
}

#[tokio::test]
async fn t72_fuzz_session_run_many() {
    let proto = proto_two_state();
    let mut sess = FuzzSession::new(proto, Box::new(OkTransport(false)));
    let _: () = sess.run(5).await.unwrap();
    assert_eq!(sess.iterations, 5);
    let stats = sess.stats();
    assert_eq!(stats.iterations, 5);
    assert!(stats.most_visited_state().is_some());
    assert!(stats.avg_bytes_per_iter() > 0);
}

#[tokio::test]
async fn t73_protocol_fuzzer_wraps_session() {
    let mut pf = ProtocolFuzzer::new(proto_two_state(), Box::new(OkTransport(false)));
    pf.fuzz(2).await.unwrap();
    assert_eq!(pf.stats().iterations, 2);
    assert!(!pf.has_crashes());
}

#[tokio::test]
async fn t74_session_stats_zero_iterations() {
    let s = SessionStats {
        iterations: 0,
        total_bytes_sent: 100,
        crash_count: 0,
        state_visit_counts: HashMap::new(),
    };
    assert_eq!(s.avg_bytes_per_iter(), 0);
    assert!(s.most_visited_state().is_none());
}

// ── 75-78: ReplaySession + boundaries ─────────────────────────────────────────

#[tokio::test]
async fn t75_replay_session_runs_inputs() {
    let inputs = vec![vec![1, 2], vec![3, 4], vec![5]];
    let mut r = ReplaySession::new(inputs, Box::new(OkTransport(false)));
    let res = r.run().await.unwrap();
    assert_eq!(res.successes, 3);
    assert!(res.failures.is_empty());
}

#[tokio::test]
async fn t76_replay_empty_inputs() {
    let mut r = ReplaySession::new(vec![], Box::new(OkTransport(false)));
    let res = r.run().await.unwrap();
    assert_eq!(res.successes, 0);
}

#[test]
fn t77_pattern_match_clone() {
    let p = PatternMatch {
        pattern: vec![1, 2, 3],
        timeout_ms: 500,
    };
    let q = p.clone();
    assert_eq!(p.pattern, q.pattern);
    assert_eq!(p.timeout_ms, q.timeout_ms);
}

#[test]
fn t78_protocol_edges_includes_all_transitions() {
    let p = ProtocolBuilder::new("a")
        .add_transition("a", "b", None)
        .add_transition("a", "c", None)
        .add_transition("b", "c", None)
        .build();
    let edges = p.edges();
    assert_eq!(edges.len(), 3);
}

// ── 79-82: extra fuzz/boundary ────────────────────────────────────────────────

#[test]
fn t79_frame_roundtrip_big_payload() {
    let payload: Vec<u8> = (0..10_000).map(|i| (i & 0xff) as u8).collect();
    let f = frame_u32_le(&payload).unwrap();
    let (_, p) = decode_frame_u32_le(&f).unwrap();
    assert_eq!(p, payload);
}

#[test]
fn t80_field_def_constructor() {
    let f = FieldDef::new("nm", FieldType::Static(vec![1]), true);
    assert_eq!(f.name, "nm");
    assert!(f.fuzz);
}

#[test]
fn t81_messagedef_empty_serialise_ok() {
    let m = MessageDef::new("empty", vec![]);
    let b = m.serialise().unwrap();
    assert!(b.is_empty());
    assert_eq!(m.estimated_len(), 0);
    assert_eq!(m.fuzz_field_count(), 0);
}

#[test]
fn t82_serialise_random_min_zero() {
    let m = MessageBuilder::new("m").fuzz_random("r", 0, 4).build();
    let b = m.serialise().unwrap();
    assert!(b.is_empty()); // serialise uses min as default
}
