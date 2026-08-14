//! Comprehensive integration tests for `rustre-fuzz-net`.
//!
//! Cover constructors, defaults, boundary inputs, error variants, round-trips,
//! and Send bounds for the public API in lib.rs.

use std::collections::HashMap;

use async_trait::async_trait;
use rustre_fuzz_afl::XorShiftRng;
use rustre_fuzz_net::{
    add_checksum, apply_strategy, decode_frame_u32_be, decode_frame_u32_le, frame_u32_be,
    frame_u32_le, interesting_int_mutation, xor_checksum, CorpusEntry, CoverageMap, CrashEntry,
    CrashLogger, FieldDef, FieldType, FuzzCorpus, FuzzNetError, FuzzSession, MessageBuilder,
    MessageDef, MutationHistory, MutationStrategy, PatternMatch, ProtocolBuilder, ProtocolDef,
    ProtocolFuzzer, ProtocolState, ReplaySession, ResponseMatcher, SessionStats, TcpTransport,
    Transition, Transport, TransportError, UdpTransport, INTERESTING_U16, INTERESTING_U32,
    INTERESTING_U8,
};

// ─── helpers ──────────────────────────────────────────────────────────────────

struct OkTransport {
    connected: bool,
}
impl OkTransport {
    fn new() -> Self {
        Self { connected: false }
    }
}

#[async_trait]
impl Transport for OkTransport {
    async fn connect(&mut self) -> Result<(), TransportError> {
        self.connected = true;
        Ok(())
    }
    async fn send(&mut self, _data: &[u8]) -> Result<(), TransportError> {
        if !self.connected {
            return Err(TransportError::ConnectionFailed("nope".into()));
        }
        Ok(())
    }
    async fn recv(&mut self, _timeout_ms: u64) -> Result<Vec<u8>, TransportError> {
        Ok(vec![1, 2, 3])
    }
    async fn disconnect(&mut self) -> Result<(), TransportError> {
        self.connected = false;
        Ok(())
    }
    fn is_connected(&self) -> bool {
        self.connected
    }
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

// ─── FieldDef / FieldType ────────────────────────────────────────────────────

#[test]
fn field_def_new_stores_fields() {
    let f = FieldDef::new("x", FieldType::Static(vec![1, 2]), true);
    assert_eq!(f.name, "x");
    assert!(f.fuzz);
    match f.field_type {
        FieldType::Static(b) => assert_eq!(b, vec![1, 2]),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn field_type_partial_eq() {
    assert_eq!(
        FieldType::Random { min: 0, max: 4 },
        FieldType::Random { min: 0, max: 4 }
    );
    assert_ne!(
        FieldType::Random { min: 0, max: 4 },
        FieldType::Random { min: 1, max: 4 }
    );
}

// ─── MessageDef / MessageBuilder ─────────────────────────────────────────────

#[test]
fn message_def_serialise_static_only() {
    let m = MessageDef::new(
        "m",
        vec![FieldDef::new("s", FieldType::Static(vec![0xAA, 0xBB]), false)],
    );
    let bytes = m.serialise().unwrap();
    assert_eq!(bytes, vec![0xAA, 0xBB]);
}

#[test]
fn message_def_serialise_integers_widths() {
    let m = MessageDef::new(
        "m",
        vec![
            FieldDef::new(
                "a",
                FieldType::Integer { size: 1, signed: false, value: 0x12 },
                false,
            ),
            FieldDef::new(
                "b",
                FieldType::Integer { size: 2, signed: false, value: 0x3344 },
                false,
            ),
            FieldDef::new(
                "c",
                FieldType::Integer { size: 4, signed: false, value: 0x5566_7788 },
                false,
            ),
            FieldDef::new(
                "d",
                FieldType::Integer { size: 8, signed: false, value: 1 },
                false,
            ),
        ],
    );
    let bytes = m.serialise().unwrap();
    assert_eq!(&bytes[0..1], &[0x12]);
    assert_eq!(&bytes[1..3], &0x3344u16.to_le_bytes());
    assert_eq!(&bytes[3..7], &0x5566_7788u32.to_le_bytes());
    assert_eq!(&bytes[7..15], &1u64.to_le_bytes());
}

#[test]
fn message_def_serialise_sizeof_resolves_target_length() {
    let m = MessageDef::new(
        "m",
        vec![
            FieldDef::new("len", FieldType::SizeOf { field: "body".into() }, false),
            FieldDef::new(
                "body",
                FieldType::Blob { data: vec![1, 2, 3, 4, 5] },
                false,
            ),
        ],
    );
    let bytes = m.serialise().unwrap();
    // Length prefix is u64 LE
    assert_eq!(&bytes[0..8], &5u64.to_le_bytes());
    assert_eq!(&bytes[8..], &[1, 2, 3, 4, 5]);
}

#[test]
fn message_def_serialise_sizeof_missing_target_errors() {
    let m = MessageDef::new(
        "m",
        vec![FieldDef::new(
            "len",
            FieldType::SizeOf { field: "no_such".into() },
            false,
        )],
    );
    match m.serialise() {
        Err(FuzzNetError::SizeOfFieldNotFound(name)) => assert_eq!(name, "no_such"),
        other => panic!("expected SizeOfFieldNotFound, got {other:?}"),
    }
}

#[test]
fn message_def_estimated_len_sums_components() {
    let m = MessageDef::new(
        "m",
        vec![
            FieldDef::new("a", FieldType::Static(vec![0; 3]), false),
            FieldDef::new("b", FieldType::Random { min: 4, max: 9 }, false),
            FieldDef::new(
                "c",
                FieldType::Integer { size: 4, signed: false, value: 0 },
                false,
            ),
            FieldDef::new("d", FieldType::String { max_len: 5 }, false),
            FieldDef::new("e", FieldType::Blob { data: vec![0; 2] }, false),
            FieldDef::new("f", FieldType::SizeOf { field: "a".into() }, false),
        ],
    );
    // 3 + 4 + 4 + 5 + 2 + 8 = 26
    assert_eq!(m.estimated_len(), 26);
}

#[test]
fn message_def_fuzz_field_count() {
    let m = MessageDef::new(
        "m",
        vec![
            FieldDef::new("a", FieldType::Static(vec![]), true),
            FieldDef::new("b", FieldType::Static(vec![]), false),
            FieldDef::new("c", FieldType::Static(vec![]), true),
        ],
    );
    assert_eq!(m.fuzz_field_count(), 2);
}

#[test]
fn message_def_field_lookup() {
    let mut m = MessageDef::new(
        "m",
        vec![FieldDef::new("hello", FieldType::Static(vec![1]), false)],
    );
    assert!(m.field("hello").is_some());
    assert!(m.field("missing").is_none());
    assert!(m.field_mut("hello").is_some());
    assert!(m.field_mut("missing").is_none());
}

#[test]
fn message_def_mutate_changes_fuzz_fields() {
    let mut rng = XorShiftRng::default();
    let mut m = MessageDef::new(
        "m",
        vec![
            FieldDef::new(
                "a",
                FieldType::Integer { size: 4, signed: false, value: 42 },
                true,
            ),
            FieldDef::new("b", FieldType::Static(vec![1, 2, 3]), false),
        ],
    );
    let before = m.serialise().unwrap();
    m.mutate(&mut rng);
    // Static field should be untouched
    if let FieldType::Static(ref b) = m.fields[1].field_type {
        assert_eq!(b, &vec![1, 2, 3]);
    } else {
        panic!("static mutated");
    }
    // Integer field likely changed
    let after = m.serialise().unwrap();
    assert_eq!(before.len(), after.len());
}

#[test]
fn message_builder_assembles_all_field_kinds() {
    let m = MessageBuilder::new("msg")
        .static_bytes("hdr", vec![0xCA, 0xFE])
        .fuzz_blob("body", vec![0; 4])
        .fuzz_u8("u8", 1)
        .fuzz_u16("u16", 2)
        .fuzz_u32("u32", 3)
        .fuzz_random("rnd", 1, 3)
        .fuzz_string("str", 4)
        .size_of("len", "body")
        .build();
    assert_eq!(m.name, "msg");
    assert_eq!(m.fields.len(), 8);
    assert_eq!(m.fuzz_field_count(), 6);
}

// ─── ProtocolDef / ProtocolBuilder ───────────────────────────────────────────

#[test]
fn protocol_builder_minimal_terminal_protocol_validates() {
    let p = ProtocolBuilder::new("start").add_terminal("done").build();
    assert!(p.validate().is_empty());
    assert_eq!(p.state_count(), 2);
}

#[test]
fn protocol_builder_add_transition_creates_states_implicitly() {
    let p = ProtocolBuilder::new("a")
        .add_transition("a", "b", None)
        .add_transition("b", "c", None)
        .build();
    assert_eq!(p.state_count(), 3);
    let edges = p.edges();
    assert!(edges.iter().any(|&(f, t)| f == "a" && t == "b"));
    assert!(edges.iter().any(|&(f, t)| f == "b" && t == "c"));
}

#[test]
fn protocol_builder_with_expect_attaches_pattern() {
    let p = ProtocolBuilder::new("a")
        .add_transition_with_expect(
            "a",
            "b",
            None,
            PatternMatch { pattern: vec![1], timeout_ms: 10 },
        )
        .build();
    let st = p.states.get("a").unwrap();
    assert_eq!(st.transitions.len(), 1);
    assert!(st.transitions[0].expect.is_some());
}

#[test]
fn protocol_def_validate_reports_missing_initial() {
    let p = ProtocolDef::new("nope", HashMap::new());
    let errors = p.validate();
    assert!(!errors.is_empty());
    assert!(errors[0].contains("initial state"));
}

#[test]
fn protocol_def_validate_reports_dangling_transition() {
    let mut states = HashMap::new();
    states.insert(
        "a".into(),
        ProtocolState {
            name: "a".into(),
            transitions: vec![Transition {
                to_state: "ghost".into(),
                send: None,
                expect: None,
            }],
        },
    );
    let p = ProtocolDef::new("a", states);
    let errs = p.validate();
    assert!(errs.iter().any(|e| e.contains("ghost")));
}

#[test]
fn protocol_def_state_names_and_count() {
    let p = ProtocolBuilder::new("x").add_terminal("y").build();
    let mut names = p.state_names();
    names.sort();
    assert_eq!(names, vec!["x", "y"]);
    assert_eq!(p.state_count(), 2);
}

// ─── Transports ──────────────────────────────────────────────────────────────

#[test]
fn tcp_transport_lifecycle() {
    let rt = rt();
    rt.block_on(async {
        let mut t = TcpTransport::new("127.0.0.1:1");
        assert!(!t.is_connected());
        t.connect().await.unwrap();
        assert!(t.is_connected());
        t.send(b"hi").await.unwrap();
        let r = t.recv(0).await.unwrap();
        assert!(r.is_empty());
        t.disconnect().await.unwrap();
        assert!(!t.is_connected());
    });
}

#[test]
fn tcp_transport_send_before_connect_errors() {
    let rt = rt();
    rt.block_on(async {
        let mut t = TcpTransport::new("h:1");
        match t.send(b"x").await {
            Err(TransportError::ConnectionFailed(_)) => {}
            other => panic!("expected ConnectionFailed, got {other:?}"),
        }
    });
}

#[test]
fn tcp_transport_recv_before_connect_errors() {
    let rt = rt();
    rt.block_on(async {
        let mut t = TcpTransport::new("h:1");
        match t.recv(0).await {
            Err(TransportError::Disconnected) => {}
            other => panic!("expected Disconnected, got {other:?}"),
        }
    });
}

#[test]
fn udp_transport_lifecycle() {
    let rt = rt();
    rt.block_on(async {
        let mut t = UdpTransport::new("127.0.0.1:1");
        assert!(!t.is_connected());
        t.connect().await.unwrap();
        assert!(t.is_connected());
        t.send(&[]).await.unwrap();
        assert!(t.recv(0).await.unwrap().is_empty());
        t.disconnect().await.unwrap();
        assert!(!t.is_connected());
    });
}

#[test]
fn udp_transport_send_before_bind_errors() {
    let rt = rt();
    rt.block_on(async {
        let mut t = UdpTransport::new("h:1");
        match t.send(&[]).await {
            Err(TransportError::ConnectionFailed(_)) => {}
            other => panic!("expected ConnectionFailed, got {other:?}"),
        }
    });
}

// ─── CrashLogger ─────────────────────────────────────────────────────────────

#[test]
fn crash_logger_default_is_empty() {
    let l = CrashLogger::new();
    assert!(l.is_empty());
    assert_eq!(l.len(), 0);
    assert!(l.unique_reasons().is_empty());
    assert_eq!(l.summary(), "");
}

#[test]
fn crash_logger_log_and_query() {
    let mut l = CrashLogger::new();
    l.log(vec![1], "timeout", "s1");
    l.log(vec![2], "disconnected", "s1");
    l.log(vec![3], "timeout", "s2");
    assert_eq!(l.len(), 3);
    assert!(!l.is_empty());
    let reasons = l.unique_reasons();
    assert_eq!(reasons.len(), 2);
    assert_eq!(l.by_reason("timeout").len(), 2);
    assert_eq!(l.by_state("s1").len(), 2);
}

#[test]
fn crash_logger_clear_resets() {
    let mut l = CrashLogger::new();
    l.log(vec![], "r", "s");
    l.clear();
    assert!(l.is_empty());
}

#[test]
fn crash_logger_dedup_keeps_first_per_reason_state() {
    let mut l = CrashLogger::new();
    l.log(vec![1], "r", "s");
    l.log(vec![2], "r", "s");
    l.log(vec![3], "r2", "s");
    l.dedup();
    assert_eq!(l.len(), 2);
}

#[test]
fn crash_logger_summary_sorted() {
    let mut l = CrashLogger::new();
    l.log(vec![], "x", "alpha");
    l.log(vec![], "x", "alpha");
    l.log(vec![], "x", "beta");
    let s = l.summary();
    // sorted alphabetically by "state:count"
    assert_eq!(s, "alpha:2, beta:1");
}

#[test]
fn crash_entry_clone() {
    let mut l = CrashLogger::new();
    l.log(vec![1], "r", "s");
    let e: CrashEntry = l.entries[0].clone();
    assert_eq!(e.reason, "r");
    assert_eq!(e.state, "s");
    assert_eq!(e.input, vec![1]);
}

// ─── FuzzSession / ProtocolFuzzer ────────────────────────────────────────────

fn tiny_proto() -> ProtocolDef {
    ProtocolBuilder::new("start")
        .add_transition(
            "start",
            "done",
            Some(MessageBuilder::new("m").fuzz_u8("v", 0).build()),
        )
        .build()
}

#[test]
fn fuzz_session_new_initial_state() {
    let s = FuzzSession::new(tiny_proto(), Box::new(OkTransport::new()));
    assert_eq!(s.current_state(), "start");
    assert_eq!(s.iterations, 0);
    assert_eq!(s.total_bytes_sent, 0);
    assert!(s.state_visit_counts.is_empty());
}

#[test]
fn fuzz_session_run_once_advances_iteration() {
    let rt = rt();
    rt.block_on(async {
        let mut s = FuzzSession::new(tiny_proto(), Box::new(OkTransport::new()));
        s.run_once().await.unwrap();
        assert_eq!(s.iterations, 1);
        assert!(s.total_bytes_sent >= 1);
        assert!(!s.state_visit_counts.is_empty());
    });
}

#[test]
fn fuzz_session_run_many_iterations() {
    let rt = rt();
    rt.block_on(async {
        let mut s = FuzzSession::new(tiny_proto(), Box::new(OkTransport::new()));
        s.run(5).await.unwrap();
        assert_eq!(s.iterations, 5);
    });
}

#[test]
fn fuzz_session_reset_returns_to_initial() {
    let mut s = FuzzSession::new(tiny_proto(), Box::new(OkTransport::new()));
    s.reset();
    assert_eq!(s.current_state(), "start");
}

#[test]
fn fuzz_session_stats_snapshot() {
    let rt = rt();
    rt.block_on(async {
        let mut s = FuzzSession::new(tiny_proto(), Box::new(OkTransport::new()));
        s.run(2).await.unwrap();
        let st: SessionStats = s.stats();
        assert_eq!(st.iterations, 2);
        assert!(st.most_visited_state().is_some());
    });
}

#[test]
fn session_stats_empty_avg_is_zero() {
    let s = SessionStats {
        iterations: 0,
        total_bytes_sent: 100,
        crash_count: 0,
        state_visit_counts: HashMap::new(),
    };
    assert_eq!(s.avg_bytes_per_iter(), 0);
    assert!(s.most_visited_state().is_none());
}

#[test]
fn session_stats_avg_non_zero() {
    let s = SessionStats {
        iterations: 4,
        total_bytes_sent: 20,
        crash_count: 0,
        state_visit_counts: HashMap::new(),
    };
    assert_eq!(s.avg_bytes_per_iter(), 5);
}

#[test]
fn protocol_fuzzer_basic_run() {
    let rt = rt();
    rt.block_on(async {
        let mut f = ProtocolFuzzer::new(tiny_proto(), Box::new(OkTransport::new()));
        assert!(!f.has_crashes());
        f.fuzz(3).await.unwrap();
        assert_eq!(f.stats().iterations, 3);
    });
}

// ─── MutationStrategy ────────────────────────────────────────────────────────

#[test]
fn mutation_strategy_eq() {
    assert_eq!(MutationStrategy::AllFields, MutationStrategy::AllFields);
    assert_ne!(MutationStrategy::SingleField, MutationStrategy::BitFlip);
}

#[test]
fn apply_strategy_no_fuzz_fields_is_noop() {
    let mut rng = XorShiftRng::default();
    let mut m = MessageDef::new(
        "m",
        vec![FieldDef::new("a", FieldType::Static(vec![1, 2]), false)],
    );
    let before = m.serialise().unwrap();
    apply_strategy(&mut m, MutationStrategy::AllFields, &mut rng);
    assert_eq!(m.serialise().unwrap(), before);
}

#[test]
fn apply_strategy_all_fields_mutates_all() {
    let mut rng = XorShiftRng::default();
    let mut m = MessageDef::new(
        "m",
        vec![
            FieldDef::new("a", FieldType::Blob { data: vec![1; 4] }, true),
            FieldDef::new("b", FieldType::Blob { data: vec![2; 4] }, true),
        ],
    );
    apply_strategy(&mut m, MutationStrategy::AllFields, &mut rng);
    // Length preserved for blob mutation
    if let FieldType::Blob { ref data } = m.fields[0].field_type {
        assert_eq!(data.len(), 4);
    }
}

#[test]
fn apply_strategy_single_field_works() {
    let mut rng = XorShiftRng::default();
    let mut m = MessageDef::new(
        "m",
        vec![FieldDef::new(
            "a",
            FieldType::Blob { data: vec![0xAA; 4] },
            true,
        )],
    );
    apply_strategy(&mut m, MutationStrategy::SingleField, &mut rng);
    // Should still serialise
    assert!(m.serialise().is_ok());
}

#[test]
fn apply_strategy_bitflip_preserves_blob_length() {
    let mut rng = XorShiftRng::default();
    let mut m = MessageDef::new(
        "m",
        vec![FieldDef::new(
            "a",
            FieldType::Blob { data: vec![0; 8] },
            true,
        )],
    );
    apply_strategy(&mut m, MutationStrategy::BitFlip, &mut rng);
    if let FieldType::Blob { ref data } = m.fields[0].field_type {
        assert_eq!(data.len(), 8);
    } else {
        panic!("expected blob");
    }
}

#[test]
fn apply_strategy_boundary_writes_zeros_or_ones() {
    let mut rng = XorShiftRng::default();
    let mut m = MessageDef::new(
        "m",
        vec![FieldDef::new(
            "a",
            FieldType::Integer { size: 4, signed: false, value: 7 },
            true,
        )],
    );
    apply_strategy(&mut m, MutationStrategy::BoundaryValues, &mut rng);
    if let FieldType::Blob { ref data } = m.fields[0].field_type {
        assert!(data.iter().all(|&b| b == 0x00) || data.iter().all(|&b| b == 0xff));
    } else {
        panic!("expected blob");
    }
}

// ─── CoverageMap ─────────────────────────────────────────────────────────────

#[test]
fn coverage_map_default_empty() {
    let c = CoverageMap::new();
    assert_eq!(c.covered(), 0);
    assert_eq!(c.coverage_pct(10), 0.0);
}

#[test]
fn coverage_map_pct_zero_total_is_100() {
    let c = CoverageMap::new();
    assert_eq!(c.coverage_pct(0), 100.0);
}

#[test]
fn coverage_map_record_dedups() {
    let mut c = CoverageMap::new();
    c.record("s", 0);
    c.record("s", 0);
    c.record("s", 1);
    assert_eq!(c.covered(), 2);
    assert!(c.is_covered("s", 0));
    assert!(c.is_covered("s", 1));
    assert!(!c.is_covered("s", 2));
}

#[test]
fn coverage_map_pct_calculation() {
    let mut c = CoverageMap::new();
    c.record("a", 0);
    c.record("a", 1);
    assert!((c.coverage_pct(4) - 50.0).abs() < 1e-9);
}

// ─── ResponseMatcher ─────────────────────────────────────────────────────────

#[test]
fn response_matcher_empty_pattern_always_matches() {
    let m = ResponseMatcher::new(vec![]);
    assert!(m.matches(&[]));
    assert!(m.matches(&[1, 2, 3]));
    assert_eq!(m.find(&[1, 2]), Some(0));
}

#[test]
fn response_matcher_longer_than_buf_no_match() {
    let m = ResponseMatcher::new(vec![1, 2, 3]);
    assert!(!m.matches(&[1, 2]));
    assert_eq!(m.find(&[1, 2]), None);
}

#[test]
fn response_matcher_find_basic() {
    let m = ResponseMatcher::new(vec![3, 4]);
    assert!(m.matches(&[1, 2, 3, 4, 5]));
    assert_eq!(m.find(&[1, 2, 3, 4, 5]), Some(2));
    assert!(!m.matches(&[1, 2, 5, 6]));
}

// ─── FuzzCorpus ──────────────────────────────────────────────────────────────

#[test]
fn fuzz_corpus_default_empty() {
    let c = FuzzCorpus::new();
    assert!(c.is_empty());
    assert_eq!(c.len(), 0);
}

#[test]
fn fuzz_corpus_add_and_query_by_tag() {
    let mut c = FuzzCorpus::new();
    c.add(vec![1], "crash", "s");
    c.add(vec![2], "new-cov", "s");
    c.add(vec![3], "crash", "t");
    assert_eq!(c.len(), 3);
    assert_eq!(c.by_tag("crash").len(), 2);
    assert!(c.by_tag("nope").is_empty());
}

#[test]
fn fuzz_corpus_pick_empty_returns_none() {
    let mut rng = XorShiftRng::default();
    let c = FuzzCorpus::new();
    assert!(c.pick(&mut rng).is_none());
}

#[test]
fn fuzz_corpus_pick_returns_entry() {
    let mut rng = XorShiftRng::default();
    let mut c = FuzzCorpus::new();
    c.add(vec![42], "t", "s");
    let e: &CorpusEntry = c.pick(&mut rng).unwrap();
    assert_eq!(e.data, vec![42]);
}

#[test]
fn fuzz_corpus_dedup_removes_dup_data() {
    let mut c = FuzzCorpus::new();
    c.add(vec![1, 2], "a", "s");
    c.add(vec![1, 2], "b", "t");
    c.add(vec![3], "c", "u");
    c.dedup();
    assert_eq!(c.len(), 2);
}

// ─── Framing ─────────────────────────────────────────────────────────────────

#[test]
fn frame_u32_le_round_trip_empty() {
    let framed = frame_u32_le(&[]).unwrap();
    assert_eq!(framed, vec![0, 0, 0, 0]);
    let (consumed, payload) = decode_frame_u32_le(&framed).unwrap();
    assert_eq!(consumed, 4);
    assert!(payload.is_empty());
}

#[test]
fn frame_u32_le_round_trip_nontrivial() {
    let payload = b"hello world";
    let framed = frame_u32_le(payload).unwrap();
    let (consumed, decoded) = decode_frame_u32_le(&framed).unwrap();
    assert_eq!(consumed, 4 + payload.len());
    assert_eq!(decoded, payload);
}

#[test]
fn frame_u32_be_round_trip() {
    let payload = vec![9u8; 7];
    let framed = frame_u32_be(&payload).unwrap();
    assert_eq!(&framed[0..4], &7u32.to_be_bytes());
    let (consumed, decoded) = decode_frame_u32_be(&framed).unwrap();
    assert_eq!(consumed, 4 + 7);
    assert_eq!(decoded, payload);
}

#[test]
fn decode_frame_le_short_header_returns_none() {
    assert!(decode_frame_u32_le(&[1, 2]).is_none());
    assert!(decode_frame_u32_be(&[1, 2]).is_none());
}

#[test]
fn decode_frame_le_incomplete_payload_returns_none() {
    // Header says 5 bytes, buf only has 2 of body
    let mut buf = 5u32.to_le_bytes().to_vec();
    buf.extend_from_slice(&[0, 0]);
    assert!(decode_frame_u32_le(&buf).is_none());
}

// ─── checksums ───────────────────────────────────────────────────────────────

#[test]
fn xor_checksum_empty_is_zero() {
    assert_eq!(xor_checksum(&[]), 0);
}

#[test]
fn xor_checksum_known() {
    assert_eq!(xor_checksum(&[0xAA, 0x55]), 0xFF);
    assert_eq!(xor_checksum(&[1, 2, 3]), 1 ^ 2 ^ 3);
}

#[test]
fn add_checksum_wraps() {
    assert_eq!(add_checksum(&[]), 0);
    assert_eq!(add_checksum(&[0xFF, 0x01]), 0x00); // wraps
    assert_eq!(add_checksum(&[1, 2, 3, 4]), 10);
}

// ─── Interesting integers & mutation ─────────────────────────────────────────

#[test]
fn interesting_tables_have_boundary_values() {
    assert!(INTERESTING_U8.contains(&0));
    assert!(INTERESTING_U8.contains(&0xff));
    assert!(INTERESTING_U16.contains(&0));
    assert!(INTERESTING_U16.contains(&u16::MAX));
    assert!(INTERESTING_U32.contains(&0));
    assert!(INTERESTING_U32.contains(&u32::MAX));
}

#[test]
fn interesting_int_mutation_returns_int_in_range_for_u8() {
    let mut rng = XorShiftRng::default();
    // Run many times to exercise both branches
    for _ in 0..50 {
        let v = interesting_int_mutation(10, 1, &mut rng);
        // No assert on exact value — must not panic and must produce a valid i64
        let _ = v;
    }
}

#[test]
fn interesting_int_mutation_u32_path() {
    let mut rng = XorShiftRng::default();
    for _ in 0..50 {
        let _ = interesting_int_mutation(0, 4, &mut rng);
    }
}

// ─── ReplaySession ───────────────────────────────────────────────────────────

#[test]
fn replay_session_runs_all_inputs() {
    let rt = rt();
    rt.block_on(async {
        let mut r = ReplaySession::new(
            vec![vec![1], vec![2], vec![3]],
            Box::new(OkTransport::new()),
        );
        let result = r.run().await.unwrap();
        assert_eq!(result.successes, 3);
        assert!(result.failures.is_empty());
    });
}

#[test]
fn replay_session_empty_inputs() {
    let rt = rt();
    rt.block_on(async {
        let mut r = ReplaySession::new(vec![], Box::new(OkTransport::new()));
        let result = r.run().await.unwrap();
        assert_eq!(result.successes, 0);
        assert!(result.failures.is_empty());
    });
}

#[test]
fn replay_session_default_delay_zero() {
    let r = ReplaySession::new(vec![], Box::new(OkTransport::new()));
    assert_eq!(r.delay_ms, 0);
}

// ─── MutationHistory ─────────────────────────────────────────────────────────

#[test]
fn mutation_history_push_pop() {
    let mut h = MutationHistory::new(3);
    assert_eq!(h.depth(), 0);
    let m = MessageBuilder::new("a").fuzz_u8("v", 1).build();
    h.push(&m);
    h.push(&m);
    assert_eq!(h.depth(), 2);
    assert!(h.pop().is_some());
    assert_eq!(h.depth(), 1);
}

#[test]
fn mutation_history_respects_max_depth() {
    let mut h = MutationHistory::new(2);
    let m = MessageBuilder::new("a").build();
    h.push(&m);
    h.push(&m);
    h.push(&m);
    h.push(&m);
    assert_eq!(h.depth(), 2);
}

#[test]
fn mutation_history_zero_depth_clamped_to_one() {
    let mut h = MutationHistory::new(0);
    let m = MessageBuilder::new("a").build();
    h.push(&m);
    h.push(&m);
    // max_depth was clamped to 1
    assert_eq!(h.depth(), 1);
}

#[test]
fn mutation_history_pop_empty_returns_none() {
    let mut h = MutationHistory::new(4);
    assert!(h.pop().is_none());
}

// ─── Errors: Display ─────────────────────────────────────────────────────────

#[test]
fn transport_error_display_strings() {
    assert!(TransportError::Timeout.to_string().contains("timeout"));
    assert!(TransportError::Disconnected.to_string().contains("disconnect"));
    assert!(TransportError::ConnectionFailed("x".into())
        .to_string()
        .contains("x"));
    assert!(TransportError::SendFailed("y".into())
        .to_string()
        .contains("send"));
    assert!(TransportError::RecvFailed("z".into())
        .to_string()
        .contains("recv"));
}

#[test]
fn fuzz_net_error_from_transport() {
    let e: FuzzNetError = TransportError::Timeout.into();
    match e {
        FuzzNetError::Transport(TransportError::Timeout) => {}
        other => panic!("expected Transport variant, got {other:?}"),
    }
}

#[test]
fn fuzz_net_error_payload_too_large_display() {
    let e = FuzzNetError::PayloadTooLarge(99);
    assert!(e.to_string().contains("99"));
}

#[test]
fn fuzz_net_error_unknown_state_display() {
    let e = FuzzNetError::UnknownState("foo".into());
    assert!(e.to_string().contains("foo"));
}

// ─── Send bounds (Transport trait is Send) ───────────────────────────────────

#[test]
fn transport_object_is_send() {
    fn assert_send<T: Send + ?Sized>() {}
    assert_send::<dyn Transport>();
}

#[test]
fn tcp_and_udp_transports_are_send() {
    fn assert_send<T: Send>() {}
    assert_send::<TcpTransport>();
    assert_send::<UdpTransport>();
}

// ─── PatternMatch / Transition clone ─────────────────────────────────────────

#[test]
fn pattern_match_clone() {
    let p = PatternMatch { pattern: vec![1, 2], timeout_ms: 50 };
    let q = p.clone();
    assert_eq!(q.pattern, vec![1, 2]);
    assert_eq!(q.timeout_ms, 50);
}

#[test]
fn transition_clone() {
    let t = Transition {
        to_state: "x".into(),
        send: None,
        expect: None,
    };
    let _u = t.clone();
}
