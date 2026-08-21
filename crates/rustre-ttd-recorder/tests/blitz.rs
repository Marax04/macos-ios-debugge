//! Blitz test suite for rustre-ttd-recorder.
//! Covers public API surface; Linux-only items are not exercised on Windows.

use rustre_ttd_recorder::*;

// ─── TtdPosition ─────────────────────────────────────────────────────────────

#[test]
fn ttd_position_new_and_start() {
    let p = TtdPosition::new(5, 7);
    assert_eq!(p.major, 5);
    assert_eq!(p.minor, 7);
    assert_eq!(TtdPosition::start(), TtdPosition::new(0, 0));
}

#[test]
fn ttd_position_ordering_and_is_before() {
    let a = TtdPosition::new(1, 0);
    let b = TtdPosition::new(1, 5);
    let c = TtdPosition::new(2, 0);
    assert!(a.is_before(&b));
    assert!(b.is_before(&c));
    assert!(!c.is_before(&a));
    assert!(!a.is_before(&a));
}

#[test]
fn ttd_position_earliest() {
    let a = TtdPosition::new(1, 0);
    let b = TtdPosition::new(2, 0);
    assert_eq!(TtdPosition::earliest(&a, &b), &a);
    assert_eq!(TtdPosition::earliest(&b, &a), &a);
    assert_eq!(TtdPosition::earliest(&a, &a), &a);
}

#[test]
fn ttd_position_display() {
    assert_eq!(format!("{}", TtdPosition::new(3, 4)), "3:4");
}

#[test]
fn ttd_position_to_trace_position_roundtrip() {
    let p = TtdPosition::new(123, 456);
    let tp = p.to_trace_position();
    // Best-effort: just ensure it doesn't panic and components survive via Display.
    let s = format!("{tp:?}");
    assert!(s.contains("123") || s.contains("456"));
}

#[test]
fn ttd_position_hash_eq_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let a = TtdPosition::new(1, 2);
    let b = TtdPosition::new(1, 2);
    let mut ha = DefaultHasher::new();
    let mut hb = DefaultHasher::new();
    a.hash(&mut ha);
    b.hash(&mut hb);
    assert_eq!(ha.finish(), hb.finish());
    assert_eq!(a, b);
}

// ─── CompressionLevel ────────────────────────────────────────────────────────

#[test]
fn compression_level_display_all() {
    assert_eq!(format!("{}", CompressionLevel::None), "none");
    assert_eq!(format!("{}", CompressionLevel::Fast), "fast");
    assert_eq!(format!("{}", CompressionLevel::Default), "default");
    assert_eq!(format!("{}", CompressionLevel::Best), "best");
}

#[test]
fn compression_level_default() {
    assert_eq!(CompressionLevel::default(), CompressionLevel::Default);
}

// ─── TtdTarget ───────────────────────────────────────────────────────────────

#[test]
fn ttd_target_display_variants() {
    assert_eq!(format!("{}", TtdTarget::ProcessId(42)), "pid:42");
    assert_eq!(
        format!("{}", TtdTarget::ProcessName("foo.exe".into())),
        "name:foo.exe"
    );
    assert_eq!(
        format!(
            "{}",
            TtdTarget::Executable {
                path: "C:/x".into(),
                args: vec!["a".into()]
            }
        ),
        "exe:C:/x"
    );
    assert_eq!(
        format!("{}", TtdTarget::Spawn { cmd: "ls -l".into() }),
        "spawn:ls -l"
    );
}

// ─── TtdRecordConfig ─────────────────────────────────────────────────────────

#[test]
fn config_for_pid_defaults() {
    let c = TtdRecordConfig::for_pid(99, "/tmp");
    assert!(matches!(c.target_process, TtdTarget::ProcessId(99)));
    assert_eq!(c.output_dir, "/tmp");
    assert!(c.validate().is_ok());
}

#[test]
fn config_validate_empty_output_dir() {
    let mut c = TtdRecordConfig::for_pid(1, "");
    let e = c.validate().unwrap_err();
    assert!(e.contains("output_dir"));
    c.output_dir = "/x".into();
    assert!(c.validate().is_ok());
}

#[test]
fn config_validate_ring_buffer_zero_rejected() {
    let mut c = TtdRecordConfig::for_pid(1, "/x");
    c.ring_buffer_mb = Some(0);
    assert!(c.validate().is_err());
    c.ring_buffer_mb = Some(1);
    assert!(c.validate().is_ok());
}

#[test]
fn config_validate_full_heap_requires_record_heap() {
    let mut c = TtdRecordConfig::for_pid(1, "/x");
    c.record_heap = false;
    c.full_heap = true;
    let e = c.validate().unwrap_err();
    assert!(e.contains("full_heap"));
}

// ─── RecordingMetrics / RecordingStatus ──────────────────────────────────────

#[test]
fn metrics_summary_and_display() {
    let m = RecordingMetrics {
        events_recorded: 10,
        file_size_bytes: 1024,
        elapsed_secs: 2.5,
        thread_count: 4,
        ..Default::default()
    };
    let s = m.summary();
    assert!(s.contains("events=10"));
    assert!(s.contains("threads=4"));
    let d = format!("{m}");
    assert!(d.contains("RecordingMetrics"));
}

#[test]
fn recording_status_display() {
    assert_eq!(format!("{}", RecordingStatus::Initializing), "Initializing");
    assert_eq!(format!("{}", RecordingStatus::Recording), "Recording");
    assert_eq!(format!("{}", RecordingStatus::Paused), "Paused");
    assert_eq!(format!("{}", RecordingStatus::Stopped), "Stopped");
    assert_eq!(
        format!("{}", RecordingStatus::Error("boom".into())),
        "Error(boom)"
    );
}

// ─── TtdCheckpoint ───────────────────────────────────────────────────────────

#[test]
fn checkpoint_new_and_display() {
    let cp = TtdCheckpoint::new("mark", TtdPosition::new(1, 2));
    assert_eq!(cp.name, "mark");
    assert_eq!(cp.position, TtdPosition::new(1, 2));
    let s = format!("{cp}");
    assert!(s.contains("mark"));
    assert!(s.contains("1:2"));
}

// ─── TtdRecordResult ─────────────────────────────────────────────────────────

#[test]
fn record_result_is_clean_and_display() {
    let r = TtdRecordResult {
        output_file: "out.run".into(),
        metrics: RecordingMetrics::default(),
        checkpoints: vec![],
        warnings: vec![],
    };
    assert!(r.is_clean());
    let r2 = TtdRecordResult {
        warnings: vec!["w".into()],
        ..r.clone()
    };
    assert!(!r2.is_clean());
    assert!(format!("{r}").contains("out.run"));
}

// ─── TtdRecordFilter / CompiledTtdFilter ─────────────────────────────────────

#[test]
fn filter_pass_all_allows_everything() {
    let f = TtdRecordFilter::pass_all();
    assert!(f.thread_allowed(0));
    assert!(f.thread_allowed(99));
    assert!(f.module_allowed(""));
    assert!(f.module_allowed("kernel32"));
}

#[test]
fn filter_include_thread_restricts() {
    let mut f = TtdRecordFilter::pass_all();
    f.include_threads = vec![1, 2];
    assert!(f.thread_allowed(1));
    assert!(f.thread_allowed(2));
    assert!(!f.thread_allowed(3));
}

#[test]
fn filter_exclude_thread() {
    let mut f = TtdRecordFilter::pass_all();
    f.exclude_threads = vec![5];
    assert!(f.thread_allowed(1));
    assert!(!f.thread_allowed(5));
}

#[test]
fn filter_include_excludes_combined() {
    let mut f = TtdRecordFilter::pass_all();
    f.include_threads = vec![1, 2];
    f.exclude_threads = vec![2];
    assert!(f.thread_allowed(1));
    assert!(!f.thread_allowed(2));
    assert!(!f.thread_allowed(3));
}

#[test]
fn filter_module_include_exclude() {
    let mut f = TtdRecordFilter::pass_all();
    f.include_modules = vec!["a".into(), "b".into()];
    f.exclude_modules = vec!["b".into()];
    assert!(f.module_allowed("a"));
    assert!(!f.module_allowed("b"));
    assert!(!f.module_allowed("c"));
}

#[test]
fn compiled_filter_matches_raw_filter_semantics() {
    let mut f = TtdRecordFilter::pass_all();
    f.include_threads = vec![10, 20];
    f.exclude_threads = vec![20];
    f.include_modules = vec!["mod1".into()];
    f.exclude_modules = vec!["mod2".into()];
    f.record_only_from_address = Some(0xdead);
    f.stop_at_address = Some(0xbeef);
    let c = f.compile();
    assert_eq!(c.record_only_from_address, Some(0xdead));
    assert_eq!(c.stop_at_address, Some(0xbeef));
    for tid in [0u32, 5, 10, 20, 30] {
        assert_eq!(
            f.thread_allowed(tid),
            c.thread_allowed(tid),
            "tid={tid}"
        );
    }
    for name in ["mod1", "mod2", "other", ""] {
        assert_eq!(
            f.module_allowed(name),
            c.module_allowed(name),
            "name={name}"
        );
    }
}

// ─── TtdRecordSession ────────────────────────────────────────────────────────

fn mk_session() -> TtdRecordSession {
    let c = TtdRecordConfig::for_pid(1234, "C:/tmp");
    TtdRecordSession::new(c)
}

#[test]
fn session_initial_status_is_initializing() {
    let s = mk_session();
    assert_eq!(s.status(), RecordingStatus::Initializing);
}

#[test]
fn session_pause_fails_before_start() {
    let s = mk_session();
    assert!(s.pause().is_err());
}

#[test]
fn session_resume_fails_before_pause() {
    let s = mk_session();
    assert!(s.resume().is_err());
}

#[test]
fn session_full_lifecycle_start_pause_resume_stop() {
    let mut s = mk_session();
    s.start().unwrap();
    assert_eq!(s.status(), RecordingStatus::Recording);
    s.pause().unwrap();
    assert_eq!(s.status(), RecordingStatus::Paused);
    // double-pause must fail
    assert!(s.pause().is_err());
    s.resume().unwrap();
    assert_eq!(s.status(), RecordingStatus::Recording);
    // double-resume must fail
    assert!(s.resume().is_err());
    let r = s.stop().unwrap();
    assert_eq!(s.status(), RecordingStatus::Stopped);
    assert!(r.output_file.contains("trace_"));
    assert_eq!(r.metrics.events_recorded, 60);
}

#[test]
fn session_double_stop_errors() {
    let mut s = mk_session();
    s.start().unwrap();
    s.stop().unwrap();
    let err = s.stop().unwrap_err();
    assert!(matches!(err, TtdRecordError::RecordingFailed(_)));
}

#[test]
fn session_start_validates_config() {
    let mut c = TtdRecordConfig::for_pid(1, "/x");
    c.output_dir = String::new();
    let mut s = TtdRecordSession::new(c);
    assert!(s.start().is_err());
}

#[test]
fn session_add_checkpoint_requires_recording() {
    let s = mk_session();
    assert!(s.add_checkpoint("a").is_err());
}

#[test]
fn session_add_checkpoint_increments_position() {
    let mut s = mk_session();
    s.start().unwrap();
    let a = s.add_checkpoint("a").unwrap();
    let b = s.add_checkpoint("b").unwrap();
    assert_eq!(a.position.major, 0);
    assert_eq!(b.position.major, 1);
    assert_ne!(a.position, b.position);
}

#[test]
fn session_trace_handle_returns_arc() {
    let s = mk_session();
    let t1 = s.trace();
    let t2 = s.trace();
    assert!(std::sync::Arc::ptr_eq(&t1, &t2));
}

#[test]
fn session_debug_impl() {
    let s = mk_session();
    let d = format!("{s:?}");
    assert!(d.contains("TtdRecordSession"));
}

// ─── TtdLaunchRecorder ───────────────────────────────────────────────────────

#[test]
fn launch_recorder_with_args() {
    let r = TtdLaunchRecorder::new("foo.exe", "C:/out").with_args(vec!["-x".into()]);
    match &r.config.target_process {
        TtdTarget::Executable { path, args } => {
            assert_eq!(path, "foo.exe");
            assert_eq!(args, &vec!["-x".to_string()]);
        }
        _ => panic!("expected executable target"),
    }
}

#[test]
fn launch_recorder_record_produces_recording_session() {
    let r = TtdLaunchRecorder::new("foo.exe", "C:/out");
    let sess = r.record().unwrap();
    assert_eq!(sess.status(), RecordingStatus::Recording);
}

// ─── TtdAttachRecorder ───────────────────────────────────────────────────────

#[test]
fn attach_recorder_pid_zero_errors() {
    let r = TtdAttachRecorder::new(0, "/x");
    assert!(matches!(r.record(), Err(TtdRecordError::ProcessNotFound)));
}

#[test]
fn attach_recorder_nonzero_succeeds() {
    let r = TtdAttachRecorder::new(123, "C:/x");
    let s = r.record().unwrap();
    assert_eq!(s.status(), RecordingStatus::Recording);
}

// ─── TtdKernelRecorder ───────────────────────────────────────────────────────

#[test]
fn kernel_recorder_only_test_driver_succeeds() {
    let r = TtdKernelRecorder::new("nonexistent", "C:/x");
    assert!(matches!(
        r.record(),
        Err(TtdRecordError::InsufficientPrivileges)
    ));
    let r2 = TtdKernelRecorder::new("test", "C:/x");
    assert!(r2.record().is_ok());
}

// ─── TtdRecordEncryptor ──────────────────────────────────────────────────────

#[test]
fn encryptor_rejects_bad_key_length() {
    assert!(TtdRecordEncryptor::new(vec![0u8; 31]).is_err());
    assert!(TtdRecordEncryptor::new(vec![0u8; 33]).is_err());
    assert!(TtdRecordEncryptor::new(vec![]).is_err());
    assert!(TtdRecordEncryptor::new(vec![0u8; 32]).is_ok());
}

#[test]
fn encryptor_roundtrip() {
    let e = TtdRecordEncryptor::new(vec![7u8; 32]).unwrap();
    let plain = b"hello, ttd trace!";
    let ct = e.encrypt(plain).unwrap();
    assert_ne!(&ct[12..], &plain[..]);
    let pt = e.decrypt(&ct).unwrap();
    assert_eq!(pt, plain);
    assert!(e.is_valid_key());
}

#[test]
fn encryptor_roundtrip_empty() {
    let e = TtdRecordEncryptor::new(vec![1u8; 32]).unwrap();
    let ct = e.encrypt(b"").unwrap();
    assert_eq!(e.decrypt(&ct).unwrap(), Vec::<u8>::new());
}

#[test]
fn encryptor_unique_nonce_per_call() {
    let e = TtdRecordEncryptor::new(vec![3u8; 32]).unwrap();
    let a = e.encrypt(b"same").unwrap();
    let b = e.encrypt(b"same").unwrap();
    assert_ne!(a[..12], b[..12], "nonces must differ");
}

#[test]
fn encryptor_rejects_truncated_ciphertext() {
    let e = TtdRecordEncryptor::new(vec![0u8; 32]).unwrap();
    assert!(e.decrypt(&[0u8; 27]).is_err());
    assert!(e.decrypt(&[]).is_err());
}

#[test]
fn encryptor_rejects_tampered() {
    let e = TtdRecordEncryptor::new(vec![9u8; 32]).unwrap();
    let mut ct = e.encrypt(b"hello").unwrap();
    let n = ct.len();
    ct[n - 1] ^= 1;
    assert!(e.decrypt(&ct).is_err());
}

#[test]
fn encryptor_wrong_key_fails() {
    let e1 = TtdRecordEncryptor::new(vec![1u8; 32]).unwrap();
    let e2 = TtdRecordEncryptor::new(vec![2u8; 32]).unwrap();
    let ct = e1.encrypt(b"secret").unwrap();
    assert!(e2.decrypt(&ct).is_err());
}

// ─── ValidationResult / TtdTraceValidation ───────────────────────────────────

#[test]
fn validation_empty_path_errors() {
    assert!(TtdTraceValidation::validate("").is_err());
}

#[test]
fn validation_run_extension_valid() {
    let r = TtdTraceValidation::validate("foo.run").unwrap();
    assert!(r.is_valid);
    assert!(r.warnings.is_empty());
    assert!(r.is_perfect());
}

#[test]
fn validation_ttd_extension_valid_case_insensitive() {
    let r = TtdTraceValidation::validate("foo.TTD").unwrap();
    assert!(r.is_valid);
}

#[test]
fn validation_unknown_extension_invalid_with_warning() {
    let r = TtdTraceValidation::validate("foo.bin").unwrap();
    assert!(!r.is_valid);
    assert!(!r.warnings.is_empty());
    assert!(!r.is_perfect());
    assert!(format!("{r}").contains("valid"));
}

#[test]
fn validation_is_valid_extension_helper() {
    assert!(TtdTraceValidation::is_valid_extension("a.run"));
    assert!(TtdTraceValidation::is_valid_extension("a.ttd"));
    assert!(TtdTraceValidation::is_valid_extension("a.RUN"));
    assert!(!TtdTraceValidation::is_valid_extension("a.txt"));
    assert!(!TtdTraceValidation::is_valid_extension("noext"));
}

// ─── RecorderConfig / RecordingSession (legacy) ─────────────────────────────

#[test]
fn recorder_config_default_and_display() {
    let c = RecorderConfig::default();
    assert!(c.record_memory);
    assert!(c.record_threads);
    assert!(c.max_events.is_none());
    let s = format!("{c}");
    assert!(s.contains("record_memory"));
}

#[test]
fn recording_session_new_and_display() {
    let s = RecordingSession::new(RecorderConfig::default(), 77);
    assert_eq!(s.pid, 77);
    assert_eq!(s.event_count, 0);
    assert!(format!("{s}").contains("pid: 77"));
}

// ─── InProcessRecorder (async) ───────────────────────────────────────────────

#[tokio::test]
async fn in_process_recorder_start_stop_default() {
    let r = InProcessRecorder;
    let sess = r.start(RecorderConfig::default()).await.unwrap();
    let trace = r.stop(sess).await.unwrap();
    assert_eq!(trace.all_events().len(), 50);
}

#[tokio::test]
async fn in_process_recorder_start_rejects_zero_max_events() {
    let r = InProcessRecorder;
    let cfg = RecorderConfig {
        max_events: Some(0),
        ..Default::default()
    };
    let e = r.start(cfg).await.unwrap_err();
    assert!(matches!(e, RecorderError::InvalidConfig(_)));
}

#[tokio::test]
async fn in_process_recorder_stop_honors_max_events() {
    let r = InProcessRecorder;
    let cfg = RecorderConfig {
        max_events: Some(7),
        ..Default::default()
    };
    let sess = r.start(cfg).await.unwrap();
    let trace = r.stop(sess).await.unwrap();
    assert_eq!(trace.all_events().len(), 7);
}

#[tokio::test]
async fn in_process_recorder_attach_zero_errors() {
    let r = InProcessRecorder;
    let e = r.attach(0, RecorderConfig::default()).await.unwrap_err();
    assert!(matches!(e, RecorderError::SpawnError(_)));
}

#[tokio::test]
async fn in_process_recorder_attach_nonzero_ok() {
    let r = InProcessRecorder;
    let s = r.attach(99, RecorderConfig::default()).await.unwrap();
    assert_eq!(s.pid, 99);
}

// ─── TraceSerializer roundtrip ───────────────────────────────────────────────

#[tokio::test]
async fn serializer_roundtrip() {
    let r = InProcessRecorder;
    let cfg = RecorderConfig {
        max_events: Some(20),
        ..Default::default()
    };
    let sess = r.start(cfg).await.unwrap();
    let trace = r.stop(sess).await.unwrap();
    let bytes = TraceSerializer::serialize(&trace).unwrap();
    let back = TraceSerializer::deserialize(&bytes).unwrap();
    assert_eq!(back.all_events().len(), trace.all_events().len());
}

#[test]
fn serializer_deserialize_garbage_errors() {
    let r = TraceSerializer::deserialize(b"not json").err();
    assert!(matches!(r, Some(RecorderError::Serde(_))));
}

// ─── RingBufferRecorder ──────────────────────────────────────────────────────

const fn mk_event(seq: u64, tid: u32) -> rustre_ttd::TraceEvent {
    rustre_ttd::TraceEvent {
        position: rustre_ttd::TracePosition::new(seq, 0),
        thread_id: tid,
        kind: rustre_ttd::EventKind::MemRead { addr: seq, len: 1 },
    }
}

#[test]
fn ring_buffer_basic_push_and_len() {
    let rb = RingBufferRecorder::new(3);
    assert!(rb.is_empty());
    rb.push(mk_event(1, 1));
    rb.push(mk_event(2, 1));
    assert_eq!(rb.len(), 2);
    assert!(!rb.is_empty());
}

#[test]
fn ring_buffer_overflow_drops_oldest() {
    let rb = RingBufferRecorder::new(2);
    rb.push(mk_event(1, 1));
    rb.push(mk_event(2, 1));
    rb.push(mk_event(3, 1));
    let snap = rb.snapshot();
    assert_eq!(snap.len(), 2);
    // Oldest (seq=1) should be dropped.
    let seqs: Vec<u64> = snap.iter().map(|e| e.position.sequence).collect();
    assert!(!seqs.contains(&1), "oldest should be evicted, got {seqs:?}");
}

#[test]
fn ring_buffer_clear() {
    let rb = RingBufferRecorder::new(4);
    rb.push(mk_event(1, 1));
    rb.push(mk_event(2, 1));
    rb.clear();
    assert!(rb.is_empty());
    assert_eq!(rb.len(), 0);
}

// ─── RecordingStats ──────────────────────────────────────────────────────────

#[tokio::test]
async fn recording_stats_from_trace() {
    let r = InProcessRecorder;
    let trace = r
        .stop(
            r.start(RecorderConfig {
                max_events: Some(30),
                ..Default::default()
            })
            .await
            .unwrap(),
        )
        .await
        .unwrap();
    let stats = RecordingStats::from_trace(&trace, 1.5);
    assert_eq!(stats.total_events, 30);
    assert_eq!(stats.duration_secs, 1.5);
    assert!(stats.hottest_thread().is_some());
    let sum: u64 = stats.events_per_thread.values().sum();
    assert_eq!(sum, 30);
}

#[test]
fn recording_stats_hottest_thread_none_on_empty() {
    let s = RecordingStats::default();
    assert!(s.hottest_thread().is_none());
}

// ─── RecordingSchedule ───────────────────────────────────────────────────────

#[test]
fn schedule_record_all_never_stops() {
    let s = RecordingSchedule::record_all();
    assert!(!s.should_stop(TtdPosition::new(99, 99), std::time::Duration::from_secs(99999)));
}

#[test]
fn schedule_for_duration_stops_after_max() {
    let s = RecordingSchedule::for_duration(5);
    assert!(!s.should_stop(TtdPosition::start(), std::time::Duration::from_secs(4)));
    assert!(s.should_stop(TtdPosition::start(), std::time::Duration::from_secs(5)));
    assert!(s.should_stop(TtdPosition::start(), std::time::Duration::from_secs(6)));
}

#[test]
fn schedule_stops_at_position() {
    let mut s = RecordingSchedule::record_all();
    s.stop_position = Some(TtdPosition::new(10, 0));
    assert!(!s.should_stop(TtdPosition::new(9, 0), std::time::Duration::ZERO));
    assert!(s.should_stop(TtdPosition::new(10, 0), std::time::Duration::ZERO));
    assert!(s.should_stop(TtdPosition::new(11, 0), std::time::Duration::ZERO));
}

// ─── TraceFileInfo ───────────────────────────────────────────────────────────

#[test]
fn trace_file_info_from_path_extension_handling() {
    let i = TraceFileInfo::from_path("x.run");
    assert!(i.valid);
    assert_eq!(i.event_count_approx, 1000);
    let j = TraceFileInfo::from_path("x.txt");
    assert!(!j.valid);
}

// ─── TtdTraceHeader / TtdTraceFile ───────────────────────────────────────────

#[test]
fn ttd_trace_header_new_validates() {
    let h = TtdTraceHeader::new(42);
    assert!(h.validate().is_ok());
    assert_eq!(h.version, TTD_VERSION);
    assert_eq!(h.pid, 42);
}

#[test]
fn ttd_trace_header_bad_magic_rejected() {
    let mut h = TtdTraceHeader::new(1);
    h.magic = "WRONG".into();
    assert!(h.validate().is_err());
}

#[test]
fn ttd_trace_header_bad_version_rejected() {
    let mut h = TtdTraceHeader::new(1);
    h.version = 9999;
    let e = h.validate().unwrap_err();
    assert!(e.contains("version"));
}

const fn mk_syscall_event(ic: u64, nr: u32) -> SyscallEvent {
    SyscallEvent {
        instr_count: ic,
        nr,
        args: [0; 6],
        retval: 0,
        mem_writes: vec![],
    }
}

#[test]
fn ttd_trace_file_basic_ops() {
    let mut f = TtdTraceFile::new(7);
    assert_eq!(f.event_count(), 0);
    assert!(f.first_event().is_none());
    assert!(f.last_event().is_none());
    f.push(mk_syscall_event(10, 1));
    f.push(mk_syscall_event(20, 2));
    f.push(mk_syscall_event(30, 1));
    assert_eq!(f.event_count(), 3);
    assert_eq!(f.first_event().unwrap().instr_count, 10);
    assert_eq!(f.last_event().unwrap().instr_count, 30);
    assert_eq!(f.total_instructions(), 30);
    assert_eq!(f.iter_events().count(), 3);
    let unique = f.unique_syscalls();
    assert_eq!(unique, vec![1, 2]);
    assert_eq!(f.filter_by_nr(1).len(), 2);
    assert_eq!(f.filter_by_nr(99).len(), 0);
}

#[test]
fn ttd_trace_file_total_instructions_empty_is_zero() {
    let f = TtdTraceFile::new(1);
    assert_eq!(f.total_instructions(), 0);
}

#[test]
fn ttd_trace_file_disk_roundtrip() {
    let dir = std::env::temp_dir().join(format!("rustre_ttd_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("trace.json");
    let mut f = TtdTraceFile::new(123);
    f.push(mk_syscall_event(5, 7));
    f.push(mk_syscall_event(6, 8));
    f.write_to_file(&path).unwrap();
    let back = TtdTraceFile::read_from_file(&path).unwrap();
    assert_eq!(back.event_count(), 2);
    assert_eq!(back.header.pid, 123);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn ttd_trace_file_read_rejects_bad_magic_on_disk() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("rustre_bad_magic_{}.json", std::process::id()));
    // Write a JSON file with a wrong magic value.
    let bad = serde_json::json!({
        "header": {
            "magic": "NOPE",
            "version": 1,
            "arch": "x86_64",
            "pid": 1,
            "recorded_at": 0,
        },
        "events": []
    });
    std::fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();
    assert!(TtdTraceFile::read_from_file(&path).is_err());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn ttd_magic_constant_is_8_bytes() {
    assert_eq!(TTD_MAGIC.len(), 8);
    assert_eq!(TTD_MAGIC, b"RUSTTD01");
}

// ─── TtdBinaryTrace ──────────────────────────────────────────────────────────

#[test]
fn binary_trace_new_and_push() {
    let mut t = TtdBinaryTrace::new(42);
    assert_eq!(t.magic, TtdBinaryTrace::MAGIC);
    assert_eq!(t.event_count(), 0);
    assert_eq!(t.total_instructions(), 0);
    t.push(mk_syscall_event(100, 1));
    assert_eq!(t.event_count(), 1);
    assert_eq!(t.total_instructions(), 100);
}

#[test]
fn binary_trace_disk_roundtrip() {
    let path = std::env::temp_dir().join(format!(
        "rustre_bin_trace_{}.bin",
        std::process::id()
    ));
    let mut t = TtdBinaryTrace::new(11);
    t.push(mk_syscall_event(1, 2));
    t.push(mk_syscall_event(2, 3));
    t.write_to_file(&path).unwrap();
    let back = TtdBinaryTrace::read_from_file(&path).unwrap();
    assert_eq!(back.event_count(), 2);
    assert_eq!(back.pid, 11);
    assert_eq!(back.magic, TtdBinaryTrace::MAGIC);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn binary_trace_rejects_bad_magic() {
    let path = std::env::temp_dir().join(format!(
        "rustre_bin_badmagic_{}.bin",
        std::process::id()
    ));
    let mut t = TtdBinaryTrace::new(1);
    t.magic = [0, 0, 0, 0];
    let encoded = bincode::serialize(&t).unwrap();
    std::fs::write(&path, encoded).unwrap();
    assert!(TtdBinaryTrace::read_from_file(&path).is_err());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn binary_trace_rejects_garbage() {
    let path = std::env::temp_dir().join(format!(
        "rustre_bin_garbage_{}.bin",
        std::process::id()
    ));
    std::fs::write(&path, b"not bincode").unwrap();
    assert!(TtdBinaryTrace::read_from_file(&path).is_err());
    let _ = std::fs::remove_file(&path);
}

// ─── TraceEventConverter ─────────────────────────────────────────────────────

#[test]
fn converter_produces_entry_exit_pair() {
    let ev = SyscallEvent {
        instr_count: 50,
        nr: 9,
        args: [1, 2, 3, 4, 5, 6],
        retval: -1,
        mem_writes: vec![],
    };
    let [enter, exit] = TraceEventConverter::convert(&ev, 7);
    assert_eq!(enter.thread_id, 7);
    assert_eq!(exit.thread_id, 7);
    match enter.kind {
        rustre_ttd::EventKind::SyscallEnter { nr, args } => {
            assert_eq!(nr, 9);
            assert_eq!(args, [1, 2, 3, 4, 5, 6]);
        }
        _ => panic!("expected SyscallEnter"),
    }
    match exit.kind {
        rustre_ttd::EventKind::SyscallExit { nr, .. } => assert_eq!(nr, 9),
        _ => panic!("expected SyscallExit"),
    }
}

#[test]
fn converter_convert_file_doubles_event_count() {
    let mut f = TtdTraceFile::new(1);
    f.push(mk_syscall_event(1, 1));
    f.push(mk_syscall_event(2, 2));
    f.push(mk_syscall_event(3, 3));
    let trace = TraceEventConverter::convert_file(&f);
    assert_eq!(trace.all_events().len(), 6);
}

// ─── SyscallEventStats ───────────────────────────────────────────────────────

#[test]
fn syscall_stats_empty() {
    let f = TtdTraceFile::new(1);
    let s = SyscallEventStats::from_trace_file(&f);
    assert_eq!(s.total, 0);
    assert_eq!(s.min_instr, 0);
    assert_eq!(s.max_instr, 0);
    assert!(s.most_common_nr().is_none());
}

#[test]
fn syscall_stats_populated() {
    let mut f = TtdTraceFile::new(1);
    f.push(mk_syscall_event(10, 1));
    f.push(mk_syscall_event(20, 1));
    f.push(mk_syscall_event(30, 2));
    let mut ev = mk_syscall_event(40, 3);
    ev.mem_writes.push(MemWrite {
        addr: 0,
        data: vec![1, 2, 3, 4],
    });
    f.push(ev);
    let s = SyscallEventStats::from_trace_file(&f);
    assert_eq!(s.total, 4);
    assert_eq!(s.min_instr, 10);
    assert_eq!(s.max_instr, 40);
    assert_eq!(s.most_common_nr(), Some(1));
    assert_eq!(s.total_write_bytes, 4);
}

// ─── check_platform_support ─────────────────────────────────────────────────

#[test]
fn check_platform_support_windows_returns_err() {
    // On Windows the function returns NotAvailable-style error per source.
    let r = check_platform_support();
    if cfg!(target_os = "linux") {
        assert!(r.is_ok());
    } else {
        assert!(r.is_err());
    }
}

// ─── TtdRecordError From<CoreError> ─────────────────────────────────────────

#[test]
fn ttd_error_from_io() {
    let io = std::io::Error::other("x");
    let e: TtdRecordError = io.into();
    assert!(matches!(e, TtdRecordError::Io(_)));
}

#[test]
fn ttd_error_display() {
    let e = TtdRecordError::NotAvailable;
    assert_eq!(format!("{e}"), "TTD recording not available");
    let e = TtdRecordError::ProcessNotFound;
    assert_eq!(format!("{e}"), "process not found");
    let e = TtdRecordError::InsufficientPrivileges;
    assert_eq!(format!("{e}"), "insufficient privileges");
}
