//! blitz2 — deep adversarial coverage for rustre-ttd-recorder.

use rustre_ttd_recorder::*;
use std::sync::Arc;

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

// ─── TtdPosition ─────────────────────────────────────────────────────────────

#[test]
fn pos_new_fields() {
    for i in 0..60u64 {
        let p = TtdPosition::new(i, i.wrapping_mul(3));
        assert_eq!(p.major, i);
        assert_eq!(p.minor, i.wrapping_mul(3));
    }
}

#[test]
fn pos_start_is_zero_zero() {
    let s = TtdPosition::start();
    assert_eq!(s.major, 0);
    assert_eq!(s.minor, 0);
}

#[test]
fn pos_display_roundtrip_format() {
    for i in 0..50u64 {
        let p = TtdPosition::new(i, i + 1);
        assert_eq!(format!("{p}"), format!("{}:{}", i, i + 1));
    }
}

#[test]
fn pos_ordering_total() {
    let mut g = lcg();
    for _ in 0..200 {
        let a = TtdPosition::new(g() % 100, g() % 100);
        let b = TtdPosition::new(g() % 100, g() % 100);
        // total order: exactly one of <, ==, >
        let lt = a < b;
        let eq = a == b;
        let gt = a > b;
        assert_eq!(u8::from(lt) + u8::from(eq) + u8::from(gt), 1);
        assert_eq!(a.is_before(&b), a < b);
    }
}

#[test]
fn pos_earliest_picks_min() {
    let mut g = lcg();
    for _ in 0..100 {
        let a = TtdPosition::new(g() % 50, g() % 50);
        let b = TtdPosition::new(g() % 50, g() % 50);
        let e = TtdPosition::earliest(&a, &b);
        assert!(*e <= a && *e <= b);
    }
}

#[test]
fn pos_to_trace_position_roundtrip() {
    for i in 0..50u64 {
        let p = TtdPosition::new(i, i * 2);
        let tp = p.to_trace_position();
        assert_eq!(tp.sequence, p.major);
        assert_eq!(tp.step, p.minor);
    }
}

#[test]
fn pos_hash_eq_consistency() {
    use std::collections::HashSet;
    let mut set: HashSet<TtdPosition> = HashSet::new();
    for i in 0..30u64 {
        set.insert(TtdPosition::new(i, 0));
        set.insert(TtdPosition::new(i, 0)); // dup
    }
    assert_eq!(set.len(), 30);
}

#[test]
fn pos_boundary_u64_max() {
    let p = TtdPosition::new(u64::MAX, u64::MAX);
    assert_eq!(p.major, u64::MAX);
    let q = TtdPosition::new(u64::MAX, u64::MAX - 1);
    assert!(q < p);
}

// ─── CompressionLevel ────────────────────────────────────────────────────────

#[test]
fn compression_display_all_variants() {
    assert_eq!(format!("{}", CompressionLevel::None), "none");
    assert_eq!(format!("{}", CompressionLevel::Fast), "fast");
    assert_eq!(format!("{}", CompressionLevel::Default), "default");
    assert_eq!(format!("{}", CompressionLevel::Best), "best");
}

#[test]
fn compression_default_is_default_variant() {
    assert_eq!(CompressionLevel::default(), CompressionLevel::Default);
}

#[test]
fn compression_serde_roundtrip() {
    for v in [
        CompressionLevel::None,
        CompressionLevel::Fast,
        CompressionLevel::Default,
        CompressionLevel::Best,
    ] {
        let s = serde_json::to_string(&v).unwrap();
        let back: CompressionLevel = serde_json::from_str(&s).unwrap();
        assert_eq!(back, v);
    }
}

// ─── TtdTarget ───────────────────────────────────────────────────────────────

#[test]
fn target_display_each_variant() {
    assert_eq!(format!("{}", TtdTarget::ProcessId(42)), "pid:42");
    assert_eq!(
        format!("{}", TtdTarget::ProcessName("notepad.exe".into())),
        "name:notepad.exe"
    );
    assert_eq!(
        format!(
            "{}",
            TtdTarget::Executable {
                path: "/bin/ls".into(),
                args: vec![]
            }
        ),
        "exe:/bin/ls"
    );
    assert_eq!(
        format!("{}", TtdTarget::Spawn { cmd: "echo hi".into() }),
        "spawn:echo hi"
    );
}

#[test]
fn target_serde_roundtrip_fuzz() {
    let mut g = lcg();
    for _ in 0..40 {
        let t = match g() % 4 {
            0 => TtdTarget::ProcessId((g() & 0xFFFF) as u32),
            1 => TtdTarget::ProcessName(format!("p{}", g() % 1000)),
            2 => TtdTarget::Executable {
                path: format!("/x/{}", g() % 100),
                args: vec!["a".into()],
            },
            _ => TtdTarget::Spawn {
                cmd: format!("c {}", g() % 100),
            },
        };
        let s = serde_json::to_string(&t).unwrap();
        let _back: TtdTarget = serde_json::from_str(&s).unwrap();
    }
}

// ─── TtdRecordConfig ──────────────────────────────────────────────────────────

#[test]
fn config_for_pid_defaults() {
    let c = TtdRecordConfig::for_pid(123, "/out");
    assert!(matches!(c.target_process, TtdTarget::ProcessId(123)));
    assert_eq!(c.output_dir, "/out");
    assert_eq!(c.max_recording_size_mb, 0);
    assert!(!c.encrypt);
    assert!(c.record_heap);
    assert!(!c.full_heap);
}

#[test]
fn config_validate_empty_output_dir_errs() {
    let mut c = TtdRecordConfig::for_pid(1, "");
    assert!(c.validate().is_err());
    c.output_dir = "/tmp".into();
    assert!(c.validate().is_ok());
}

#[test]
fn config_validate_zero_ring_buffer_errs() {
    let mut c = TtdRecordConfig::for_pid(1, "/tmp");
    c.ring_buffer_mb = Some(0);
    assert!(c.validate().is_err());
    c.ring_buffer_mb = Some(1);
    assert!(c.validate().is_ok());
    c.ring_buffer_mb = Some(u64::MAX);
    assert!(c.validate().is_ok());
}

#[test]
fn config_validate_full_heap_requires_record_heap() {
    let mut c = TtdRecordConfig::for_pid(1, "/tmp");
    c.record_heap = false;
    c.full_heap = true;
    assert!(c.validate().is_err());
    c.record_heap = true;
    assert!(c.validate().is_ok());
}

// ─── RecordingStatus ─────────────────────────────────────────────────────────

#[test]
fn status_display_all_variants() {
    assert_eq!(format!("{}", RecordingStatus::Initializing), "Initializing");
    assert_eq!(format!("{}", RecordingStatus::Injecting), "Injecting");
    assert_eq!(format!("{}", RecordingStatus::Recording), "Recording");
    assert_eq!(format!("{}", RecordingStatus::Paused), "Paused");
    assert_eq!(format!("{}", RecordingStatus::Stopping), "Stopping");
    assert_eq!(format!("{}", RecordingStatus::Stopped), "Stopped");
    assert_eq!(
        format!("{}", RecordingStatus::Error("oops".into())),
        "Error(oops)"
    );
}

#[test]
fn status_eq_and_clone() {
    let a = RecordingStatus::Recording;
    let b = a.clone();
    assert_eq!(a, b);
    assert_ne!(a, RecordingStatus::Paused);
}

// ─── RecordingMetrics ────────────────────────────────────────────────────────

#[test]
fn metrics_default_and_summary() {
    let m = RecordingMetrics::default();
    assert_eq!(m.events_recorded, 0);
    let s = m.summary();
    assert!(s.contains("events=0"));
    assert!(s.contains("threads=0"));
}

#[test]
fn metrics_display_contains_summary() {
    let mut m = RecordingMetrics::default();
    m.events_recorded = 99;
    let d = format!("{m}");
    assert!(d.contains("events=99"));
}

// ─── TtdCheckpoint ───────────────────────────────────────────────────────────

#[test]
fn checkpoint_new_fields() {
    let p = TtdPosition::new(7, 3);
    let cp = TtdCheckpoint::new("foo", p);
    assert_eq!(cp.name, "foo");
    assert_eq!(cp.position, p);
}

#[test]
fn checkpoint_display() {
    let cp = TtdCheckpoint::new("x", TtdPosition::new(1, 2));
    let s = format!("{cp}");
    assert!(s.contains("Checkpoint(x"));
    assert!(s.contains("1:2"));
}

// ─── TtdRecordResult ─────────────────────────────────────────────────────────

#[test]
fn result_is_clean_only_when_no_warnings() {
    let r = TtdRecordResult {
        output_file: "x.run".into(),
        metrics: RecordingMetrics::default(),
        checkpoints: vec![],
        warnings: vec![],
    };
    assert!(r.is_clean());
    let r2 = TtdRecordResult {
        warnings: vec!["w".into()],
        ..r
    };
    assert!(!r2.is_clean());
}

// ─── TtdRecordFilter ─────────────────────────────────────────────────────────

#[test]
fn filter_pass_all_accepts_everything() {
    let f = TtdRecordFilter::pass_all();
    let mut g = lcg();
    for _ in 0..50 {
        let tid = (g() & 0xFFFF) as u32;
        assert!(f.thread_allowed(tid));
        assert!(f.module_allowed(&format!("m{}", g() % 100)));
    }
}

#[test]
fn filter_include_threads_excludes_others() {
    let mut f = TtdRecordFilter::pass_all();
    f.include_threads = vec![1, 2, 3];
    assert!(f.thread_allowed(1));
    assert!(f.thread_allowed(2));
    assert!(!f.thread_allowed(4));
    assert!(!f.thread_allowed(0));
}

#[test]
fn filter_exclude_threads_blocks() {
    let mut f = TtdRecordFilter::pass_all();
    f.exclude_threads = vec![10];
    assert!(f.thread_allowed(11));
    assert!(!f.thread_allowed(10));
}

#[test]
fn filter_include_modules() {
    let mut f = TtdRecordFilter::pass_all();
    f.include_modules = vec!["kernel32.dll".into()];
    assert!(f.module_allowed("kernel32.dll"));
    assert!(!f.module_allowed("user32.dll"));
}

#[test]
fn filter_exclude_modules() {
    let mut f = TtdRecordFilter::pass_all();
    f.exclude_modules = vec!["ntdll.dll".into()];
    assert!(f.module_allowed("kernel32.dll"));
    assert!(!f.module_allowed("ntdll.dll"));
}

#[test]
fn compiled_filter_matches_uncompiled_behavior() {
    let mut f = TtdRecordFilter::pass_all();
    f.include_threads = vec![1, 5, 7];
    f.exclude_threads = vec![5];
    f.include_modules = vec!["a".into(), "b".into()];
    f.exclude_modules = vec!["b".into()];
    let c = f.compile();
    for tid in 0..20u32 {
        assert_eq!(f.thread_allowed(tid), c.thread_allowed(tid), "tid={tid}");
    }
    for name in ["a", "b", "c", "x", "y"] {
        assert_eq!(f.module_allowed(name), c.module_allowed(name), "n={name}");
    }
}

#[test]
fn compiled_filter_carries_addresses() {
    let mut f = TtdRecordFilter::pass_all();
    f.record_only_from_address = Some(0x1000);
    f.stop_at_address = Some(0x2000);
    let c = f.compile();
    assert_eq!(c.record_only_from_address, Some(0x1000));
    assert_eq!(c.stop_at_address, Some(0x2000));
}

// ─── TtdRecordSession ─────────────────────────────────────────────────────────

#[test]
fn session_lifecycle_start_pause_resume_stop() {
    let mut s = TtdRecordSession::new(TtdRecordConfig::for_pid(1, "/tmp"));
    assert_eq!(s.status(), RecordingStatus::Initializing);
    s.start().unwrap();
    assert_eq!(s.status(), RecordingStatus::Recording);
    s.pause().unwrap();
    assert_eq!(s.status(), RecordingStatus::Paused);
    s.resume().unwrap();
    assert_eq!(s.status(), RecordingStatus::Recording);
    let r = s.stop().unwrap();
    assert_eq!(s.status(), RecordingStatus::Stopped);
    assert_eq!(r.metrics.events_recorded, 60);
}

#[test]
fn session_invalid_pause_resume_transitions() {
    let mut s = TtdRecordSession::new(TtdRecordConfig::for_pid(1, "/tmp"));
    // Can't pause when not recording
    assert!(s.pause().is_err());
    // Can't resume when not paused
    assert!(s.resume().is_err());
    s.start().unwrap();
    // Can't resume while recording
    assert!(s.resume().is_err());
    s.pause().unwrap();
    // Can't pause again while paused
    assert!(s.pause().is_err());
}

#[test]
fn session_double_stop_errors() {
    let mut s = TtdRecordSession::new(TtdRecordConfig::for_pid(1, "/tmp"));
    s.start().unwrap();
    s.stop().unwrap();
    assert!(s.stop().is_err());
}

#[test]
fn session_invalid_config_fails_start() {
    let mut cfg = TtdRecordConfig::for_pid(1, "");
    cfg.output_dir = String::new();
    let mut s = TtdRecordSession::new(cfg);
    assert!(s.start().is_err());
}

#[test]
fn session_checkpoint_requires_recording() {
    let s = TtdRecordSession::new(TtdRecordConfig::for_pid(1, "/tmp"));
    assert!(s.add_checkpoint("c").is_err());
}

#[test]
fn session_checkpoints_advance_position() {
    let mut s = TtdRecordSession::new(TtdRecordConfig::for_pid(1, "/tmp"));
    s.start().unwrap();
    let a = s.add_checkpoint("a").unwrap();
    let b = s.add_checkpoint("b").unwrap();
    assert!(a.position < b.position);
}

#[test]
fn session_metrics_snapshot_consistent() {
    let mut s = TtdRecordSession::new(TtdRecordConfig::for_pid(1, "/tmp"));
    s.start().unwrap();
    let _ = s.metrics();
    let r = s.stop().unwrap();
    assert_eq!(r.metrics.instructions_recorded, 60);
    assert_eq!(r.metrics.memory_events, (60 / 5) * 2);
}

// ─── TtdLaunchRecorder / TtdAttachRecorder / TtdKernelRecorder ───────────────

#[test]
fn launch_recorder_with_args() {
    let r = TtdLaunchRecorder::new("/bin/ls", "/tmp").with_args(vec!["-l".into()]);
    if let TtdTarget::Executable { args, .. } = &r.config.target_process {
        assert_eq!(args, &vec!["-l".to_string()]);
    } else {
        panic!("expected Executable");
    }
    let sess = r.record().unwrap();
    assert_eq!(sess.status(), RecordingStatus::Recording);
}

#[test]
fn attach_recorder_rejects_pid_zero() {
    let r = TtdAttachRecorder::new(0, "/tmp");
    assert!(matches!(
        r.record(),
        Err(TtdRecordError::ProcessNotFound)
    ));
}

#[test]
fn attach_recorder_succeeds_with_valid_pid() {
    let r = TtdAttachRecorder::new(42, "/tmp");
    let sess = r.record().unwrap();
    assert_eq!(sess.status(), RecordingStatus::Recording);
}

#[test]
fn kernel_recorder_only_test_driver_accepted() {
    let bad = TtdKernelRecorder::new("realdriver", "/tmp");
    assert!(matches!(
        bad.record(),
        Err(TtdRecordError::InsufficientPrivileges)
    ));
    let good = TtdKernelRecorder::new("test", "/tmp");
    let sess = good.record().unwrap();
    assert_eq!(sess.status(), RecordingStatus::Recording);
}

// ─── TtdRecordEncryptor ──────────────────────────────────────────────────────

#[test]
fn encryptor_rejects_wrong_key_size() {
    for n in [0usize, 1, 16, 31, 33, 64, 100] {
        assert!(TtdRecordEncryptor::new(vec![0u8; n]).is_err());
    }
    assert!(TtdRecordEncryptor::new(vec![0u8; 32]).is_ok());
}

#[test]
fn encryptor_roundtrip_many_messages() {
    let key = vec![0xAA; 32];
    let enc = TtdRecordEncryptor::new(key.clone()).unwrap();
    let dec = TtdRecordEncryptor::new(key).unwrap();
    let mut g = lcg();
    for _ in 0..30 {
        let n = (g() % 256) as usize;
        let msg: Vec<u8> = (0..n).map(|_| g() as u8).collect();
        let ct = enc.encrypt(&msg).unwrap();
        // ct contains nonce (12) + ciphertext + tag (16)
        assert!(ct.len() >= 12 + 16);
        let pt = dec.decrypt(&ct).unwrap();
        assert_eq!(pt, msg);
    }
}

#[test]
fn encryptor_detects_tampering() {
    let key = vec![0x11; 32];
    let enc = TtdRecordEncryptor::new(key).unwrap();
    let mut ct = enc.encrypt(b"hello").unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 0xFF;
    assert!(enc.decrypt(&ct).is_err());
}

#[test]
fn encryptor_rejects_truncated_blob() {
    let enc = TtdRecordEncryptor::new(vec![0; 32]).unwrap();
    for n in [0usize, 1, 11, 27] {
        assert!(enc.decrypt(&vec![0u8; n]).is_err());
    }
}

#[test]
fn encryptor_nonces_unique_per_call() {
    let enc = TtdRecordEncryptor::new(vec![0x42; 32]).unwrap();
    let mut nonces = std::collections::HashSet::new();
    for _ in 0..30 {
        let ct = enc.encrypt(b"x").unwrap();
        nonces.insert(ct[..12].to_vec());
    }
    assert_eq!(nonces.len(), 30);
}

#[test]
fn encryptor_is_valid_key_always_true() {
    let enc = TtdRecordEncryptor::new(vec![0; 32]).unwrap();
    assert!(enc.is_valid_key());
}

// ─── ValidationResult / TtdTraceValidation ───────────────────────────────────

#[test]
fn validation_is_perfect() {
    let v = ValidationResult {
        is_valid: true,
        version: 1,
        position_range: (TtdPosition::start(), TtdPosition::new(1, 0)),
        warnings: vec![],
    };
    assert!(v.is_perfect());
    let v2 = ValidationResult {
        warnings: vec!["w".into()],
        ..v
    };
    assert!(!v2.is_perfect());
}

#[test]
fn validation_extensions() {
    assert!(TtdTraceValidation::is_valid_extension("foo.run"));
    assert!(TtdTraceValidation::is_valid_extension("foo.RUN"));
    assert!(TtdTraceValidation::is_valid_extension("foo.ttd"));
    assert!(TtdTraceValidation::is_valid_extension("foo.TTD"));
    assert!(!TtdTraceValidation::is_valid_extension("foo.txt"));
    assert!(!TtdTraceValidation::is_valid_extension("foo"));
}

#[test]
fn validation_empty_path_errors() {
    assert!(TtdTraceValidation::validate("").is_err());
}

#[test]
fn validation_valid_path_clean() {
    let v = TtdTraceValidation::validate("/tmp/trace.run").unwrap();
    assert!(v.is_valid);
    assert!(v.warnings.is_empty());
}

#[test]
fn validation_invalid_ext_warns() {
    let v = TtdTraceValidation::validate("/tmp/trace.txt").unwrap();
    assert!(!v.is_valid);
    assert!(!v.warnings.is_empty());
}

// ─── RecorderConfig ──────────────────────────────────────────────────────────

#[test]
fn recorder_config_default_display() {
    let c = RecorderConfig::default();
    assert!(c.record_memory);
    assert!(c.record_threads);
    assert!(c.max_events.is_none());
    let d = format!("{c}");
    assert!(d.contains("record_memory: true"));
}

#[test]
fn recording_session_new_and_display() {
    let s = RecordingSession::new(RecorderConfig::default(), 99);
    assert_eq!(s.pid, 99);
    assert_eq!(s.event_count, 0);
    let d = format!("{s}");
    assert!(d.contains("pid: 99"));
}

// ─── InProcessRecorder + TraceSerializer ─────────────────────────────────────

#[test]
fn inprocess_recorder_basic() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let r = InProcessRecorder;
        let mut cfg = RecorderConfig::default();
        cfg.max_events = Some(20);
        let sess = r.start(cfg.clone()).await.unwrap();
        let trace = r.stop(sess).await.unwrap();
        assert_eq!(trace.all_events().len(), 20);
    });
}

#[test]
fn inprocess_recorder_zero_max_events_errs() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let r = InProcessRecorder;
        let mut cfg = RecorderConfig::default();
        cfg.max_events = Some(0);
        assert!(r.start(cfg).await.is_err());
    });
}

#[test]
fn inprocess_recorder_attach_zero_errs() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let r = InProcessRecorder;
        assert!(r.attach(0, RecorderConfig::default()).await.is_err());
        assert!(r.attach(1, RecorderConfig::default()).await.is_ok());
    });
}

#[test]
fn trace_serializer_roundtrip() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let r = InProcessRecorder;
        let mut cfg = RecorderConfig::default();
        cfg.max_events = Some(15);
        let sess = r.start(cfg).await.unwrap();
        let trace = r.stop(sess).await.unwrap();
        let bytes = TraceSerializer::serialize(&trace).unwrap();
        let back = TraceSerializer::deserialize(&bytes).unwrap();
        assert_eq!(back.all_events().len(), trace.all_events().len());
    });
}

#[test]
fn trace_serializer_garbage_errs() {
    assert!(TraceSerializer::deserialize(b"not json").is_err());
    assert!(TraceSerializer::deserialize(b"").is_err());
}

// ─── RingBufferRecorder ──────────────────────────────────────────────────────

#[test]
fn ring_buffer_basic_push_snapshot() {
    use rustre_ttd::{EventKind, TraceEvent, TracePosition};
    let rb = RingBufferRecorder::new(4);
    assert!(rb.is_empty());
    for i in 0..3u64 {
        rb.push(TraceEvent {
            position: TracePosition::new(i, 0),
            thread_id: 1,
            kind: EventKind::MemRead { addr: i, len: 1 },
        });
    }
    assert_eq!(rb.len(), 3);
    assert!(!rb.is_empty());
    let snap = rb.snapshot();
    assert_eq!(snap.len(), 3);
}

#[test]
fn ring_buffer_drops_oldest_when_full() {
    use rustre_ttd::{EventKind, TraceEvent, TracePosition};
    let rb = RingBufferRecorder::new(3);
    for i in 0..10u64 {
        rb.push(TraceEvent {
            position: TracePosition::new(i, 0),
            thread_id: 1,
            kind: EventKind::MemRead { addr: i, len: 1 },
        });
    }
    assert_eq!(rb.len(), 3);
    let snap = rb.snapshot();
    // The last 3 pushed (positions 7,8,9) should remain
    assert_eq!(snap[0].position.sequence, 7);
    assert_eq!(snap[2].position.sequence, 9);
}

#[test]
fn ring_buffer_clear() {
    use rustre_ttd::{EventKind, TraceEvent, TracePosition};
    let rb = RingBufferRecorder::new(8);
    rb.push(TraceEvent {
        position: TracePosition::new(0, 0),
        thread_id: 1,
        kind: EventKind::MemRead { addr: 0, len: 1 },
    });
    rb.clear();
    assert!(rb.is_empty());
}

// ─── RecordingSchedule ───────────────────────────────────────────────────────

#[test]
fn schedule_record_all_never_stops() {
    let s = RecordingSchedule::record_all();
    assert!(!s.should_stop(TtdPosition::new(u64::MAX, 0), std::time::Duration::from_secs(u64::MAX)));
}

#[test]
fn schedule_for_duration_stops_after_elapsed() {
    let s = RecordingSchedule::for_duration(5);
    assert!(!s.should_stop(TtdPosition::start(), std::time::Duration::from_secs(4)));
    assert!(s.should_stop(TtdPosition::start(), std::time::Duration::from_secs(5)));
    assert!(s.should_stop(TtdPosition::start(), std::time::Duration::from_secs(100)));
}

#[test]
fn schedule_stops_at_position() {
    let mut s = RecordingSchedule::record_all();
    s.stop_position = Some(TtdPosition::new(10, 0));
    assert!(!s.should_stop(TtdPosition::new(9, 0), std::time::Duration::from_secs(0)));
    assert!(s.should_stop(TtdPosition::new(10, 0), std::time::Duration::from_secs(0)));
    assert!(s.should_stop(TtdPosition::new(11, 0), std::time::Duration::from_secs(0)));
}

// ─── TraceFileInfo ───────────────────────────────────────────────────────────

#[test]
fn trace_file_info_valid_ext() {
    let i = TraceFileInfo::from_path("/x/y.run");
    assert!(i.valid);
    assert_eq!(i.version, 1);
    let j = TraceFileInfo::from_path("/x/y.bin");
    assert!(!j.valid);
}

// ─── TtdTraceHeader / TtdTraceFile ───────────────────────────────────────────

#[test]
fn ttd_header_validate_ok() {
    let h = TtdTraceHeader::new(42);
    assert!(h.validate().is_ok());
    assert_eq!(h.pid, 42);
    assert_eq!(h.version, TTD_VERSION);
}

#[test]
fn ttd_header_bad_magic_errs() {
    let mut h = TtdTraceHeader::new(1);
    h.magic = "WRONG".into();
    assert!(h.validate().is_err());
}

#[test]
fn ttd_header_bad_version_errs() {
    let mut h = TtdTraceHeader::new(1);
    h.version = TTD_VERSION + 1;
    assert!(h.validate().is_err());
}

#[test]
fn ttd_file_push_event_count() {
    let mut f = TtdTraceFile::new(7);
    assert_eq!(f.event_count(), 0);
    for i in 0..5 {
        f.push(SyscallEvent {
            instr_count: i,
            nr: 1,
            args: [0; 6],
            retval: 0,
            mem_writes: vec![],
        });
    }
    assert_eq!(f.event_count(), 5);
    assert_eq!(f.first_event().unwrap().instr_count, 0);
    assert_eq!(f.last_event().unwrap().instr_count, 4);
}

#[test]
fn ttd_file_unique_syscalls_sorted() {
    let mut f = TtdTraceFile::new(1);
    for nr in [3u32, 1, 2, 1, 3, 2, 4] {
        f.push(SyscallEvent {
            instr_count: 0,
            nr,
            args: [0; 6],
            retval: 0,
            mem_writes: vec![],
        });
    }
    assert_eq!(f.unique_syscalls(), vec![1, 2, 3, 4]);
}

#[test]
fn ttd_file_total_instructions_is_last() {
    let mut f = TtdTraceFile::new(1);
    assert_eq!(f.total_instructions(), 0);
    f.push(SyscallEvent {
        instr_count: 99,
        nr: 0,
        args: [0; 6],
        retval: 0,
        mem_writes: vec![],
    });
    assert_eq!(f.total_instructions(), 99);
}

#[test]
fn ttd_file_filter_by_nr() {
    let mut f = TtdTraceFile::new(1);
    for nr in [1u32, 2, 1, 3] {
        f.push(SyscallEvent {
            instr_count: 0,
            nr,
            args: [0; 6],
            retval: 0,
            mem_writes: vec![],
        });
    }
    assert_eq!(f.filter_by_nr(1).len(), 2);
    assert_eq!(f.filter_by_nr(2).len(), 1);
    assert_eq!(f.filter_by_nr(99).len(), 0);
}

// ─── SyscallRecord / CaptureReason / MemoryCapture ───────────────────────────

#[test]
fn syscall_record_errno_classification() {
    let mk = |rv: i64| SyscallRecord {
        instr_count: 0,
        syscall_nr: 1,
        args: [0; 6],
        return_value: rv,
        pre_memory_state: vec![],
        post_memory_writes: vec![],
    };
    assert!(mk(-1).is_error());
    assert_eq!(mk(-1).errno(), Some(1));
    assert!(mk(-4095).is_error());
    assert!(!mk(-4096).is_error()); // out of errno range
    assert!(!mk(0).is_error());
    assert!(!mk(42).is_error());
    assert_eq!(mk(0).errno(), None);
}

#[test]
fn syscall_record_byte_counts() {
    let r = SyscallRecord {
        instr_count: 0,
        syscall_nr: 1,
        args: [0; 6],
        return_value: 0,
        pre_memory_state: vec![
            MemoryCapture::new(0, vec![1, 2, 3], CaptureReason::ReturnBuffer),
            MemoryCapture::new(0, vec![4], CaptureReason::PageFaultData),
        ],
        post_memory_writes: vec![MemWrite {
            addr: 0,
            data: vec![5, 6],
        }],
    };
    assert_eq!(r.pre_capture_bytes(), 4);
    assert_eq!(r.post_write_bytes(), 2);
    assert!(r.summary().contains("syscall nr=1"));
}

#[test]
fn capture_reason_display() {
    assert_eq!(
        format!("{}", CaptureReason::SyscallArg { arg_index: 3 }),
        "arg[3]"
    );
    assert_eq!(format!("{}", CaptureReason::ReturnBuffer), "retbuf");
    assert_eq!(format!("{}", CaptureReason::PageFaultData), "pagefault");
}

#[test]
fn memory_capture_basics() {
    let mc = MemoryCapture::new(0x1000, vec![1, 2, 3, 4], CaptureReason::ReturnBuffer);
    assert_eq!(mc.len(), 4);
    assert!(!mc.is_empty());
    assert_eq!(mc.end_address(), 0x1004);
    assert!(mc.contains(0x1000));
    assert!(mc.contains(0x1003));
    assert!(!mc.contains(0x1004));
    assert!(!mc.contains(0x0FFF));
    assert_eq!(mc.byte_at(0x1002), Some(3));
    assert_eq!(mc.byte_at(0x2000), None);
}

#[test]
fn memory_capture_empty() {
    let mc = MemoryCapture::new(0, vec![], CaptureReason::ReturnBuffer);
    assert!(mc.is_empty());
    assert_eq!(mc.end_address(), 0);
    assert!(!mc.contains(0));
}

// ─── RecordingStats ──────────────────────────────────────────────────────────

#[test]
fn recording_stats_from_trace_thread_counts() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let r = InProcessRecorder;
        let mut cfg = RecorderConfig::default();
        cfg.max_events = Some(12);
        let sess = r.start(cfg).await.unwrap();
        let trace = r.stop(sess).await.unwrap();
        let stats = RecordingStats::from_trace(&trace, 1.5);
        assert_eq!(stats.total_events, 12);
        assert_eq!(stats.duration_secs, 1.5);
        let total: u64 = stats.events_per_thread.values().sum();
        assert_eq!(total, 12);
        let hot = stats.hottest_thread();
        assert!(hot.is_some());
    });
}

#[test]
fn recording_stats_empty_hottest_none() {
    let s = RecordingStats::default();
    assert_eq!(s.hottest_thread(), None);
}

// ─── Send+Sync threaded stress ───────────────────────────────────────────────

#[test]
fn ring_buffer_send_sync_stress() {
    use rustre_ttd::{EventKind, TraceEvent, TracePosition};
    let rb = Arc::new(RingBufferRecorder::new(256));
    let mut handles = vec![];
    for t in 0..4u32 {
        let rb2 = Arc::clone(&rb);
        handles.push(std::thread::spawn(move || {
            for i in 0..100u64 {
                rb2.push(TraceEvent {
                    position: TracePosition::new(i, 0),
                    thread_id: t,
                    kind: EventKind::MemRead {
                        addr: i,
                        len: 1,
                    },
                });
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    // capacity bounded
    assert!(rb.len() <= 256);
}

#[test]
fn encryptor_send_sync_stress() {
    let enc = Arc::new(TtdRecordEncryptor::new(vec![0x77; 32]).unwrap());
    let mut handles = vec![];
    for _ in 0..4 {
        let e = Arc::clone(&enc);
        handles.push(std::thread::spawn(move || {
            for i in 0..100u32 {
                let msg = i.to_le_bytes();
                let ct = e.encrypt(&msg).unwrap();
                let pt = e.decrypt(&ct).unwrap();
                assert_eq!(pt, msg);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ─── check_platform_support ──────────────────────────────────────────────────

#[test]
fn check_platform_support_runs() {
    // Just exercise it; result depends on OS.
    let _ = check_platform_support();
}

// ─── TtdRecordError From CoreError sanity ────────────────────────────────────

#[test]
fn error_display_smoke() {
    let e = TtdRecordError::ProcessNotFound;
    assert!(format!("{e}").contains("process"));
    let e = TtdRecordError::NotAvailable;
    assert!(!format!("{e}").is_empty());
    let e = TtdRecordError::OutputPathError("bad".into());
    assert!(format!("{e}").contains("bad"));
}
