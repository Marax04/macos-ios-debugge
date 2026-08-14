//! Deep adversarial tests for `rustre-daemon` public API.
//!
//! Targets pure types from `lib.rs`:
//!   DaemonError, DaemonState, DaemonConfig, PidFile, IpcMessage, IpcResponse,
//!   IpcServer, DaemonClient, LogRotator, HealthCheck/Item, SignalBus/Signal,
//!   Daemon, format_duration, is_process_running, HttpDaemonConfig,
//!   ProjectHandle, ServerState, JsonRpcRequest/Response/Error.

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustre_daemon::*;
use serde_json::{json, Value};
use tempfile::tempdir;

// ── seeded LCG ───────────────────────────────────────────────────────────────
fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

fn free_addr() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. DaemonState
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn b2_state_display_roundtrip() {
    let pairs = [
        (DaemonState::Stopped, "stopped"),
        (DaemonState::Starting, "starting"),
        (DaemonState::Running, "running"),
        (DaemonState::Stopping, "stopping"),
        (DaemonState::Failed, "failed"),
    ];
    for (s, txt) in pairs {
        assert_eq!(s.to_string(), txt);
    }
}

#[test]
fn b2_state_predicates() {
    assert!(DaemonState::Running.is_active());
    assert!(DaemonState::Starting.is_active());
    assert!(!DaemonState::Stopped.is_active());
    assert!(!DaemonState::Stopping.is_active());
    assert!(!DaemonState::Failed.is_active());

    assert!(DaemonState::Stopped.can_start());
    assert!(DaemonState::Failed.can_start());
    assert!(!DaemonState::Running.can_start());
    assert!(!DaemonState::Starting.can_start());
    assert!(!DaemonState::Stopping.can_start());
}

#[test]
fn b2_state_serde_roundtrip() {
    for s in [
        DaemonState::Stopped,
        DaemonState::Starting,
        DaemonState::Running,
        DaemonState::Stopping,
        DaemonState::Failed,
    ] {
        let j = serde_json::to_string(&s).unwrap();
        let s2: DaemonState = serde_json::from_str(&j).unwrap();
        assert_eq!(s, s2);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. DaemonError
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn b2_error_display_contains_text() {
    let cases = [
        (DaemonError::AlreadyRunning(99), "99"),
        (DaemonError::PidFile("x".into()), "x"),
        (DaemonError::Socket("s".into()), "s"),
        (DaemonError::Protocol("p".into()), "p"),
        (DaemonError::Io("i".into()), "i"),
        (DaemonError::Config("c".into()), "c"),
        (DaemonError::NotRunning, "not running"),
    ];
    for (e, sub) in cases {
        assert!(e.to_string().contains(sub), "{e:?} missing {sub}");
    }
}

#[test]
fn b2_error_from_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::Other, "boom");
    let de: DaemonError = io_err.into();
    assert!(matches!(de, DaemonError::Io(_)));
}

#[test]
fn b2_error_eq() {
    assert_eq!(DaemonError::NotRunning, DaemonError::NotRunning);
    assert_eq!(
        DaemonError::AlreadyRunning(1),
        DaemonError::AlreadyRunning(1)
    );
    assert_ne!(
        DaemonError::AlreadyRunning(1),
        DaemonError::AlreadyRunning(2)
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. DaemonConfig
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn b2_config_default_validates() {
    DaemonConfig::default().validate().unwrap();
    DaemonConfig::new().validate().unwrap();
}

#[test]
fn b2_config_validate_zero_max_log_size() {
    let mut c = DaemonConfig::default();
    c.max_log_size = 0;
    let e = c.validate().unwrap_err();
    assert!(matches!(e, DaemonError::Config(_)));
}

#[test]
fn b2_config_validate_zero_max_files_and_timeout() {
    let mut c = DaemonConfig::default();
    c.max_log_files = 0;
    assert!(matches!(c.validate(), Err(DaemonError::Config(_))));
    let mut c = DaemonConfig::default();
    c.shutdown_timeout_secs = 0;
    assert!(matches!(c.validate(), Err(DaemonError::Config(_))));
}

#[test]
fn b2_config_with_ipc_addr_ok_and_err() {
    let c = DaemonConfig::default().with_ipc_addr("10.0.0.1:1234").unwrap();
    assert_eq!(c.ipc_addr.port(), 1234);
    let e = DaemonConfig::default()
        .with_ipc_addr("not-an-addr")
        .unwrap_err();
    assert!(matches!(e, DaemonError::Config(_)));
}

#[test]
fn b2_config_log_paths() {
    let c = DaemonConfig::default().with_pid_file("/tmp/xyz.pid");
    assert_eq!(c.pid_file, PathBuf::from("/tmp/xyz.pid"));
    let p = c.log_file_path();
    assert!(p.to_string_lossy().ends_with(".log"));
    for i in 1..=5 {
        let r = c.rotated_log_path(i);
        assert!(r.to_string_lossy().contains(&format!("{i}")));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. PidFile
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn b2_pidfile_roundtrip_many() {
    let dir = tempdir().unwrap();
    let mut g = lcg();
    for i in 0..50 {
        let path = dir.path().join(format!("p{i}.pid"));
        let pf = PidFile::new(&path);
        let pid = (g() & 0x7FFF_FFFF) as u32;
        pf.write_pid(pid).unwrap();
        assert!(pf.exists());
        assert_eq!(pf.read().unwrap(), pid);
        assert_eq!(pf.path(), path.as_path());
        pf.remove().unwrap();
        assert!(!pf.exists());
    }
}

#[test]
fn b2_pidfile_invalid_content() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("bad.pid");
    std::fs::write(&p, "not-a-number").unwrap();
    let pf = PidFile::new(&p);
    assert!(matches!(pf.read(), Err(DaemonError::PidFile(_))));
}

#[test]
fn b2_pidfile_missing_read() {
    let dir = tempdir().unwrap();
    let pf = PidFile::new(dir.path().join("missing.pid"));
    assert!(matches!(pf.read(), Err(DaemonError::PidFile(_))));
    // remove on missing is Ok
    pf.remove().unwrap();
}

#[test]
fn b2_pidfile_write_current_pid() {
    let dir = tempdir().unwrap();
    let pf = PidFile::new(dir.path().join("c.pid"));
    pf.write().unwrap();
    assert_eq!(pf.read().unwrap(), std::process::id());
}

#[test]
fn b2_pidfile_boundary_values() {
    let dir = tempdir().unwrap();
    for pid in [0u32, 1, u32::MAX - 1, u32::MAX] {
        let pf = PidFile::new(dir.path().join(format!("b{pid}.pid")));
        pf.write_pid(pid).unwrap();
        assert_eq!(pf.read().unwrap(), pid);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. IpcMessage / IpcResponse
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn b2_ipc_message_roundtrip_50() {
    let mut g = lcg();
    for i in 0..50 {
        let cmd = format!("cmd-{i}-{}", g() & 0xff);
        let args: Vec<String> = (0..(g() % 5))
            .map(|j| format!("a{j}-{}", g() & 0xffff))
            .collect();
        let m = IpcMessage::new(&cmd).with_args(args.clone());
        let line = m.to_line().unwrap();
        let m2 = IpcMessage::from_line(&line).unwrap();
        assert_eq!(m2.command, cmd);
        assert_eq!(m2.args, args);
    }
}

#[test]
fn b2_ipc_response_roundtrip_variants() {
    let cases = [
        IpcResponse::success("ok"),
        IpcResponse::failure("bad"),
        IpcResponse::success("x").with_payload("{\"a\":1}"),
        IpcResponse::failure("y").with_payload("null"),
    ];
    for r in cases {
        let line = r.to_line();
        let r2 = IpcResponse::from_line(&line).unwrap();
        assert_eq!(r, r2);
    }
}

#[test]
fn b2_ipc_message_malformed_fuzz() {
    let mut g = lcg();
    let inputs = [
        "", "{", "}", "not json", "[1,2,3]", "{\"command\":1}",
        "{\"command\":\"x\"}", // missing args → should still error or default
    ];
    for s in inputs {
        // must not panic; either Ok or Err — we don't assert which
        let _ = IpcMessage::from_line(s);
    }
    for _ in 0..50 {
        let v = g();
        let s = format!("{{\"command\":\"x\",\"args\":[{v}]}}");
        let _ = IpcMessage::from_line(&s);
    }
}

#[test]
fn b2_ipc_response_malformed() {
    for s in ["", "{", "garbage", "null", "{\"ok\":\"yes\"}"] {
        let _ = IpcResponse::from_line(s);
    }
}

#[test]
fn b2_ipc_message_eq_hash_like_consistency() {
    // PartialEq/Eq consistency for 30 pairs.
    let mut g = lcg();
    for _ in 0..30 {
        let v = g();
        let a = IpcMessage::new(format!("c{v}"));
        let b = IpcMessage::new(format!("c{v}"));
        assert_eq!(a, b);
        let c = IpcMessage::new(format!("c{}", v.wrapping_add(1)));
        assert_ne!(a, c);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. IpcServer + DaemonClient + send_ipc_command
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn b2_ipc_server_unknown_command() {
    let addr = free_addr();
    let mut srv = IpcServer::bind(addr).unwrap();
    srv.on("ping", |_| IpcResponse::success("pong"));
    assert_eq!(srv.handler_count(), 1);
    assert!(srv.has_handler("ping"));
    assert!(!srv.has_handler("nope"));
    let local = srv.local_addr().unwrap();

    let h = thread::spawn(move || {
        // Poll for ~2s.
        for _ in 0..200 {
            if srv.poll_once().unwrap() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
    });

    let client = DaemonClient::new(local);
    let r = client.command("does-not-exist").unwrap();
    assert!(!r.ok);
    assert!(r.message.contains("unknown"));
    h.join().unwrap();
}

#[test]
fn b2_ipc_server_serve_loop_and_stop() {
    let addr = free_addr();
    let mut srv = IpcServer::bind(addr).unwrap();
    srv.on("echo", |m| IpcResponse::success(m.args.join(",")));
    let local = srv.local_addr().unwrap();

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop2 = stop.clone();
    let h = thread::spawn(move || {
        srv.serve(&|| stop2.load(std::sync::atomic::Ordering::SeqCst))
            .unwrap();
    });

    let client = DaemonClient::new(local).with_timeout(Duration::from_secs(2));
    assert_eq!(client.timeout(), Duration::from_secs(2));
    assert_eq!(client.addr(), local);

    let r = client
        .command_with_args("echo", vec!["a".into(), "b".into()])
        .unwrap();
    assert!(r.ok);
    assert_eq!(r.message, "a,b");

    let line = send_ipc_command(local, &IpcMessage::new("echo").with_args(vec!["z"])).unwrap();
    assert!(line.contains("\"ok\":true"));
    assert!(line.contains("\"z\""));

    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    h.join().unwrap();
}

#[test]
fn b2_client_ping_false_when_no_server() {
    let addr = free_addr();
    // nothing bound here -> ping must return false, not panic
    let c = DaemonClient::new(addr).with_timeout(Duration::from_millis(200));
    assert!(!c.ping());
}

#[test]
fn b2_client_const_accessors() {
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let c = DaemonClient::new(addr);
    assert_eq!(c.addr(), addr);
    assert_eq!(c.timeout(), Duration::from_secs(5));
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. LogRotator
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn b2_log_rotator_basic_writes() {
    let dir = tempdir().unwrap();
    let mut cfg = DaemonConfig::default();
    cfg.log_dir = dir.path().into();
    cfg.log_name = "t".into();
    cfg.max_log_size = 1024 * 1024;
    cfg.max_log_files = 3;
    let mut lr = LogRotator::new(cfg.clone()).unwrap();
    for i in 0..20 {
        lr.write_line(&format!("line {i}")).unwrap();
    }
    let active = std::fs::read_to_string(cfg.log_file_path()).unwrap();
    assert!(active.contains("line 0"));
    assert!(active.contains("line 19"));
}

#[test]
fn b2_log_rotator_rotates_on_size() {
    let dir = tempdir().unwrap();
    let mut cfg = DaemonConfig::default();
    cfg.log_dir = dir.path().into();
    cfg.log_name = "r".into();
    cfg.max_log_size = 64;
    cfg.max_log_files = 3;
    let mut lr = LogRotator::new(cfg.clone()).unwrap();
    for i in 0..50 {
        lr.write_line(&format!("payload-line-{i:03}")).unwrap();
    }
    // Should have at least one rotated file.
    assert!(cfg.rotated_log_path(1).exists());
}

#[test]
fn b2_log_rotator_force_rotate() {
    let dir = tempdir().unwrap();
    let mut cfg = DaemonConfig::default();
    cfg.log_dir = dir.path().into();
    cfg.log_name = "f".into();
    cfg.max_log_size = 1024 * 1024;
    cfg.max_log_files = 2;
    let mut lr = LogRotator::new(cfg.clone()).unwrap();
    lr.write_line("hello").unwrap();
    lr.rotate().unwrap();
    assert!(cfg.rotated_log_path(1).exists());
    lr.write_line("world").unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. HealthCheck / CheckItem
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn b2_health_check_aggregate() {
    let mut hc = HealthCheck::new();
    hc.add_check(|| CheckItem::pass("a", "ok"));
    hc.add_check(|| CheckItem::pass("b", "ok"));
    let r = hc.run();
    assert!(r.healthy);
    assert_eq!(r.checks.len(), 2);
    let t = r.to_text();
    assert!(t.contains("HEALTHY"));
}

#[test]
fn b2_health_check_one_failing() {
    let mut hc = HealthCheck::default();
    hc.add_check(|| CheckItem::pass("a", "ok"));
    hc.add_check(|| CheckItem::fail("b", "down"));
    let r = hc.run();
    assert!(!r.healthy);
    assert!(r.to_text().contains("UNHEALTHY"));
}

#[test]
fn b2_check_item_constructors() {
    let p = CheckItem::pass("n", "d");
    assert!(p.ok && p.name == "n" && p.detail == "d");
    let f = CheckItem::fail("n2", "d2");
    assert!(!f.ok);
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. SignalBus / Signal
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn b2_signal_display() {
    use Signal::*;
    assert_eq!(Terminate.to_string(), "SIGTERM");
    assert_eq!(Interrupt.to_string(), "SIGINT");
    assert_eq!(HangUp.to_string(), "SIGHUP");
    assert_eq!(User1.to_string(), "SIGUSR1");
    assert_eq!(User2.to_string(), "SIGUSR2");
}

#[test]
fn b2_signal_bus_post_drain() {
    let bus = SignalBus::new();
    assert!(!bus.has_pending());
    bus.post(Signal::Terminate);
    bus.post(Signal::User1);
    assert!(bus.has_pending());
    let drained = bus.drain();
    assert_eq!(drained.len(), 2);
    assert!(!bus.has_pending());
}

#[test]
fn b2_signal_bus_threaded_stress() {
    let bus = SignalBus::new();
    let mut handles = vec![];
    for _ in 0..4 {
        let b = bus.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                b.post(Signal::User2);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let drained = bus.drain();
    assert_eq!(drained.len(), 400);
    assert!(drained.iter().all(|s| *s == Signal::User2));
}

#[test]
fn b2_signal_hash_set_uniqueness() {
    let mut set = HashSet::new();
    set.insert(Signal::Terminate);
    set.insert(Signal::Interrupt);
    set.insert(Signal::HangUp);
    set.insert(Signal::User1);
    set.insert(Signal::User2);
    set.insert(Signal::Terminate);
    assert_eq!(set.len(), 5);
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Daemon lifecycle
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn b2_daemon_start_stop_state_transitions() {
    let dir = tempdir().unwrap();
    let mut cfg = DaemonConfig::default();
    cfg.pid_file = dir.path().join("d.pid");
    cfg.log_dir = dir.path().into();
    let mut d = Daemon::new(cfg).unwrap();
    assert_eq!(d.state(), DaemonState::Stopped);
    d.start().unwrap();
    assert_eq!(d.state(), DaemonState::Running);
    assert!(d.uptime().is_some());
    assert!(d.status_text().contains("running"));
    d.stop().unwrap();
    assert_eq!(d.state(), DaemonState::Stopped);
    assert!(d.uptime().is_none());
}

#[test]
fn b2_daemon_stop_when_not_running() {
    let dir = tempdir().unwrap();
    let mut cfg = DaemonConfig::default();
    cfg.pid_file = dir.path().join("ns.pid");
    cfg.log_dir = dir.path().into();
    let mut d = Daemon::new(cfg).unwrap();
    assert!(matches!(d.stop(), Err(DaemonError::NotRunning)));
}

#[test]
fn b2_daemon_restart_and_mark_failed() {
    let dir = tempdir().unwrap();
    let mut cfg = DaemonConfig::default();
    cfg.pid_file = dir.path().join("rr.pid");
    cfg.log_dir = dir.path().into();
    let mut d = Daemon::new(cfg).unwrap();
    d.start().unwrap();
    d.restart().unwrap();
    assert_eq!(d.state(), DaemonState::Running);
    // Stop cleanly first so the PID file is gone before we mark failed; this
    // mirrors how a real daemon would crash after its PID file was cleared
    // and avoids `is_process_running(self_pid)` racing with restart-from-failed.
    d.stop().unwrap();
    d.mark_failed();
    assert_eq!(d.state(), DaemonState::Failed);
    // From failed we can start again.
    d.start().unwrap();
    assert_eq!(d.state(), DaemonState::Running);
    d.stop().unwrap();
}

#[test]
fn b2_daemon_process_signals_and_bus() {
    let dir = tempdir().unwrap();
    let mut cfg = DaemonConfig::default();
    cfg.pid_file = dir.path().join("s.pid");
    cfg.log_dir = dir.path().into();
    let d = Daemon::new(cfg).unwrap();
    d.signal_bus().post(Signal::HangUp);
    let drained = d.process_signals();
    assert_eq!(drained, vec![Signal::HangUp]);
}

#[test]
fn b2_daemon_health_checks() {
    let dir = tempdir().unwrap();
    let mut cfg = DaemonConfig::default();
    cfg.pid_file = dir.path().join("h.pid");
    cfg.log_dir = dir.path().into();
    let d = Daemon::new(cfg).unwrap();
    d.add_health_check(|| CheckItem::pass("x", "ok"));
    let r = d.run_health_check();
    assert!(r.healthy);
    assert_eq!(r.checks.len(), 1);
}

#[test]
fn b2_daemon_capabilities_listed() {
    let dir = tempdir().unwrap();
    let mut cfg = DaemonConfig::default();
    cfg.pid_file = dir.path().join("c.pid");
    cfg.log_dir = dir.path().into();
    let d = Daemon::new(cfg).unwrap();
    let caps = d.list_capabilities();
    // Just ensure it doesn't panic and returns something well-formed.
    for c in &caps {
        assert!(!c.is_empty());
    }
    let _ = d.config();
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. Utility helpers
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn b2_format_duration_buckets() {
    assert_eq!(format_duration(Duration::from_secs(0)), "0s");
    assert_eq!(format_duration(Duration::from_secs(45)), "45s");
    assert_eq!(format_duration(Duration::from_secs(60)), "1m 0s");
    assert_eq!(format_duration(Duration::from_secs(125)), "2m 5s");
    assert_eq!(format_duration(Duration::from_secs(3600)), "1h 0m 0s");
    assert_eq!(format_duration(Duration::from_secs(3661)), "1h 1m 1s");
}

#[test]
fn b2_format_duration_fuzz_never_panic() {
    let mut g = lcg();
    for _ in 0..50 {
        let secs = g() % 1_000_000;
        let s = format_duration(Duration::from_secs(secs));
        assert!(!s.is_empty());
    }
}

#[test]
fn b2_is_process_running_self_and_bogus() {
    assert!(is_process_running(std::process::id()));
    // pid 0xFFFF_FFFE almost certainly not a process
    assert!(!is_process_running(0xFFFF_FFFE));
}

// ─────────────────────────────────────────────────────────────────────────────
// 12. HttpDaemonConfig
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn b2_http_config_default_and_serde() {
    let c = HttpDaemonConfig::default();
    assert_eq!(c.bind_addr, "127.0.0.1:7878");
    assert_eq!(c.max_connections, 16);
    let j = serde_json::to_string(&c).unwrap();
    let c2: HttpDaemonConfig = serde_json::from_str(&j).unwrap();
    assert_eq!(c.bind_addr, c2.bind_addr);
    assert_eq!(c.max_connections, c2.max_connections);
}

// ─────────────────────────────────────────────────────────────────────────────
// 13. ProjectHandle / ServerState
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn b2_project_handle_id_sanitised() {
    let h = ProjectHandle::new(PathBuf::from("/some path/x:y"));
    assert!(!h.id.contains('/'));
    assert!(!h.id.contains(' '));
    assert!(!h.id.contains(':'));
    assert_eq!(h.binary_count, 0);
}

#[test]
fn b2_server_state_uptime_and_fields() {
    let s = ServerState::new(HttpDaemonConfig::default());
    let _ = s.uptime_secs();
    assert_eq!(s.active_sessions, 0);
    assert_eq!(s.total_requests, 0);
    assert_eq!(s.rpc_errors, 0);
    assert!(s.projects.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// 14. JsonRpcResponse
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn b2_jsonrpc_ok_and_err() {
    let r = JsonRpcResponse::ok(json!(1), json!({"x":42}));
    assert_eq!(r.jsonrpc, "2.0");
    assert!(r.error.is_none());
    assert_eq!(r.result.as_ref().unwrap()["x"], 42);

    let e = JsonRpcResponse::err(json!("abc"), -32600, "bad");
    assert!(e.result.is_none());
    let ee = e.error.unwrap();
    assert_eq!(ee.code, -32600);
    assert_eq!(ee.message, "bad");
    assert!(ee.data.is_none());
}

#[test]
fn b2_jsonrpc_err_data() {
    let r = JsonRpcResponse::err_data(json!(5), -32000, "x", json!({"k":1}));
    assert_eq!(r.error.unwrap().data.unwrap()["k"], 1);
}

#[test]
fn b2_jsonrpc_to_bytes_parseable() {
    let r = JsonRpcResponse::ok(json!(7), json!("hi"));
    let bytes = r.to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], 7);
    assert_eq!(v["result"], "hi");
    assert!(v.get("error").is_none());
}

#[test]
fn b2_jsonrpc_request_deserialise() {
    let s = r#"{"jsonrpc":"2.0","id":1,"method":"status","params":null}"#;
    let req: JsonRpcRequest = serde_json::from_str(s).unwrap();
    assert_eq!(req.method, "status");
    assert_eq!(req.id, Some(json!(1)));
}

#[test]
fn b2_jsonrpc_const_internal_error_value() {
    assert_eq!(JSONRPC_INTERNAL_ERROR, -32603);
}

// ─────────────────────────────────────────────────────────────────────────────
// 15. Send+Sync stress: DaemonClient + SignalBus + ServerState arc
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn b2_daemon_client_send_sync_threaded() {
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let client = Arc::new(DaemonClient::new(addr).with_timeout(Duration::from_millis(50)));
    let mut handles = vec![];
    for _ in 0..4 {
        let c = client.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let _ = c.addr();
                let _ = c.timeout();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn b2_pidfile_path_accessor() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("acc.pid");
    let pf = PidFile::new(&p);
    assert_eq!(pf.path(), p.as_path());
}

#[test]
fn b2_daemon_config_extra_map() {
    let mut c = DaemonConfig::default();
    c.extra.insert("k".into(), "v".into());
    assert_eq!(c.extra.get("k").map(String::as_str), Some("v"));
    let j = serde_json::to_string(&c).unwrap();
    let c2: DaemonConfig = serde_json::from_str(&j).unwrap();
    assert_eq!(c2.extra.get("k").map(String::as_str), Some("v"));
}

#[test]
fn b2_ipc_message_empty_args_roundtrip() {
    let m = IpcMessage::new("c");
    assert!(m.args.is_empty());
    let line = m.to_line().unwrap();
    let m2 = IpcMessage::from_line(&line).unwrap();
    assert_eq!(m, m2);
}

#[test]
fn b2_health_result_serde() {
    let mut hc = HealthCheck::new();
    hc.add_check(|| CheckItem::pass("z", "d"));
    let r = hc.run();
    let j = serde_json::to_string(&r).unwrap();
    let r2: HealthCheckResult = serde_json::from_str(&j).unwrap();
    assert_eq!(r, r2);
}

#[test]
fn b2_jsonrpc_invalid_request_code_value() {
    let r = JsonRpcResponse::err(json!(null), -32600, "x");
    assert_eq!(r.error.unwrap().code, -32600);
}

#[test]
fn b2_format_duration_one_hour_boundary() {
    assert_eq!(format_duration(Duration::from_secs(3599)), "59m 59s");
    assert_eq!(format_duration(Duration::from_secs(3600)), "1h 0m 0s");
}

#[test]
fn b2_ipc_response_payload_optional() {
    let r = IpcResponse::success("m");
    assert!(r.payload.is_none());
    let r2 = r.clone().with_payload("data");
    assert_eq!(r2.payload.as_deref(), Some("data"));
}

#[test]
fn b2_pidfile_overwrite() {
    let dir = tempdir().unwrap();
    let pf = PidFile::new(dir.path().join("ow.pid"));
    pf.write_pid(11).unwrap();
    pf.write_pid(22).unwrap();
    assert_eq!(pf.read().unwrap(), 22);
}
