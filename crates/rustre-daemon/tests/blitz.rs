//! Exhaustive black-box tests for `rustre-daemon`.
//!
//! Focuses on pure public API exposed via `lib.rs`:
//!   - DaemonError / DaemonState
//!   - DaemonConfig (builder, validation, paths)
//!   - PidFile (write/read/exists/remove)
//!   - IpcMessage / IpcResponse (round-trip, malformed)
//!   - IpcServer (bind, handler registration, poll, serve loop via client)
//!   - DaemonClient (request/command/ping)
//!   - send_ipc_command
//!   - LogRotator (write, rotation)
//!   - HealthCheck (register, run)
//!   - SignalBus, Signal
//!   - Daemon (start/stop/restart, state transitions)
//!   - format_duration, is_process_running
//!   - HttpDaemonConfig, ProjectHandle, ServerState
//!   - JsonRpcRequest/Response/Error

use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustre_daemon::*;
use serde_json::{json, Value};
use tempfile::tempdir;

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

fn free_addr() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap()
}

// ─────────────────────────────────────────────────────────────────────────────
// DaemonError + DaemonState
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn daemon_error_from_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::Other, "boom");
    let de: DaemonError = io_err.into();
    matches!(de, DaemonError::Io(_));
}

#[test]
fn daemon_error_display_messages() {
    assert_eq!(
        DaemonError::AlreadyRunning(42).to_string(),
        "daemon already running (pid 42)"
    );
    assert_eq!(DaemonError::NotRunning.to_string(), "daemon is not running");
    assert!(DaemonError::PidFile("x".into()).to_string().contains("pid file"));
    assert!(DaemonError::Socket("x".into()).to_string().contains("socket"));
    assert!(DaemonError::Protocol("x".into()).to_string().contains("ipc"));
    assert!(DaemonError::Config("x".into()).to_string().contains("config"));
    assert!(DaemonError::Io("x".into()).to_string().contains("i/o"));
}

#[test]
fn daemon_error_eq_and_clone() {
    let a = DaemonError::AlreadyRunning(1);
    let b = a.clone();
    assert_eq!(a, b);
    assert_ne!(a, DaemonError::AlreadyRunning(2));
    assert_ne!(a, DaemonError::NotRunning);
}

#[test]
fn daemon_state_display_all_variants() {
    assert_eq!(DaemonState::Stopped.to_string(), "stopped");
    assert_eq!(DaemonState::Starting.to_string(), "starting");
    assert_eq!(DaemonState::Running.to_string(), "running");
    assert_eq!(DaemonState::Stopping.to_string(), "stopping");
    assert_eq!(DaemonState::Failed.to_string(), "failed");
}

#[test]
fn daemon_state_is_active_truth_table() {
    assert!(!DaemonState::Stopped.is_active());
    assert!(DaemonState::Starting.is_active());
    assert!(DaemonState::Running.is_active());
    assert!(!DaemonState::Stopping.is_active());
    assert!(!DaemonState::Failed.is_active());
}

#[test]
fn daemon_state_can_start_truth_table() {
    assert!(DaemonState::Stopped.can_start());
    assert!(!DaemonState::Starting.can_start());
    assert!(!DaemonState::Running.can_start());
    assert!(!DaemonState::Stopping.can_start());
    assert!(DaemonState::Failed.can_start());
}

#[test]
fn daemon_state_serde_round_trip() {
    for s in [
        DaemonState::Stopped,
        DaemonState::Starting,
        DaemonState::Running,
        DaemonState::Stopping,
        DaemonState::Failed,
    ] {
        let j = serde_json::to_string(&s).unwrap();
        let back: DaemonState = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DaemonConfig
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn daemon_config_defaults_are_valid() {
    let c = DaemonConfig::new();
    c.validate().unwrap();
    assert_eq!(c.max_log_files, 5);
    assert_eq!(c.max_log_size, 10 * 1024 * 1024);
}

#[test]
fn daemon_config_with_pid_file() {
    let c = DaemonConfig::new().with_pid_file("/tmp/foo.pid");
    assert_eq!(c.pid_file, PathBuf::from("/tmp/foo.pid"));
}

#[test]
fn daemon_config_with_ipc_addr_ok() {
    let c = DaemonConfig::new().with_ipc_addr("127.0.0.1:1234").unwrap();
    assert_eq!(c.ipc_addr.port(), 1234);
}

#[test]
fn daemon_config_with_ipc_addr_bad() {
    let e = DaemonConfig::new().with_ipc_addr("not an addr").unwrap_err();
    matches!(e, DaemonError::Config(_));
}

#[test]
fn daemon_config_validate_zero_log_size() {
    let mut c = DaemonConfig::new();
    c.max_log_size = 0;
    assert!(matches!(c.validate(), Err(DaemonError::Config(_))));
}

#[test]
fn daemon_config_validate_zero_log_files() {
    let mut c = DaemonConfig::new();
    c.max_log_files = 0;
    assert!(matches!(c.validate(), Err(DaemonError::Config(_))));
}

#[test]
fn daemon_config_validate_zero_shutdown_timeout() {
    let mut c = DaemonConfig::new();
    c.shutdown_timeout_secs = 0;
    assert!(matches!(c.validate(), Err(DaemonError::Config(_))));
}

#[test]
fn daemon_config_log_paths() {
    let mut c = DaemonConfig::new();
    c.log_dir = PathBuf::from("/var/logs");
    c.log_name = "app".into();
    assert_eq!(c.log_file_path(), PathBuf::from("/var/logs/app.log"));
    assert_eq!(c.rotated_log_path(2), PathBuf::from("/var/logs/app.2.log"));
}

#[test]
fn daemon_config_extra_map() {
    let mut c = DaemonConfig::new();
    c.extra.insert("k".into(), "v".into());
    let s = serde_json::to_string(&c).unwrap();
    let back: DaemonConfig = serde_json::from_str(&s).unwrap();
    assert_eq!(back.extra.get("k").map(String::as_str), Some("v"));
}

// ─────────────────────────────────────────────────────────────────────────────
// PidFile
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pidfile_write_read_remove() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("nested/dir/x.pid");
    let pf = PidFile::new(&p);
    assert!(!pf.exists());
    pf.write_pid(12345).unwrap();
    assert!(pf.exists());
    assert_eq!(pf.read().unwrap(), 12345);
    pf.remove().unwrap();
    assert!(!pf.exists());
}

#[test]
fn pidfile_remove_when_absent_is_ok() {
    let dir = tempdir().unwrap();
    let pf = PidFile::new(dir.path().join("nope.pid"));
    pf.remove().unwrap();
}

#[test]
fn pidfile_read_missing_returns_pidfile_err() {
    let dir = tempdir().unwrap();
    let pf = PidFile::new(dir.path().join("missing.pid"));
    assert!(matches!(pf.read(), Err(DaemonError::PidFile(_))));
}

#[test]
fn pidfile_read_invalid_content() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("bad.pid");
    std::fs::write(&p, "not-a-number").unwrap();
    let pf = PidFile::new(&p);
    assert!(matches!(pf.read(), Err(DaemonError::PidFile(_))));
}

#[test]
fn pidfile_path_getter() {
    let pf = PidFile::new("/tmp/x.pid");
    assert_eq!(pf.path(), std::path::Path::new("/tmp/x.pid"));
}

#[test]
fn pidfile_write_current_process() {
    let dir = tempdir().unwrap();
    let pf = PidFile::new(dir.path().join("self.pid"));
    pf.write().unwrap();
    assert_eq!(pf.read().unwrap(), std::process::id());
}

// ─────────────────────────────────────────────────────────────────────────────
// IpcMessage / IpcResponse
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ipcmessage_new_and_args() {
    let m = IpcMessage::new("status");
    assert_eq!(m.command, "status");
    assert!(m.args.is_empty());
    let m2 = IpcMessage::new("set").with_args(vec!["a".to_string(), "b".to_string()]);
    assert_eq!(m2.args, vec!["a".to_string(), "b".to_string()]);
}

#[test]
fn ipcmessage_round_trip() {
    let m = IpcMessage::new("cmd").with_args(vec!["x with spaces".to_string(), "\"quoted\"".to_string()]);
    let line = m.to_line().unwrap();
    let back = IpcMessage::from_line(&line).unwrap();
    assert_eq!(m, back);
}

#[test]
fn ipcmessage_from_line_with_trailing_newline() {
    let m = IpcMessage::new("ping");
    let line = format!("{}\n", m.to_line().unwrap());
    let back = IpcMessage::from_line(&line).unwrap();
    assert_eq!(back, m);
}

#[test]
fn ipcmessage_from_line_malformed() {
    assert!(matches!(
        IpcMessage::from_line("not json"),
        Err(DaemonError::Protocol(_))
    ));
    assert!(matches!(
        IpcMessage::from_line("{}"),
        Err(DaemonError::Protocol(_))
    ));
}

#[test]
fn ipcresponse_success_and_failure() {
    let s = IpcResponse::success("hi");
    assert!(s.ok);
    assert_eq!(s.message, "hi");
    assert!(s.payload.is_none());

    let f = IpcResponse::failure("oops");
    assert!(!f.ok);
    assert_eq!(f.message, "oops");
}

#[test]
fn ipcresponse_with_payload_round_trip() {
    let r = IpcResponse::success("ok").with_payload(r#"{"a":1}"#);
    let line = r.to_line();
    let back = IpcResponse::from_line(&line).unwrap();
    assert_eq!(back, r);
    assert_eq!(back.payload.as_deref(), Some(r#"{"a":1}"#));
}

#[test]
fn ipcresponse_from_line_malformed() {
    assert!(matches!(
        IpcResponse::from_line("garbage"),
        Err(DaemonError::Protocol(_))
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// IpcServer + DaemonClient + send_ipc_command
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ipc_server_registers_handlers() {
    let mut srv = IpcServer::bind(free_addr()).unwrap();
    assert_eq!(srv.handler_count(), 0);
    srv.on("ping", |_| IpcResponse::success("pong"));
    assert_eq!(srv.handler_count(), 1);
    assert!(srv.has_handler("ping"));
    assert!(!srv.has_handler("nope"));
}

#[test]
fn ipc_server_poll_once_no_clients() {
    let srv = IpcServer::bind(free_addr()).unwrap();
    assert!(!srv.poll_once().unwrap());
}

#[test]
fn ipc_server_local_addr() {
    let srv = IpcServer::bind(free_addr()).unwrap();
    let a = srv.local_addr().unwrap();
    assert_eq!(a.ip().to_string(), "127.0.0.1");
    assert!(a.port() > 0);
}

#[test]
fn ipc_server_serve_and_client_request() {
    let mut srv = IpcServer::bind(free_addr()).unwrap();
    let addr = srv.local_addr().unwrap();
    srv.on("echo", |m| IpcResponse::success(format!("got {} args", m.args.len())));
    srv.on("health", |_| IpcResponse::success("healthy"));

    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let handle = thread::spawn(move || {
        srv.serve(&|| stop2.load(Ordering::SeqCst)).unwrap();
    });

    // Give the server a beat to start its loop.
    thread::sleep(Duration::from_millis(50));

    let client = DaemonClient::new(addr).with_timeout(Duration::from_secs(2));
    assert_eq!(client.addr(), addr);
    assert_eq!(client.timeout(), Duration::from_secs(2));

    let resp = client
        .command_with_args("echo", vec!["a".into(), "b".into()])
        .unwrap();
    assert!(resp.ok);
    assert_eq!(resp.message, "got 2 args");

    assert!(client.ping());

    let bad = client.command("does-not-exist").unwrap();
    assert!(!bad.ok);
    assert!(bad.message.contains("unknown command"));

    // send_ipc_command free fn
    let line = send_ipc_command(addr, &IpcMessage::new("echo")).unwrap();
    let parsed = IpcResponse::from_line(&line).unwrap();
    assert!(parsed.ok);

    stop.store(true, Ordering::SeqCst);
    handle.join().unwrap();
}

#[test]
fn daemon_client_ping_fails_on_dead_addr() {
    // Reserve and release to get a likely-unused port.
    let addr = free_addr();
    let client = DaemonClient::new(addr).with_timeout(Duration::from_millis(200));
    assert!(!client.ping());
}

// ─────────────────────────────────────────────────────────────────────────────
// LogRotator
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn log_rotator_writes_then_rotates() {
    let dir = tempdir().unwrap();
    let mut cfg = DaemonConfig::new();
    cfg.log_dir = dir.path().to_path_buf();
    cfg.log_name = "t".into();
    cfg.max_log_size = 32;
    cfg.max_log_files = 3;

    let mut r = LogRotator::new(cfg.clone()).unwrap();
    for i in 0..20 {
        r.write_line(&format!("line-{i:04}")).unwrap();
    }
    // Current log exists.
    assert!(cfg.log_file_path().exists());
    // At least one rotated file should exist.
    assert!(cfg.rotated_log_path(1).exists());
}

#[test]
fn log_rotator_explicit_rotate() {
    let dir = tempdir().unwrap();
    let mut cfg = DaemonConfig::new();
    cfg.log_dir = dir.path().to_path_buf();
    cfg.log_name = "z".into();
    cfg.max_log_size = 1024;
    cfg.max_log_files = 2;
    let mut r = LogRotator::new(cfg.clone()).unwrap();
    r.write_line("hello").unwrap();
    r.rotate().unwrap();
    assert!(cfg.rotated_log_path(1).exists());
    assert!(cfg.log_file_path().exists());
}

// ─────────────────────────────────────────────────────────────────────────────
// HealthCheck
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn health_check_empty_runs() {
    let h = HealthCheck::new();
    let r = h.run();
    assert!(r.healthy); // all() of empty is true
    assert!(r.checks.is_empty());
}

#[test]
fn health_check_aggregates_pass_fail() {
    let mut h = HealthCheck::default();
    h.add_check(|| CheckItem::pass("a", "ok"));
    h.add_check(|| CheckItem::fail("b", "bad"));
    let r = h.run();
    assert!(!r.healthy);
    assert_eq!(r.checks.len(), 2);
    let txt = r.to_text();
    assert!(txt.contains("UNHEALTHY"));
    assert!(txt.contains("OK"));
    assert!(txt.contains("FAIL"));
}

#[test]
fn health_check_all_pass() {
    let mut h = HealthCheck::new();
    h.add_check(|| CheckItem::pass("a", "1"));
    h.add_check(|| CheckItem::pass("b", "2"));
    let r = h.run();
    assert!(r.healthy);
    assert!(r.to_text().contains("HEALTHY"));
}

#[test]
fn check_item_constructors() {
    let p = CheckItem::pass("n", "d");
    assert!(p.ok && p.name == "n" && p.detail == "d");
    let f = CheckItem::fail("n", "d");
    assert!(!f.ok);
}

// ─────────────────────────────────────────────────────────────────────────────
// SignalBus + Signal
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn signal_display() {
    assert_eq!(Signal::Terminate.to_string(), "SIGTERM");
    assert_eq!(Signal::Interrupt.to_string(), "SIGINT");
    assert_eq!(Signal::HangUp.to_string(), "SIGHUP");
    assert_eq!(Signal::User1.to_string(), "SIGUSR1");
    assert_eq!(Signal::User2.to_string(), "SIGUSR2");
}

#[test]
fn signal_hash_eq() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(Signal::Terminate);
    s.insert(Signal::Terminate);
    s.insert(Signal::Interrupt);
    assert_eq!(s.len(), 2);
}

#[test]
fn signal_bus_post_drain() {
    let bus = SignalBus::new();
    assert!(!bus.has_pending());
    bus.post(Signal::Terminate);
    bus.post(Signal::HangUp);
    assert!(bus.has_pending());
    let drained = bus.drain();
    assert_eq!(drained, vec![Signal::Terminate, Signal::HangUp]);
    assert!(!bus.has_pending());
}

// ─────────────────────────────────────────────────────────────────────────────
// Daemon
// ─────────────────────────────────────────────────────────────────────────────

fn fresh_daemon_cfg(dir: &std::path::Path) -> DaemonConfig {
    let mut c = DaemonConfig::new();
    c.pid_file = dir.join("d.pid");
    c.log_dir = dir.join("logs");
    c
}

#[test]
fn daemon_new_validates() {
    let dir = tempdir().unwrap();
    let mut c = fresh_daemon_cfg(dir.path());
    c.max_log_size = 0;
    assert!(matches!(Daemon::new(c), Err(DaemonError::Config(_))));
}

#[test]
fn daemon_start_stop_lifecycle() {
    let dir = tempdir().unwrap();
    let c = fresh_daemon_cfg(dir.path());
    let pid_path = c.pid_file.clone();
    let mut d = Daemon::new(c).unwrap();
    assert_eq!(d.state(), DaemonState::Stopped);
    assert!(d.uptime().is_none());

    d.start().unwrap();
    assert_eq!(d.state(), DaemonState::Running);
    assert!(pid_path.exists());
    assert!(d.uptime().is_some());

    d.stop().unwrap();
    assert_eq!(d.state(), DaemonState::Stopped);
    assert!(!pid_path.exists());
    assert!(d.uptime().is_none());
}

#[test]
fn daemon_stop_without_start_is_err() {
    let dir = tempdir().unwrap();
    let mut d = Daemon::new(fresh_daemon_cfg(dir.path())).unwrap();
    assert!(matches!(d.stop(), Err(DaemonError::NotRunning)));
}

#[test]
fn daemon_double_start_errors() {
    let dir = tempdir().unwrap();
    let mut d = Daemon::new(fresh_daemon_cfg(dir.path())).unwrap();
    d.start().unwrap();
    let err = d.start().unwrap_err();
    assert!(matches!(err, DaemonError::AlreadyRunning(_)));
    d.stop().unwrap();
}

#[test]
fn daemon_restart() {
    let dir = tempdir().unwrap();
    let mut d = Daemon::new(fresh_daemon_cfg(dir.path())).unwrap();
    d.start().unwrap();
    d.restart().unwrap();
    assert_eq!(d.state(), DaemonState::Running);
    d.stop().unwrap();
}

#[test]
fn daemon_restart_from_stopped() {
    let dir = tempdir().unwrap();
    let mut d = Daemon::new(fresh_daemon_cfg(dir.path())).unwrap();
    // restart while stopped should just start.
    d.restart().unwrap();
    assert_eq!(d.state(), DaemonState::Running);
    d.stop().unwrap();
}

#[test]
fn daemon_signal_bus_round_trip() {
    let dir = tempdir().unwrap();
    let d = Daemon::new(fresh_daemon_cfg(dir.path())).unwrap();
    d.signal_bus().post(Signal::HangUp);
    let sigs = d.process_signals();
    assert_eq!(sigs, vec![Signal::HangUp]);
    assert!(d.process_signals().is_empty());
}

#[test]
fn daemon_health_check_runs() {
    let dir = tempdir().unwrap();
    let d = Daemon::new(fresh_daemon_cfg(dir.path())).unwrap();
    d.add_health_check(|| CheckItem::pass("p", "ok"));
    let r = d.run_health_check();
    assert!(r.healthy);
    assert_eq!(r.checks.len(), 1);
}

#[test]
fn daemon_mark_failed_then_can_start() {
    let dir = tempdir().unwrap();
    let mut d = Daemon::new(fresh_daemon_cfg(dir.path())).unwrap();
    d.mark_failed();
    assert_eq!(d.state(), DaemonState::Failed);
    // Failed is can_start
    d.start().unwrap();
    assert_eq!(d.state(), DaemonState::Running);
    d.stop().unwrap();
}

#[test]
fn daemon_status_text_contains_state() {
    let dir = tempdir().unwrap();
    let d = Daemon::new(fresh_daemon_cfg(dir.path())).unwrap();
    let s = d.status_text();
    assert!(s.contains("state=stopped"));
    assert!(s.contains("uptime=n/a"));
}

#[test]
fn daemon_config_getter() {
    let dir = tempdir().unwrap();
    let cfg = fresh_daemon_cfg(dir.path());
    let pid_path = cfg.pid_file.clone();
    let d = Daemon::new(cfg).unwrap();
    assert_eq!(d.config().pid_file, pid_path);
}

#[test]
fn daemon_list_capabilities_non_empty() {
    let dir = tempdir().unwrap();
    let d = Daemon::new(fresh_daemon_cfg(dir.path())).unwrap();
    let caps = d.list_capabilities();
    // The MCP catalog should expose at least one tool.
    assert!(!caps.is_empty(), "expected at least one capability");
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility helpers
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn format_duration_zero() {
    assert_eq!(format_duration(Duration::from_secs(0)), "0s");
}

#[test]
fn format_duration_seconds() {
    assert_eq!(format_duration(Duration::from_secs(45)), "45s");
}

#[test]
fn format_duration_minutes() {
    assert_eq!(format_duration(Duration::from_secs(125)), "2m 5s");
}

#[test]
fn format_duration_hours() {
    assert_eq!(format_duration(Duration::from_secs(3 * 3600 + 4 * 60 + 5)), "3h 4m 5s");
}

#[test]
fn format_duration_exactly_one_hour() {
    assert_eq!(format_duration(Duration::from_secs(3600)), "1h 0m 0s");
}

#[test]
fn is_process_running_self_is_true() {
    assert!(is_process_running(std::process::id()));
}

#[test]
fn is_process_running_zero_is_false_or_consistent() {
    // PID 0 on Windows is "System Idle Process" -> may or may not be reachable.
    // Just call it to exercise the code path.
    let _ = is_process_running(0);
}

#[test]
fn is_process_running_implausible_pid() {
    // A very large PID is extremely unlikely to be running.
    assert!(!is_process_running(u32::MAX - 1));
}

// ─────────────────────────────────────────────────────────────────────────────
// HttpDaemonConfig + ProjectHandle + ServerState
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn http_daemon_config_defaults() {
    let c = HttpDaemonConfig::default();
    assert_eq!(c.bind_addr, "127.0.0.1:7878");
    assert_eq!(c.log_level, "info");
    assert_eq!(c.max_connections, 16);
    assert!(c.mcp_bind.is_none());
    assert!(c.project_dir.is_none());
    assert!(c.auth_token.is_none());
    assert_eq!(c.workers, 0);
}

#[test]
fn http_daemon_config_serde() {
    let c = HttpDaemonConfig::default();
    let s = serde_json::to_string(&c).unwrap();
    let back: HttpDaemonConfig = serde_json::from_str(&s).unwrap();
    assert_eq!(back.bind_addr, c.bind_addr);
}

#[test]
fn project_handle_id_derives_from_path() {
    let h = ProjectHandle::new(PathBuf::from("/a b/c:d"));
    assert!(h.id.contains("_"));
    // No raw separators or spaces in the id
    assert!(!h.id.contains(' '));
    assert!(!h.id.contains(':'));
    assert!(!h.id.contains('/'));
    assert!(!h.id.contains('\\'));
    assert_eq!(h.binary_count, 0);
}

#[test]
fn project_handle_serde() {
    let h = ProjectHandle::new(PathBuf::from("/x"));
    let s = serde_json::to_string(&h).unwrap();
    let back: ProjectHandle = serde_json::from_str(&s).unwrap();
    assert_eq!(back.id, h.id);
    assert_eq!(back.path, h.path);
}

#[test]
fn server_state_uptime_grows() {
    let s = ServerState::new(HttpDaemonConfig::default());
    let u1 = s.uptime_secs();
    // uptime is monotonic non-decreasing
    assert!(s.uptime_secs() >= u1);
    assert!(s.projects.is_empty());
    assert_eq!(s.active_sessions, 0);
    assert_eq!(s.total_requests, 0);
    assert_eq!(s.rpc_errors, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON-RPC types
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn jsonrpc_response_ok() {
    let r = JsonRpcResponse::ok(json!(1), json!({"a":1}));
    assert_eq!(r.jsonrpc, "2.0");
    assert_eq!(r.id, json!(1));
    assert!(r.error.is_none());
    assert_eq!(r.result, Some(json!({"a":1})));
}

#[test]
fn jsonrpc_response_err() {
    let r = JsonRpcResponse::err(json!("xid"), JSONRPC_INTERNAL_ERROR, "boom");
    assert_eq!(r.id, json!("xid"));
    assert!(r.result.is_none());
    let err = r.error.unwrap();
    assert_eq!(err.code, JSONRPC_INTERNAL_ERROR);
    assert_eq!(err.message, "boom");
    assert!(err.data.is_none());
}

#[test]
fn jsonrpc_response_err_data() {
    let r = JsonRpcResponse::err_data(json!(7), -1, "nope", json!([1,2,3]));
    let err = r.error.unwrap();
    assert_eq!(err.data, Some(json!([1,2,3])));
}

#[test]
fn jsonrpc_response_to_bytes_round_trip() {
    let r = JsonRpcResponse::ok(json!(42), json!("hello"));
    let bytes = r.to_bytes();
    let parsed: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed["jsonrpc"], "2.0");
    assert_eq!(parsed["id"], 42);
    assert_eq!(parsed["result"], "hello");
    assert!(parsed.get("error").is_none(), "error should be skipped when None");
}

#[test]
fn jsonrpc_response_to_bytes_err_skips_result() {
    let r = JsonRpcResponse::err(json!(0), JSONRPC_INTERNAL_ERROR, "x");
    let bytes = r.to_bytes();
    let parsed: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(parsed.get("result").is_none(), "result should be skipped when None");
    assert!(parsed.get("error").is_some());
}

#[test]
fn jsonrpc_internal_error_const() {
    assert_eq!(JSONRPC_INTERNAL_ERROR, -32603);
}

#[test]
fn jsonrpc_request_deserialize_minimal() {
    let r: JsonRpcRequest =
        serde_json::from_str(r#"{"jsonrpc":"2.0","id":1,"method":"status"}"#).unwrap();
    assert_eq!(r.method, "status");
    // `Some`: this message carries an id, so it is a request. A notification
    // (no `id`) now parses as `None` instead of failing to deserialise.
    assert_eq!(r.id, Some(json!(1)));
    assert!(r.params.is_none());
}

/// The decision the `POST /rpc` route makes: answer, or stay silent.
///
/// This covers the LOGIC, not the wiring — no test in this crate builds an HTTP
/// request (`Request<Incoming>` cannot be constructed outside hyper), so the
/// `204 No Content` branch itself is still only checked by the compiler.
#[test]
fn expects_reply_distinguishes_a_request_from_a_notification() {
    let request: JsonRpcRequest =
        serde_json::from_str(r#"{"jsonrpc":"2.0","id":1,"method":"status"}"#).unwrap();
    assert!(rustre_daemon::expects_reply(&request));

    let notification: JsonRpcRequest =
        serde_json::from_str(r#"{"jsonrpc":"2.0","method":"status"}"#).unwrap();
    assert!(!rustre_daemon::expects_reply(&notification));

    // `id: null` is a REQUEST with a null id, not a notification: the spec keys
    // on the member being absent, not on its value.
    let null_id: JsonRpcRequest =
        serde_json::from_str(r#"{"jsonrpc":"2.0","id":null,"method":"status"}"#).unwrap();
    assert!(
        rustre_daemon::expects_reply(&null_id),
        "an explicit null id still expects an answer"
    );
}

/// A NOTIFICATION carries no `id` and must parse. While `id` was a plain
/// `Value` this failed as a missing field, so `POST /rpc` answered a valid
/// message with a parse error — and answered it at all, which the spec forbids.
#[test]
fn jsonrpc_request_deserialize_notification_without_id() {
    let r: JsonRpcRequest =
        serde_json::from_str(r#"{"jsonrpc":"2.0","method":"status"}"#)
            .expect("a notification must parse");
    assert_eq!(r.method, "status");
    assert!(r.id.is_none(), "a notification carries no id");
}

#[test]
fn jsonrpc_request_with_params() {
    let r: JsonRpcRequest =
        serde_json::from_str(r#"{"jsonrpc":"2.0","id":"x","method":"m","params":{"k":"v"}}"#)
            .unwrap();
    assert_eq!(r.params.unwrap()["k"], "v");
}

// Compile-time: structs are Send so they can cross thread boundaries.
#[test]
fn signal_bus_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SignalBus>();
    assert_send_sync::<DaemonClient>();
}

#[test]
fn daemon_client_clone_preserves_addr_and_timeout() {
    let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
    let c = DaemonClient::new(addr).with_timeout(Duration::from_millis(500));
    let c2 = c.clone();
    assert_eq!(c2.addr(), addr);
    assert_eq!(c2.timeout(), Duration::from_millis(500));
}

#[test]
fn daemon_config_clone_independent_extras() {
    let mut a = DaemonConfig::new();
    a.extra.insert("k".into(), "v".into());
    let mut b = a.clone();
    b.extra.insert("k2".into(), "v2".into());
    assert!(!a.extra.contains_key("k2"));
    assert!(b.extra.contains_key("k"));
}

#[test]
fn extra_map_default_empty() {
    let c = DaemonConfig::default();
    assert!(c.extra.is_empty());
    let _: &HashMap<String, String> = &c.extra;
}
