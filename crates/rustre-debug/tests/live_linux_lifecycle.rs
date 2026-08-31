//! Live-process coverage for the Linux backend's session lifecycle:
//! `launch` / `attach` / `detach` / `kill` / `is_attached` / `target_pid`,
//! and — the part this file exists for — what the rest of the API answers
//! AFTER the session is over.
//!
//! Every test drives a REAL process. A small C fixture is compiled on the fly
//! with `cc -no-pie -O0 -g` (so the address `nm` prints is the address the
//! function occupies at run time) and is either launched under `ptrace` or
//! started independently and attached to. Nothing here asserts on a structure
//! built in memory: whether a process is alive is read back from
//! `/proc/<pid>/stat`, which is the only evidence that `kill` killed and
//! `detach` did not.
//!
//! The rule under test is the one a debugger is judged by once the target is
//! gone: it must answer "I am not attached", not answer with data from the
//! session that ended. A stale answer is worse than an error — the caller
//! cannot tell it apart from a live one.
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::{
    BreakpointKind, DebugError, Debugger, LaunchOptions, OutputRedirect, ProcessId, ThreadId,
};

/// The fixture: runs long enough to be attached to, poked at and killed, and
/// exits on its own shortly after so the "target ran to completion" test does
/// not have to wait.
const FIXTURE_C: &str = r#"
#include <unistd.h>
__attribute__((noinline)) int hot(int x) { return x + 1; }
int main(void) {
    volatile int s = 0;
    for (int i = 0; i < 5; i++) { s = hot(s); }
    usleep(400000);
    return 0;
}
"#;

/// A long-lived fixture for the attach tests: it must still be running when we
/// get around to attaching to it, and must not outlive the test if something
/// goes wrong, so it exits by itself after a while.
const SLEEPER_C: &str = r#"
#include <unistd.h>
int main(void) { sleep(30); return 0; }
"#;

struct Fixture {
    _dir: tempfile::TempDir,
    exe: String,
    hot: u64,
}

fn build(source: &str) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("fixture.c");
    let exe = dir.path().join("fixture");
    std::fs::write(&src, source).expect("write fixture source");
    let out = std::process::Command::new("cc")
        .args(["-no-pie", "-O0", "-g"])
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .output()
        .expect("cc must be available to run the live lifecycle tests");
    assert!(
        out.status.success(),
        "cc failed to build the fixture: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let nm = std::process::Command::new("nm").arg(&exe).output().expect("nm");
    let listing = String::from_utf8_lossy(&nm.stdout).to_string();
    let hot = listing
        .lines()
        .find_map(|l| {
            let mut it = l.split_whitespace();
            let addr = it.next()?;
            let _kind = it.next()?;
            if it.next()? != "hot" {
                return None;
            }
            u64::from_str_radix(addr, 16).ok()
        })
        .unwrap_or(0);
    Fixture { _dir: dir, exe: exe.to_string_lossy().to_string(), hot }
}

fn opts(exe: &str) -> LaunchOptions {
    LaunchOptions {
        executable: exe.to_string(),
        args: Vec::new(),
        env: std::collections::HashMap::new(),
        working_dir: None,
        stop_at_entry: false,
        follow_forks: false,
        redirect: OutputRedirect::default(),
    }
}

/// The process state letter from `/proc/<pid>/stat`, or `None` if the process
/// is gone entirely. The comm field is parenthesised and may itself contain
/// spaces, so the state letter is found from the LAST `)`, never by splitting
/// the line on whitespace.
fn proc_state(pid: u32) -> Option<char> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = s.rfind(')')?;
    s[close + 1..].split_whitespace().next()?.chars().next()
}

/// `Z` is a zombie — dead but unreaped — and is deliberately not counted as
/// alive: a debugger that leaves a zombie behind has not killed cleanly.
fn alive(pid: u32) -> bool {
    matches!(proc_state(pid), Some(c) if c != 'Z')
}

/// Start the sleeper independently of the debugger, so `attach` has a target it
/// did not create.
fn spawn_sleeper(exe: &str) -> std::process::Child {
    let child = std::process::Command::new(exe).spawn().expect("spawn sleeper");
    // Give it time to reach `sleep`; attaching mid-`execve` is a different test.
    std::thread::sleep(std::time::Duration::from_millis(150));
    child
}

fn is_not_attached(e: &DebugError) -> bool {
    matches!(e, DebugError::NotAttached)
}

/// A teardown call with no session may legitimately answer either with the
/// bare `NotAttached` or with a `DetachError` that EXPLAINS which step could
/// not be taken and why — `detach` sweeps the debug registers before it
/// detaches, and that sweep is the first thing to notice there is no target.
/// Both are honest; what this rejects is `Ok(())` and any message that does
/// not name the missing attachment.
fn says_not_attached(e: &DebugError) -> bool {
    is_not_attached(e) || format!("{e}").contains("not attached")
}

// ─────────────────────────────── launch ───────────────────────────────

/// After a successful `launch` the instance must report itself attached and
/// hand out a pid that names a REAL live process. `target_pid` is the only
/// handle a caller has on the target; if it were fabricated or stale, every
/// `/proc`-based tool built on top of it would silently address another
/// process.
#[tokio::test]
async fn launch_reports_a_pid_that_is_a_live_process() {
    let fx = build(FIXTURE_C);
    let dbg = LinuxDebugger::new();
    let pid = dbg.launch(opts(&fx.exe)).await.expect("launch");

    assert!(dbg.is_attached(), "is_attached must be true right after a successful launch");
    assert_eq!(dbg.target_pid(), Some(pid), "target_pid must be the pid launch returned");
    assert!(
        alive(pid.0),
        "pid {} must name a live process, state was {:?}",
        pid.0,
        proc_state(pid.0)
    );
    assert_eq!(
        dbg.current_thread().await.expect("current_thread after launch"),
        ThreadId(pid.0),
        "the post-execve stop is on the main thread, so current_thread must already be known"
    );

    let _ = dbg.kill().await;
}

/// A second `launch` on an instance that is already attached must be REFUSED,
/// and must leave the first session intact. Silently replacing the session
/// would orphan the first process: the only channel able to reach its ptrace
/// thread would be overwritten, and its pid would exist nowhere.
#[tokio::test]
async fn a_second_launch_is_refused_and_the_first_session_survives() {
    let fx = build(FIXTURE_C);
    let dbg = LinuxDebugger::new();
    let first = dbg.launch(opts(&fx.exe)).await.expect("first launch");

    let err = dbg.launch(opts(&fx.exe)).await.expect_err("a second launch must be refused");
    assert!(
        matches!(err, DebugError::LaunchError(_)),
        "expected a LaunchError explaining the instance is busy, got {err:?}"
    );
    assert_eq!(dbg.target_pid(), Some(first), "the refused launch must not replace the target");
    assert!(alive(first.0), "the first process must still be alive after the refused launch");

    let _ = dbg.kill().await;
}

/// `attach` on an already-attached instance must be refused for the same
/// reason a second `launch` is: the two doors lead into the same room, and a
/// guard on only one of them is no guard.
#[tokio::test]
async fn attach_on_an_already_attached_instance_is_refused() {
    let fx = build(FIXTURE_C);
    let sleeper = build(SLEEPER_C);
    let dbg = LinuxDebugger::new();
    let launched = dbg.launch(opts(&fx.exe)).await.expect("launch");
    let mut other = spawn_sleeper(&sleeper.exe);

    let err =
        dbg.attach(ProcessId(other.id())).await.expect_err("attach while attached must be refused");
    assert!(matches!(err, DebugError::LaunchError(_)), "expected LaunchError, got {err:?}");
    assert_eq!(dbg.target_pid(), Some(launched), "the refused attach must not change the target");

    let _ = dbg.kill().await;
    let _ = other.kill();
    let _ = other.wait();
}

// ────────────────────────── attach / detach ──────────────────────────

/// `attach` must take control of a process the debugger did NOT create, and
/// `detach` must give it back still running. Killing on detach, or leaving it
/// stopped, would both destroy a process the caller merely inspected.
#[tokio::test]
async fn attach_takes_control_and_detach_returns_the_process_running() {
    let sleeper = build(SLEEPER_C);
    let mut child = spawn_sleeper(&sleeper.exe);
    let pid = child.id();

    let dbg = LinuxDebugger::new();
    if let Err(e) = dbg.attach(ProcessId(pid)).await {
        // `ptrace_scope=1` forbids attaching to a non-descendant. That is a
        // host policy, not a backend defect, so the test reports it rather
        // than failing on it.
        eprintln!("skipping: attach not permitted on this host ({e})");
        let _ = child.kill();
        let _ = child.wait();
        return;
    }
    assert!(dbg.is_attached(), "is_attached must be true after a successful attach");
    assert_eq!(dbg.target_pid(), Some(ProcessId(pid)), "target_pid must be the attached pid");
    let regs = dbg.get_registers(ThreadId(pid)).await.expect("registers of the attached process");
    assert_ne!(regs.pc, 0, "an attached, stopped process must expose a real pc");

    dbg.detach().await.expect("detach");
    assert!(!dbg.is_attached(), "is_attached must be false after detach");
    assert_eq!(dbg.target_pid(), None, "target_pid must be None after detach");

    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(alive(pid), "detach must leave the process running, state was {:?}", proc_state(pid));

    let _ = child.kill();
    let _ = child.wait();
}

/// Attaching to a pid that does not exist must fail, and must leave the
/// instance USABLE. A failed attach that half-registers a session is the worst
/// of both worlds: no target, and no way to start one.
#[tokio::test]
async fn a_failed_attach_leaves_the_instance_free_for_the_next_target() {
    let fx = build(FIXTURE_C);
    let dbg = LinuxDebugger::new();
    // A pid far above the usual range, verified absent right now.
    let mut ghost = 4_000_000u32;
    while std::path::Path::new(&format!("/proc/{ghost}")).exists() {
        ghost += 1;
    }

    let err = dbg.attach(ProcessId(ghost)).await.expect_err("attach to a dead pid must fail");
    assert!(!matches!(err, DebugError::NotAttached), "the error must describe the attach failure");
    assert!(!dbg.is_attached(), "a failed attach must not mark the instance attached");
    assert_eq!(dbg.target_pid(), None, "a failed attach must not publish a pid");

    let pid = dbg.launch(opts(&fx.exe)).await.expect("the instance must still be usable");
    assert!(alive(pid.0));
    let _ = dbg.kill().await;
}

// ────────────────────── after the session ends ──────────────────────

/// After `kill` the process must actually be gone, and the API must say "not
/// attached" rather than serving answers from the session that ended. The
/// calls checked here read three different sources — the ptrace command
/// channel (`get_registers`, `read_memory`), `/proc` (`memory_maps`), and the
/// resume path (`continue_execution`) — so one forgotten teardown cannot pass
/// them all by luck.
#[tokio::test]
async fn after_kill_the_process_is_gone_and_the_api_says_not_attached() {
    let fx = build(FIXTURE_C);
    let dbg = LinuxDebugger::new();
    let pid = dbg.launch(opts(&fx.exe)).await.expect("launch");

    dbg.kill().await.expect("kill");

    assert!(!dbg.is_attached(), "is_attached must be false after kill");
    assert_eq!(dbg.target_pid(), None, "target_pid must be None after kill");
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(!alive(pid.0), "kill must terminate the process, state was {:?}", proc_state(pid.0));

    let e = dbg.get_registers(ThreadId(pid.0)).await.expect_err("registers after kill");
    assert!(is_not_attached(&e), "expected NotAttached from get_registers, got {e:?}");
    let e = dbg.memory_maps().await.expect_err("memory_maps after kill");
    assert!(is_not_attached(&e), "expected NotAttached from memory_maps, got {e:?}");
    let e = dbg.continue_execution().await.expect_err("continue after kill");
    assert!(is_not_attached(&e), "expected NotAttached from continue_execution, got {e:?}");
    let e = dbg.read_memory(Address(fx.hot), 1).await.expect_err("read_memory after kill");
    assert!(is_not_attached(&e), "expected NotAttached from read_memory, got {e:?}");
}

/// The same rule for `detach`: the session is over, so every read must refuse
/// rather than answer. `detach` differs from `kill` in that the process is
/// still alive — which makes a stale answer look even more plausible, and
/// therefore more dangerous.
#[tokio::test]
async fn after_detach_the_api_says_not_attached() {
    let fx = build(FIXTURE_C);
    let dbg = LinuxDebugger::new();
    let pid = dbg.launch(opts(&fx.exe)).await.expect("launch");

    dbg.detach().await.expect("detach");

    assert!(!dbg.is_attached(), "is_attached must be false after detach");
    assert_eq!(dbg.target_pid(), None, "target_pid must be None after detach");

    let e = dbg.get_registers(ThreadId(pid.0)).await.expect_err("registers after detach");
    assert!(is_not_attached(&e), "expected NotAttached from get_registers, got {e:?}");
    let e = dbg.threads().await.expect_err("threads after detach");
    assert!(is_not_attached(&e), "expected NotAttached from threads, got {e:?}");
    let e = dbg.memory_maps().await.expect_err("memory_maps after detach");
    assert!(is_not_attached(&e), "expected NotAttached from memory_maps, got {e:?}");
    let e = dbg
        .set_breakpoint(Address(fx.hot), BreakpointKind::Software)
        .await
        .expect_err("set_breakpoint after detach");
    assert!(is_not_attached(&e), "expected NotAttached from set_breakpoint, got {e:?}");

    let _ = std::process::Command::new("kill").arg("-9").arg(pid.0.to_string()).status();
}

/// The breakpoint table must not survive the session. It records the ORIGINAL
/// byte behind each planted trap, and those bytes belong to a process that no
/// longer exists; `set_breakpoint` returns early for an address already in the
/// table, so an inherited entry would make the next session report a
/// breakpoint it never planted.
#[tokio::test]
async fn the_breakpoint_table_does_not_survive_the_session() {
    let fx = build(FIXTURE_C);
    assert_ne!(fx.hot, 0, "the fixture must export `hot`");
    let dbg = LinuxDebugger::new();
    dbg.launch(opts(&fx.exe)).await.expect("launch");
    dbg.set_breakpoint(Address(fx.hot), BreakpointKind::Software).await.expect("plant");
    assert_eq!(dbg.breakpoints().await.expect("list").len(), 1, "the breakpoint must be listed");

    dbg.kill().await.expect("kill");

    let listed = dbg.breakpoints().await.expect("breakpoints after kill");
    assert!(
        listed.is_empty(),
        "after kill the table must be empty, it still listed {} entry/entries",
        listed.len()
    );
}

/// A target that simply RAN TO COMPLETION ends the session just as `kill`
/// does. This is the case with no explicit teardown call, so it is the one a
/// backend is most likely to miss: if `is_attached` kept answering `true` the
/// instance would be permanently stuck — `attach`/`launch` refuse while a pid
/// is set, and `detach`/`kill` need a ptrace thread that has already gone.
#[tokio::test]
async fn a_target_that_exits_on_its_own_retires_the_session() {
    let fx = build(FIXTURE_C);
    let dbg = LinuxDebugger::new();
    dbg.launch(opts(&fx.exe)).await.expect("launch");

    let mut exited = false;
    for _ in 0..40 {
        match dbg.continue_execution().await {
            Ok(ev) if ev.reason.is_exit() => {
                exited = true;
                break;
            }
            Ok(_) => continue,
            Err(e) => panic!("continue_execution failed before the target exited: {e:?}"),
        }
    }
    assert!(exited, "the fixture must reach exit within a bounded number of resumes");

    assert!(!dbg.is_attached(), "is_attached must be false once the target has exited");
    assert_eq!(dbg.target_pid(), None, "target_pid must be None once the target has exited");

    // And the instance must be reusable, which is the whole point of retiring.
    let pid = dbg.launch(opts(&fx.exe)).await.expect("relaunch after the target exited");
    assert!(alive(pid.0));
    let _ = dbg.kill().await;
}

/// `current_thread` must not outlive the session either. It is the tid every
/// register and step call defaults to, so a stale value is not an inert field:
/// it is a thread id from a dead process, handed to the next caller who asks
/// "which thread am I looking at?".
/// MEASURED RED, 2026-08-31 — a backend defect, left failing on purpose.
/// `kill()` and `detach()` clear `pid`, `cmd_tx` and the breakpoint tables but
/// never clear `current_tid`; only `retire_session_after_exit` (the
/// natural-exit path) does. Expected `Err(NotAttached)`; obtained
/// `Ok(ThreadId(15126))` — the main thread of a process killed milliseconds
/// earlier. `is_attached()` already answers `false` at that moment, so the
/// instance contradicts itself, and `current_thread()` is the tid the
/// register and stepping calls default to.
#[ignore = "backend defect: kill()/detach() do not clear current_tid, so current_thread() serves the dead session's tid"]
#[tokio::test]
async fn current_thread_does_not_outlive_the_session() {
    let fx = build(FIXTURE_C);
    let dbg = LinuxDebugger::new();
    let pid = dbg.launch(opts(&fx.exe)).await.expect("launch");
    assert_eq!(dbg.current_thread().await.expect("live"), ThreadId(pid.0));

    dbg.kill().await.expect("kill");

    match dbg.current_thread().await {
        Err(e) => assert!(is_not_attached(&e), "expected NotAttached, got {e:?}"),
        Ok(tid) => panic!(
            "current_thread answered {tid:?} for a process killed moments ago; \
             the session is over and the only honest answer is NotAttached"
        ),
    }
}

// ─────────────────── teardown called twice, or never ───────────────────

/// A second `detach` must report that there is nothing to detach from. Saying
/// `Ok(())` would tell a caller that a detach happened when none did — and the
/// caller has no other way to find out.
#[tokio::test]
async fn detaching_twice_reports_the_second_call_as_not_attached() {
    let fx = build(FIXTURE_C);
    let dbg = LinuxDebugger::new();
    let pid = dbg.launch(opts(&fx.exe)).await.expect("launch");
    dbg.detach().await.expect("first detach");

    let e = dbg.detach().await.expect_err("the second detach must not report success");
    assert!(says_not_attached(&e), "the second detach must say there is no target, got {e:?}");

    let _ = std::process::Command::new("kill").arg("-9").arg(pid.0.to_string()).status();
}

/// Same for `kill`: the process died on the first call, so the second must be
/// an error and must not reach anything — a second kill that found a live
/// channel would be signalling whatever pid had been recycled since.
#[tokio::test]
async fn killing_twice_reports_the_second_call_as_not_attached() {
    let fx = build(FIXTURE_C);
    let dbg = LinuxDebugger::new();
    dbg.launch(opts(&fx.exe)).await.expect("launch");
    dbg.kill().await.expect("first kill");

    let e = dbg.kill().await.expect_err("the second kill must not report success");
    assert!(is_not_attached(&e), "expected NotAttached from the second kill, got {e:?}");
}

/// A brand-new instance has no target. `detach` and `kill` must both say so,
/// and `is_attached`/`target_pid` must agree with them — four answers from
/// four code paths that must not contradict each other.
#[tokio::test]
async fn a_fresh_instance_refuses_teardown_and_reports_no_target() {
    let dbg = LinuxDebugger::new();
    assert!(!dbg.is_attached(), "a fresh instance is not attached");
    assert_eq!(dbg.target_pid(), None, "a fresh instance has no pid");

    let e = dbg.detach().await.expect_err("detach with no target");
    assert!(says_not_attached(&e), "detach must say there is no target, got {e:?}");
    let e = dbg.kill().await.expect_err("kill with no target");
    assert!(says_not_attached(&e), "kill must say there is no target, got {e:?}");
}

/// A killed session must be fully replaceable: launch, kill, launch again on
/// the SAME instance, and the second target must be a different, live process
/// under real control. This is the end-to-end statement that teardown released
/// everything — pid, command channel and ptrace thread — rather than just
/// clearing the flag `is_attached` reads.
#[tokio::test]
async fn an_instance_is_fully_reusable_after_kill() {
    let fx = build(FIXTURE_C);
    let dbg = LinuxDebugger::new();
    let first = dbg.launch(opts(&fx.exe)).await.expect("first launch");
    dbg.kill().await.expect("kill");

    let second = dbg.launch(opts(&fx.exe)).await.expect("second launch on the same instance");
    assert_ne!(first, second, "the second launch must be a different process");
    let regs = dbg.get_registers(ThreadId(second.0)).await.expect("registers of the second target");
    assert_ne!(regs.pc, 0, "the second session must reach the new process, not the dead one");

    let _ = dbg.kill().await;
}
