//! Live-process coverage for the Linux backend's STOP REASONS.
//!
//! Every test here drives a REAL process: a C fixture is compiled on the fly
//! with `cc -no-pie -O0 -g`, launched under `ptrace`, and made to stop for a
//! specific reason — a planted breakpoint, a genuine SIGSEGV from a NULL
//! dereference, a SIGFPE from an integer division by zero, an asynchronous
//! SIGINT, a signal the backend has no name for, or plain process exit. What
//! is asserted is that `StopReason` tells those apart, that a signal the
//! program itself caused is FORWARDED to the tracee when it resumes, and that
//! an unknown signal is not dressed up as a known one.
//!
//! `-no-pie` is load-bearing: the binary is `ET_EXEC`, so the address `nm`
//! prints for a symbol is the address it occupies at run time.
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::{
    BreakpointKind, DebugEvent, Debugger, LaunchOptions, OutputRedirect, StopReason,
};

/// The fixture. `argv[1]` picks the way it stops:
///   `segv` — dereference a NULL pointer (a real SIGSEGV at address 0)
///   `fpe`  — divide by zero (SIGFPE)
///   `usr1` — install a SIGUSR1 handler that `_exit(7)`s, then spin
///   `int`  — install a SIGINT handler that `_exit(9)`s, then spin
///   `ok`   — do nothing and exit 0
/// The `volatile`s keep even `-O0` from folding the faults away.
const FIXTURE_C: &str = r#"
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
static void on_usr1(int s) { (void)s; _exit(7); }
static void on_int(int s)  { (void)s; _exit(9); }
__attribute__((noinline)) int hot(int x) { return x + 1; }
int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "ok";
    volatile int s = hot(0);
    if (!strcmp(mode, "segv")) {
        volatile int *p = (volatile int *)0;
        s = *p;
    } else if (!strcmp(mode, "fpe")) {
        volatile int z = 0;
        volatile int d = 1;
        s = d / z;
    } else if (!strcmp(mode, "usr1")) {
        signal(SIGUSR1, on_usr1);
        for (;;) { pause(); }
    } else if (!strcmp(mode, "int")) {
        signal(SIGINT, on_int);
        for (;;) { pause(); }
    }
    return s == 12345 ? 3 : 0;
}
"#;

struct Fixture {
    _dir: tempfile::TempDir,
    exe: String,
    hot: u64,
}

fn build_fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("fixture.c");
    let exe = dir.path().join("fixture");
    std::fs::write(&src, FIXTURE_C).expect("write fixture source");
    let out = std::process::Command::new("cc")
        .args(["-no-pie", "-O0", "-g"])
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .output()
        .expect("cc must be available to run the live signal tests");
    assert!(
        out.status.success(),
        "cc failed to build the fixture: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let nm = std::process::Command::new("nm").arg(&exe).output().expect("nm");
    let listing = String::from_utf8_lossy(&nm.stdout).to_string();
    let hot = symbol_address(&listing, "hot").expect("the fixture must export `hot`");
    Fixture { _dir: dir, exe: exe.to_string_lossy().to_string(), hot }
}

fn symbol_address(nm_listing: &str, want: &str) -> Option<u64> {
    for line in nm_listing.lines() {
        let mut parts = line.split_whitespace();
        let Some(addr) = parts.next() else { continue };
        let Some(kind) = parts.next() else { continue };
        if parts.next().unwrap_or("") == want && (kind == "T" || kind == "t") {
            return u64::from_str_radix(addr, 16).ok();
        }
    }
    None
}

fn launch_opts(exe: &str, mode: &str) -> LaunchOptions {
    LaunchOptions {
        executable: exe.to_string(),
        args: vec![mode.to_string()],
        env: std::collections::HashMap::new(),
        working_dir: None,
        stop_at_entry: false,
        follow_forks: false,
        redirect: OutputRedirect::default(),
    }
}

async fn launched(fx: &Fixture, mode: &str) -> LinuxDebugger {
    let dbg = LinuxDebugger::new();
    dbg.launch(launch_opts(&fx.exe, mode)).await.expect("launch should succeed");
    dbg
}

/// Resume until a stop that is neither a library event nor a thread birth,
/// with a hard budget so a misbehaving backend fails instead of hanging.
///
/// Events belonging to some OTHER process are skipped. Every test in this file
/// shares one test binary, and the backend reaps with `waitpid(-1)`, so a child
/// left behind by an earlier test can be handed to a later one's debugger —
/// measured: the SIGKILLed tracee of one test arrived as a `ThreadExit` inside
/// the next. Filtering on the pid we launched keeps each test looking at its
/// own process instead of asserting on a neighbour's corpse.
async fn run_until_interesting(dbg: &LinuxDebugger, mine: u32, budget: usize) -> DebugEvent {
    for _ in 0..budget {
        let ev = dbg.continue_execution().await.expect("continue_execution");
        if ev.pid.0 != mine {
            continue;
        }
        match &ev.reason {
            StopReason::LibraryLoad { .. }
            | StopReason::LibraryUnload { .. }
            | StopReason::ThreadCreate { .. } => {}
            _ => return ev,
        }
    }
    panic!("the tracee never reached an interesting stop within the budget");
}

/// Send `sig` straight to `pid` from another thread, after a delay.
///
/// It has to be asynchronous. A freshly launched tracee is stopped at its exec
/// trap and has executed NOTHING of `main`, so a signal sent before the first
/// resume arrives at a program that has not installed its handler yet and dies
/// of the default action — measured, and the reason this helper exists: the
/// first version of these tests signalled inline and read that as the backend
/// dropping the signal, when in fact the test had signalled too early.
fn kill_later(pid: u32, sig: libc::c_int, after_ms: u64) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(after_ms));
        let rc = unsafe { libc::kill(pid as libc::pid_t, sig) };
        assert_eq!(rc, 0, "kill({sig}) failed: {}", std::io::Error::last_os_error());
    })
}

/// The pid the debugger is driving.
fn pid_of(dbg: &LinuxDebugger) -> u32 {
    dbg.target_pid().expect("a live pid is required").0
}

// ─────────────────────────────────────────────────────────────────────────────

/// A NULL dereference must arrive as a real SIGSEGV, NOT as a breakpoint.
///
/// This is the distinction the whole file exists for. On Linux a planted
/// breakpoint and a crash both stop the tracee through `waitpid`, and the only
/// thing separating them is the signal number: a breakpoint is SIGTRAP with the
/// debugger's own `0xCC` at `rip-1`, a crash is SIGSEGV. Reporting the crash as
/// a `Breakpoint` would make a debugger claim the program stopped where the
/// user asked, when in fact it died — the most misleading answer available.
/// `access_fault()` must also recognise it and report the faulting address the
/// kernel gave (0, the address dereferenced), with `is_write` UNKNOWN, because
/// `si_addr` does not carry the direction on Linux.
#[tokio::test]
async fn a_null_dereference_stops_as_sigsegv_not_as_a_breakpoint() {
    let fx = build_fixture();
    let dbg = launched(&fx, "segv").await;
    let mine = pid_of(&dbg);

    let ev = run_until_interesting(&dbg, mine, 40).await;
    match &ev.reason {
        StopReason::Signal { signum, signame, address } => {
            assert_eq!(*signum, libc::SIGSEGV, "expected SIGSEGV, got {}", ev.reason);
            assert_eq!(signame, "SIGSEGV");
            assert_eq!(
                *address,
                Some(Address(0)),
                "the kernel reports si_addr == 0 for a NULL dereference; the backend reported {address:?}"
            );
        }
        other => panic!("a NULL dereference must stop as a signal, got {other:?}"),
    }
    let fault = ev.reason.access_fault().expect("SIGSEGV must be recognised as a memory fault");
    assert_eq!(fault.address, Some(Address(0)));
    assert_eq!(
        fault.is_write, None,
        "Linux cannot report the access direction; None is the honest answer"
    );
    let _ = dbg.kill().await;
}

/// A planted breakpoint must stop as `Breakpoint`, and must NOT look like a
/// memory fault.
///
/// The control for the test above: the same backend, the same `waitpid` path,
/// a stop the user PLANNED. If both a crash and a breakpoint came back as the
/// same variant the classification would be worthless, so this pins the other
/// side of the distinction — including that `access_fault()` says `None`, since
/// a breakpoint is not a crash and treating it as one would send a caller
/// hunting a bug that does not exist.
#[tokio::test]
async fn a_planted_breakpoint_stops_as_breakpoint_and_is_not_a_memory_fault() {
    let fx = build_fixture();
    let dbg = launched(&fx, "ok").await;
    let mine = pid_of(&dbg);
    dbg.set_breakpoint(Address(fx.hot), BreakpointKind::Software)
        .await
        .expect("set_breakpoint");

    let ev = run_until_interesting(&dbg, mine, 40).await;
    match &ev.reason {
        StopReason::Breakpoint { address, .. } => {
            assert_eq!(
                address.as_u64(),
                fx.hot,
                "the breakpoint stop must name the address that was planted"
            );
        }
        other => panic!("expected a Breakpoint stop at `hot`, got {other:?}"),
    }
    assert!(
        ev.reason.access_fault().is_none(),
        "a breakpoint is not a memory fault, but access_fault() reported {:?}",
        ev.reason.access_fault()
    );
    let _ = dbg.kill().await;
}

/// An integer division by zero must arrive as SIGFPE, named, and must NOT be
/// classified as a memory fault.
///
/// SIGFPE is a genuine fault that carries a `si_addr` just like SIGSEGV does,
/// which is exactly why it is worth testing: a predicate that answered "is this
/// a crash?" by asking "does it have a faulting address?" would call this a
/// memory fault. It is not one — nothing was dereferenced — and `access_fault`
/// accepts only SIGSEGV and the host's SIGBUS.
#[tokio::test]
async fn a_division_by_zero_stops_as_sigfpe_and_is_not_a_memory_fault() {
    let fx = build_fixture();
    let dbg = launched(&fx, "fpe").await;
    let mine = pid_of(&dbg);

    let ev = run_until_interesting(&dbg, mine, 40).await;
    match &ev.reason {
        StopReason::Signal { signum, signame, .. } => {
            assert_eq!(*signum, libc::SIGFPE, "expected SIGFPE, got {}", ev.reason);
            assert_eq!(signame, "SIGFPE");
        }
        other => panic!("a division by zero must stop as a signal, got {other:?}"),
    }
    assert!(
        ev.reason.access_fault().is_none(),
        "SIGFPE is not a memory fault, but access_fault() reported {:?}",
        ev.reason.access_fault()
    );
    let _ = dbg.kill().await;
}

/// A SIGSEGV the debugger does not consume must be FORWARDED to the tracee.
///
/// A ptrace debugger decides, on every resume, whether to hand the stopping
/// signal back. Passing 0 is the easy default and it is wrong for a fault the
/// program caused: the program would sail past its own crash and finish
/// normally, which is a fabricated execution. The evidence here is the exit
/// status, which the debugger cannot fake: after resuming from the SIGSEGV the
/// process must die BY SIGSEGV — the backend spells that `exit_code == -11`.
#[tokio::test]
async fn a_sigsegv_is_forwarded_and_kills_the_tracee_on_resume() {
    let fx = build_fixture();
    let dbg = launched(&fx, "segv").await;
    let mine = pid_of(&dbg);

    let seg = run_until_interesting(&dbg, mine, 40).await;
    assert!(
        matches!(&seg.reason, StopReason::Signal { signum, .. } if *signum == libc::SIGSEGV),
        "precondition: expected the SIGSEGV stop first, got {:?}",
        seg.reason
    );

    let ev = run_until_interesting(&dbg, mine, 40).await;
    match &ev.reason {
        StopReason::ProcessExit { exit_code } => assert_eq!(
            *exit_code,
            -libc::SIGSEGV,
            "the SIGSEGV was not delivered on resume: the process ended with {exit_code} instead of dying by signal 11"
        ),
        other => panic!("expected the tracee to die of the forwarded SIGSEGV, got {other:?}"),
    }
}

/// An asynchronous SIGINT must be reported as a signal stop AND handed to the
/// program, whose own handler then decides the exit code.
///
/// SIGINT is not a fault: nothing in the program caused it, it arrived from
/// outside. A debugger that swallowed it would make Ctrl-C stop working under
/// the debugger while working outside it. The fixture installs a handler that
/// `_exit(9)`s, so 9 — a value only the tracee's own code can produce — is
/// proof the signal really reached the program rather than being reported and
/// dropped.
#[tokio::test]
async fn a_sigint_is_reported_and_then_delivered_to_the_programs_handler() {
    let fx = build_fixture();
    let dbg = launched(&fx, "int").await;
    let mine = pid_of(&dbg);

    // Signalled from another thread while the tracee RUNS: it must reach its
    // `signal(SIGINT, ...)` call before the signal arrives.
    let killer = kill_later(mine, libc::SIGINT, 400);

    let ev = run_until_interesting(&dbg, mine, 40).await;
    killer.join().expect("the signalling thread must not panic");
    match &ev.reason {
        StopReason::Signal { signum, .. } => {
            assert_eq!(*signum, libc::SIGINT, "expected the SIGINT stop, got {}", ev.reason);
        }
        other => panic!("expected a signal stop for SIGINT, got {other:?}"),
    }

    let ev = run_until_interesting(&dbg, mine, 40).await;
    match &ev.reason {
        StopReason::ProcessExit { exit_code } => assert_eq!(
            *exit_code, 9,
            "the SIGINT never reached the program's handler: exit code {exit_code}, expected the handler's 9"
        ),
        other => panic!("expected the process to exit from its SIGINT handler, got {other:?}"),
    }
}

/// A signal the backend has no name for must be reported honestly, never
/// dressed up as a known one, and never as a memory fault.
///
/// `signal_name` maps a short list and falls back to `SIG<n>` for the rest.
/// SIGUSR1 is 10 on Linux — the same number that means SIGBUS on macOS/BSD —
/// so it is precisely the signal a union-of-two-platforms fault predicate
/// misreports as a crash. The requirements are therefore: the number survives
/// intact, the name is not the name of some OTHER signal, and `access_fault()`
/// says `None`.
#[tokio::test]
async fn an_unnamed_signal_keeps_its_number_and_is_not_mistaken_for_a_fault() {
    let fx = build_fixture();
    let dbg = launched(&fx, "usr1").await;
    let mine = pid_of(&dbg);

    let killer = kill_later(mine, libc::SIGUSR1, 400);

    let ev = run_until_interesting(&dbg, mine, 40).await;
    killer.join().expect("the signalling thread must not panic");
    let StopReason::Signal { signum, signame, .. } = &ev.reason else {
        panic!("expected a signal stop for SIGUSR1, got {:?}", ev.reason)
    };
    assert_eq!(*signum, libc::SIGUSR1, "the signal number must survive intact");
    assert_eq!(
        signame,
        &format!("SIG{}", libc::SIGUSR1),
        "an unmapped signal must fall back to its number, not borrow another signal's name; got {signame}"
    );
    assert!(
        ev.reason.access_fault().is_none(),
        "SIGUSR1 is signal 10, which is SIGBUS on macOS but NOT on Linux; access_fault() reported {:?}",
        ev.reason.access_fault()
    );

    // And it is forwarded: the handler's exit code is the proof.
    let ev = run_until_interesting(&dbg, mine, 40).await;
    match &ev.reason {
        StopReason::ProcessExit { exit_code } => assert_eq!(
            *exit_code, 7,
            "SIGUSR1 was not delivered: exit code {exit_code}, expected the handler's 7"
        ),
        other => panic!("expected the process to exit from its SIGUSR1 handler, got {other:?}"),
    }
}

/// A process that runs to completion must stop as `ProcessExit` with the real
/// status, and that must be the LAST word from the backend.
///
/// The fourth way a run ends, and the one that is not a signal at all. Two
/// things are pinned: the exit code is the program's own (0 here, not a
/// placeholder), and the debugger no longer claims a live target afterwards —
/// a debugger that still reports `is_attached` over a reaped process will hand
/// every later call a stale pid.
#[tokio::test]
async fn a_clean_exit_is_reported_with_its_code_and_ends_the_session() {
    let fx = build_fixture();
    let dbg = launched(&fx, "ok").await;
    let mine = pid_of(&dbg);

    let ev = run_until_interesting(&dbg, mine, 40).await;
    match &ev.reason {
        StopReason::ProcessExit { exit_code } => assert_eq!(
            *exit_code, 0,
            "the fixture returns 0; the backend reported {exit_code}"
        ),
        other => panic!("expected a clean ProcessExit, got {other:?}"),
    }
    assert!(
        !dbg.is_attached(),
        "the process has exited, but the debugger still reports itself attached"
    );
}

/// Killing the tracee must be reported as death BY SIGNAL, distinguishable
/// from any ordinary exit code.
///
/// `WIFEXITED` and `WIFSIGNALED` are different statuses, and collapsing them
/// loses the difference between "returned 9" and "was killed by signal 9". The
/// backend encodes the second as a NEGATIVE code, so the sign carries the
/// distinction; this asserts the sign, not just the magnitude.
#[tokio::test]
async fn a_killed_tracee_is_reported_as_death_by_signal_with_a_negative_code() {
    let fx = build_fixture();
    let dbg = launched(&fx, "int").await;
    let mine = pid_of(&dbg);

    let killer = kill_later(mine, libc::SIGKILL, 400);

    let ev = run_until_interesting(&dbg, mine, 40).await;
    killer.join().expect("the signalling thread must not panic");
    match &ev.reason {
        StopReason::ProcessExit { exit_code } => {
            assert!(
                *exit_code < 0,
                "death by signal must be reported with a negative code so it cannot be confused with a return value; got {exit_code}"
            );
            assert_eq!(*exit_code, -libc::SIGKILL, "the code must name the killing signal");
        }
        other => panic!("expected ProcessExit after SIGKILL, got {other:?}"),
    }
}
