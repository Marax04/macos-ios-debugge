//! LIVE Linux coverage for FORK and EXEC — the two events that make a
//! debugger's answers go stale without anything looking wrong.
//!
//! Every test drives a REAL process: C fixtures compiled on the fly with `cc`
//! into a temp dir and launched under `ptrace(2)` through `LinuxDebugger`.
//! Nothing here builds a struct in memory and asks it about itself.
//!
//! Two questions are asked, both of the "who is answering?" kind:
//!
//! * **fork** — when the tracee forks, WHICH process does the debugger speak
//!   for? `waitpid(-1, __WALL)` in the backend means a stray child could be
//!   delivered as if it were the tracee, so every event here is checked
//!   against the pid `launch()` returned, and the child's tracing state is
//!   read out of `/proc/<child>/status` (`TracerPid`), which is external
//!   truth this crate did not write.
//! * **execve** — after the tracee replaces its image, `modules()`,
//!   `memory_maps()` and any symbol resolved through them must describe the
//!   NEW program. A debugger still showing the symbols of the program that no
//!   longer exists is the most insidious form of stale answer, because every
//!   address it prints is well-formed and wrong.
//!
//! `follow_forks` is documented in `lib.rs` as a no-op on this backend. That
//! claim is not taken on trust: it is MEASURED here (the stub is pinned by a
//! passing test, and the promised behaviour by an `#[ignore]`d one carrying
//! the red), so a future implementation flips a known assertion instead of
//! silently satisfying nobody.
#![cfg(target_os = "linux")]

use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::{Debugger, LaunchOptions, OutputRedirect, StopReason};
use rustre_symbols::SymbolProvider;

use rustre_symbols::elf_provider::ElfSymbolProvider;
use std::time::Duration;

/// `SIGCHLD` on Linux/x86-64. Spelled out rather than pulled from `libc`
/// because `libc` is a normal, not a dev, dependency of this crate and an
/// integration test cannot see it. Ground truth: `kill -l 17` prints `CHLD`.
const SIGCHLD: i32 = 17;

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

/// The parent of a real `fork()`. `raise(SIGTRAP)` AFTER the fork, so the
/// debugger is parked at a moment when both processes exist at once — the only
/// moment at which "who stopped?" is a question with two possible wrong
/// answers.
///
/// The child `execve`s `argv[1]` so it is a distinct image too, not merely a
/// copy of the parent: a debugger that followed the child by accident would
/// then be caught by `modules()` as well as by the pid.
const FORKER_C: &str = r#"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
__attribute__((noinline)) int rustre_marker_forker(int x) { return x + 11; }
int main(int argc, char **argv) {
    volatile int r = rustre_marker_forker(1);
    (void)r; (void)argc;
    pid_t p = fork();
    if (p == 0) {
        execl(argv[1], argv[1], (char *)0);
        _exit(9);
    }
    raise(SIGTRAP);                 /* stop A: parent + child both alive */
    for (;;) { }
    return 0;
}
"#;

/// The program that `execve`s itself away. Its unique symbol
/// `rustre_marker_old` must be gone from every live view afterwards.
const EXECER_C: &str = r#"
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
__attribute__((noinline)) int rustre_marker_old(int x) { return x * 5; }
int main(int argc, char **argv) {
    volatile int r = rustre_marker_old(3);
    (void)r; (void)argc;
    raise(SIGTRAP);                 /* stop A: still the OLD image */
    execl(argv[1], argv[1], (char *)0);
    _exit(9);
}
"#;

/// A fork whose child dies at once, so the parent is guaranteed a real
/// `SIGCHLD` while it is stopped under the debugger. `FORKER_C`'s child
/// `execve`s and then spins, which makes its `SIGCHLD` a race; this one does
/// not.
const REAPER_C: &str = r#"
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
int main(void) {
    pid_t p = fork();
    if (p == 0) { _exit(7); }
    raise(SIGTRAP);                 /* stop A */
    for (;;) { }
    return 0;
}
"#;

/// The replacement image. `rustre_marker_new` exists ONLY here, so finding it
/// proves the view followed the exec and did not merely fail to notice it.
const NEWPROG_C: &str = r#"
#include <signal.h>
__attribute__((noinline)) int rustre_marker_new(int x) { return x - 4; }
int main(void) {
    volatile int r = rustre_marker_new(3);
    (void)r;
    raise(SIGTRAP);                 /* stop B: the NEW image is running */
    for (;;) { }
    return 0;
}
"#;

struct Fixtures {
    _dir: tempfile::TempDir,
    forker: String,
    execer: String,
    newprog: String,
    reaper: String,
}

/// Compile all three fixtures. `None` when this machine has no working `cc` —
/// a skip, not a failure.
///
/// `-no-pie` so the address `nm` prints IS the run-time address, which is what
/// lets a symbol be checked against the RUNNING process rather than a file.
fn build() -> Option<Fixtures> {
    let dir = tempfile::TempDir::new().ok()?;
    let mut out = Vec::new();
    for (name, src) in [
        ("forker", FORKER_C),
        ("execer", EXECER_C),
        ("newprog", NEWPROG_C),
        ("reaper", REAPER_C),
    ] {
        let c = dir.path().join(format!("{name}.c"));
        let bin = dir.path().join(name);
        std::fs::write(&c, src).ok()?;
        let st = std::process::Command::new("cc")
            .args([c.to_str()?, "-no-pie", "-O0", "-g", "-o", bin.to_str()?])
            .output()
            .ok()?;
        if !st.status.success() {
            return None;
        }
        out.push(bin.to_str()?.to_string());
    }
    Some(Fixtures {
        _dir: dir,
        forker: out[0].clone(),
        execer: out[1].clone(),
        newprog: out[2].clone(),
        reaper: out[3].clone(),
    })
}

macro_rules! fixtures {
    () => {
        match build() {
            Some(f) => f,
            None => {
                eprintln!("skipping: no working `cc` on this machine");
                return;
            }
        }
    };
}

fn opts(exe: &str, arg: &str, follow: bool) -> LaunchOptions {
    LaunchOptions {
        executable: exe.to_string(),
        args: vec![arg.to_string()],
        env: std::collections::HashMap::new(),
        working_dir: None,
        stop_at_entry: false,
        follow_forks: follow,
        redirect: OutputRedirect::default(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Resume, discarding stops that are only thread births, until something else
/// happens. Bounded: resuming *until* a condition would hang forever on a
/// kernel that stopped delivering, and a hang is not a failure anyone can read.
async fn resume_past_noise(dbg: &LinuxDebugger) -> rustre_debug::DebugEvent {
    let mut ev = tokio::time::timeout(Duration::from_secs(30), dbg.continue_execution())
        .await
        .expect("continue_execution must not hang")
        .expect("continue_execution must not error");
    for _ in 0..64 {
        if matches!(ev.reason, StopReason::ThreadCreate { .. }) {
            ev = tokio::time::timeout(Duration::from_secs(30), dbg.continue_execution())
                .await
                .expect("continue_execution must not hang")
                .expect("continue_execution must not error");
        } else {
            break;
        }
    }
    ev
}

/// Like [`resume_past_noise`] but NEVER panics: a timeout or an error comes
/// back as `None`.
///
/// Needed because a panic inside a test that still holds a live tracee does not
/// end the run — the backend's ptrace thread stays blocked in `waitpid` and the
/// harness hangs forever. Measured: the first draft of the `#[ignore]`d test
/// below panicked on a 30 s timeout and left `forker` spinning at 101% CPU with
/// the test binary never exiting. A test that cannot fail cleanly cannot report
/// anything, so the ignored test resumes through THIS and asserts only after it
/// has torn the process down.
async fn try_resume(dbg: &LinuxDebugger) -> Option<rustre_debug::DebugEvent> {
    let mut ev = tokio::time::timeout(Duration::from_secs(10), dbg.continue_execution())
        .await
        .ok()?
        .ok()?;
    for _ in 0..64 {
        if matches!(ev.reason, StopReason::ThreadCreate { .. }) {
            ev = tokio::time::timeout(Duration::from_secs(10), dbg.continue_execution())
                .await
                .ok()?
                .ok()?;
        } else {
            break;
        }
    }
    Some(ev)
}

/// The pids whose `/proc/<pid>/status` names `parent` as their `PPid`.
///
/// External truth, read from the kernel rather than from the crate: this is
/// how the forked child is found without the debugger's cooperation.
fn children_of(parent: u32) -> Vec<u32> {
    let mut v = Vec::new();
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return v;
    };
    let want = parent.to_string();
    for e in rd.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
            continue;
        };
        let is_child = status
            .lines()
            .filter_map(|l| l.strip_prefix("PPid:"))
            .any(|r| r.trim() == want);
        if is_child {
            v.push(pid);
        }
    }
    v
}

/// `TracerPid` from `/proc/<pid>/status`: 0 means nobody is tracing it.
fn tracer_pid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("TracerPid:"))
        .and_then(|r| r.trim().parse().ok())
}

/// The address `nm` gives a symbol in an on-disk `-no-pie` ELF, or `None`.
fn nm_address(exe: &str, want: &str) -> Option<u64> {
    let out = std::process::Command::new("nm").arg(exe).output().ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| {
            let mut it = l.split_whitespace();
            let a = it.next()?;
            let _t = it.next()?;
            if it.next()? == want {
                u64::from_str_radix(a, 16).ok()
            } else {
                None
            }
        })
}

fn u16le(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([d[o], d[o + 1]])
}
fn u32le(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}
fn u64le(d: &[u8], o: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[o..o + 8]);
    u64::from_le_bytes(b)
}

/// `(name, file_off, size)` for every section of a 64-bit little-endian ELF.
fn sections(elf: &[u8]) -> Vec<(String, usize, usize)> {
    let shoff = u64le(elf, 0x28) as usize;
    let shentsize = u16le(elf, 0x3A) as usize;
    let shnum = u16le(elf, 0x3C) as usize;
    let shstrndx = u16le(elf, 0x3E) as usize;
    let strtab_off = u64le(elf, shoff + shstrndx * shentsize + 0x18) as usize;
    (0..shnum)
        .map(|i| {
            let h = shoff + i * shentsize;
            let nameoff = strtab_off + u32le(elf, h) as usize;
            let end = elf[nameoff..].iter().position(|&b| b == 0).unwrap_or(0);
            (
                String::from_utf8_lossy(&elf[nameoff..nameoff + end]).into_owned(),
                u64le(elf, h + 0x18) as usize,
                u64le(elf, h + 0x20) as usize,
            )
        })
        .collect()
}

/// Load an on-disk ELF's `.symtab` through the crate's own symtab parser.
///
/// The `Debugger` trait exposes no `resolve_symbol`, so "the symbols of the
/// program that is running now" can only mean: take the main module PATH the
/// LIVE debugger reports, and parse THAT file. Which is exactly the chain a
/// stale `modules()` would poison — the point of the exec tests below.
fn symtab_of(path: &str) -> Option<ElfSymbolProvider> {
    let bytes = std::fs::read(path).ok()?;
    let secs = sections(&bytes);
    let off = |n: &str| secs.iter().find(|s| s.0 == n).map(|s| (s.1, s.2));
    let (so, sl) = off(".symtab")?;
    let (to, tl) = off(".strtab")?;
    ElfSymbolProvider::parse_symtab(
        "live",
        &bytes[so..so + sl],
        &bytes[to..to + tl],
        true,
        true,
    )
    .ok()
}

/// Kill the tracee through the debugger AND with `kill -9`, on every path.
async fn shutdown(dbg: LinuxDebugger, pid: u32) {
    let _ = dbg.kill().await;
    let _ = std::process::Command::new("kill")
        .args(["-9", &pid.to_string()])
        .output();
}

fn kill_all(pids: &[u32]) {
    for p in pids {
        let _ = std::process::Command::new("kill")
            .args(["-9", &p.to_string()])
            .output();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// fork: who stopped?
// ─────────────────────────────────────────────────────────────────────────────

/// Proves: after the tracee `fork()`s, the stop the debugger delivers still
/// carries the pid `launch()` returned — the PARENT — and never the child's.
///
/// Why it matters: the backend reaps with a process-global
/// `waitpid(-1, __WALL)`. A child that is not being traced cannot produce a
/// ptrace-stop, but a debugger that reported one anyway would hand the caller
/// registers and memory belonging to a process it never attached to, and
/// nothing in the returned event would look wrong.
#[tokio::test(flavor = "multi_thread")]
async fn a_stop_after_fork_names_the_parent_the_debugger_launched() {
    let fx = fixtures!();
    let dbg = LinuxDebugger::new();
    let pid = dbg
        .launch(opts(&fx.forker, &fx.newprog, false))
        .await
        .expect("the forker fixture must launch under ptrace");

    let ev = resume_past_noise(&dbg).await;
    let kids = children_of(pid.0);
    assert_eq!(
        ev.pid.0, pid.0,
        "the stop after fork must be attributed to the launched parent, got pid {} for launched {}",
        ev.pid.0, pid.0
    );
    assert_eq!(
        ev.tid.0, pid.0,
        "the parent is single-threaded, so the stopping thread must be its main thread"
    );
    let cur = dbg
        .current_thread()
        .await
        .expect("a consumed event must have set the current thread");
    assert_eq!(cur.0, pid.0, "current_thread must follow the parent");
    shutdown(dbg, pid.0).await;
    kill_all(&kids);
}

/// Proves: the forked child really exists as a separate process while the
/// parent is stopped, and the kernel says NOBODY is tracing it.
///
/// This is the measurement behind `LaunchOptions::follow_forks` being a no-op:
/// the claim is not read off a doc comment, it is read off
/// `/proc/<child>/status`, which the crate did not write.
#[tokio::test(flavor = "multi_thread")]
async fn the_forked_child_runs_untraced_because_follow_forks_is_not_implemented() {
    let fx = fixtures!();
    let dbg = LinuxDebugger::new();
    let pid = dbg
        .launch(opts(&fx.forker, &fx.newprog, false))
        .await
        .expect("the forker fixture must launch under ptrace");
    let _ = resume_past_noise(&dbg).await;

    let kids = children_of(pid.0);
    let tracers: Vec<(u32, Option<u32>)> = kids.iter().map(|k| (*k, tracer_pid(*k))).collect();
    shutdown(dbg, pid.0).await;
    kill_all(&kids);

    assert!(
        !tracers.is_empty(),
        "the fixture forked, so the kernel must show at least one child of {}",
        pid.0
    );
    for (k, t) in tracers {
        assert_eq!(
            t,
            Some(0),
            "child {k} must be UNtraced: this backend never sets PTRACE_O_TRACEFORK"
        );
    }
}

/// Proves: asking for `follow_forks: true` is ACCEPTED and changes nothing.
///
/// Pinning a stub is not busywork. The field is public API; a caller who sets
/// it gets no error today, and the only way to learn that is to run it. When
/// the backend grows `PTRACE_O_TRACEFORK`, this assertion is the one that
/// fails first, which is the intended alarm.
#[tokio::test(flavor = "multi_thread")]
async fn follow_forks_true_is_accepted_and_still_leaves_the_child_untraced() {
    let fx = fixtures!();
    let dbg = LinuxDebugger::new();
    let pid = dbg
        .launch(opts(&fx.forker, &fx.newprog, true))
        .await
        .expect("follow_forks: true must not make launch fail");
    let _ = resume_past_noise(&dbg).await;

    let kids = children_of(pid.0);
    let traced: Vec<u32> = kids
        .iter()
        .copied()
        .filter(|k| tracer_pid(*k).unwrap_or(0) != 0)
        .collect();
    let any = !kids.is_empty();
    shutdown(dbg, pid.0).await;
    kill_all(&kids);

    assert!(any, "the fixture must have forked");
    assert!(
        traced.is_empty(),
        "MEASURED STUB: follow_forks: true was accepted but children {traced:?} are traced — \
         the flag has been implemented and `lib.rs`'s doc comment plus this test are now stale"
    );
}

/// The RED for `follow_forks`. What the field PROMISES: a child created by
/// `fork` is followed, which on this API means a `StopReason::ProcessCreate`
/// naming the child's pid.
///
/// Measured today: no such event is ever delivered — the parent runs from the
/// fork straight to its own `raise(SIGTRAP)`. `StopReason::ProcessCreate`
/// exists in `lib.rs` and is constructed by no Linux code path.
///
/// | row | expected (external truth) | reachable with what the crate already has | obtained today |
/// |---|---|---|---|
/// | child is traced (`/proc/<c>/status` `TracerPid`) | the debugger's pid | yes — the `PTRACE_SETOPTIONS` call already at `linux_debugger.rs:1380` carries `PTRACE_O_TRACECLONE`; OR-in `PTRACE_O_TRACEFORK` | `0` |
/// | `ProcessCreate` events on one fork | 1 | yes — the wait loop already decodes `SIGTRAP \| (PTRACE_EVENT_CLONE << 8)` at `linux_debugger.rs:2069`; `PTRACE_EVENT_FORK` has the same shape and `PTRACE_GETEVENTMSG` yields the child pid | 0 |
/// | debugger can read the child's memory | yes | NOT reachable as-is: `self.pid` is a single value, so the command channel has no way to address a second process | n/a |
///
/// Commands producing the external truth:
/// * `strace -f -e trace=ptrace <test binary>` — no `PTRACE_SETOPTIONS` ever
///   carries `PTRACE_O_TRACEFORK`.
/// * `grep TracerPid /proc/<child>/status` — reads `0` while the parent is
///   stopped under the debugger (this is what the passing test above asserts).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "follow_forks is a documented no-op: no ProcessCreate is ever delivered on Linux"]
async fn follow_forks_should_deliver_a_process_create_event() {
    let fx = fixtures!();
    let dbg = LinuxDebugger::new();
    let pid = dbg
        .launch(opts(&fx.forker, &fx.newprog, true))
        .await
        .expect("launch");
    let mut seen = Vec::new();
    let mut created = None;
    // Two bounded resumes: the fork happens before the parent's first
    // raise(SIGTRAP), so a ProcessCreate would arrive at or before it. The
    // second resume exists only to prove nothing arrives later; it is expected
    // to time out on the fixture's `for(;;)`, which `try_resume` reports as
    // `None` instead of panicking with the tracee still alive.
    for _ in 0..2 {
        let Some(ev) = try_resume(&dbg).await else { break };
        if ev.pid.0 != pid.0 {
            continue;
        }
        seen.push(format!("{:?}", ev.reason));
        if let StopReason::ProcessCreate { pid: child } = ev.reason {
            created = Some(child.0);
            break;
        }
    }
    let kids = children_of(pid.0);
    shutdown(dbg, pid.0).await;
    kill_all(&kids);

    let child = created.unwrap_or_else(|| {
        panic!(
            "follow_forks: true must deliver StopReason::ProcessCreate for the fork;              the kernel showed children {kids:?} but the debugger only reported {seen:?}"
        )
    });
    assert_ne!(child, pid.0, "the created process must not be the parent");
}

/// Proves: the parent's `memory_maps()` never contains the image the CHILD
/// exec'd into, and its main module is still its own.
///
/// A view that leaked the child's mappings would give a caller addresses that
/// are unmapped in the process being debugged — reads would fail for reasons
/// no message would explain.
#[tokio::test(flavor = "multi_thread")]
async fn the_parents_map_never_shows_the_childs_new_image() {
    let fx = fixtures!();
    let dbg = LinuxDebugger::new();
    let pid = dbg
        .launch(opts(&fx.forker, &fx.newprog, false))
        .await
        .expect("launch");
    let _ = resume_past_noise(&dbg).await;

    let maps = dbg.memory_maps().await.expect("memory_maps on a live tracee");
    let leaked: Vec<String> = maps
        .iter()
        .filter_map(|m| m.name.clone())
        .filter(|n| n.contains("newprog"))
        .collect();
    let mods = dbg.modules().await.expect("modules on a live tracee");
    let own = mods.iter().any(|m| m.path == fx.forker);
    let kids = children_of(pid.0);
    shutdown(dbg, pid.0).await;
    kill_all(&kids);

    assert!(
        leaked.is_empty(),
        "the parent's map must not contain the child's exec'd image, found {leaked:?}"
    );
    assert!(
        own,
        "the parent's module list must still contain the forker itself"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// execve: is the answer still about the program that no longer exists?
// ─────────────────────────────────────────────────────────────────────────────

/// Run `execer` to its pre-exec stop, then past the `execve`, and return the
/// debugger parked in the NEW image.
async fn through_exec(fx: &Fixtures) -> (LinuxDebugger, u32) {
    let dbg = LinuxDebugger::new();
    let pid = dbg
        .launch(opts(&fx.execer, &fx.newprog, false))
        .await
        .expect("the execer fixture must launch under ptrace");

    // stop A: the raise(SIGTRAP) in the OLD image.
    let _ = resume_past_noise(&dbg).await;
    let mods = dbg.modules().await.expect("modules before exec");
    assert!(
        mods.iter().any(|m| m.path == fx.execer),
        "before the exec the module list must contain the execer, got {:?}",
        mods.iter().map(|m| &m.path).collect::<Vec<_>>()
    );

    // The kernel delivers a SIGTRAP to a traced process on a successful
    // execve, and the new image then raises its own. Resume until the map
    // really shows the new file — bounded, so a backend that never notices
    // fails with a readable assertion instead of hanging.
    for _ in 0..8 {
        let _ = resume_past_noise(&dbg).await;
        let m = dbg.modules().await.unwrap_or_default();
        if m.iter().any(|x| x.path == fx.newprog) {
            return (dbg, pid.0);
        }
    }
    shutdown(dbg, pid.0).await;
    panic!("after execve the live module list never mentioned the new program");
}

/// Proves: after `execve`, `modules()` describes the NEW program — and the old
/// one is GONE, not merely joined by a newcomer.
///
/// This is the stale-answer test. `modules()` re-reads `/proc/<pid>/maps` on
/// every call, so it should follow; a cached implementation would keep naming
/// a file whose image is not in the address space any more, and every base
/// address it reported would be a plausible number pointing at nothing.
#[tokio::test(flavor = "multi_thread")]
async fn after_execve_modules_show_the_new_program_and_not_the_old_one() {
    let fx = fixtures!();
    let (dbg, pid) = through_exec(&fx).await;
    let mods = dbg.modules().await.expect("modules after exec");
    let paths: Vec<String> = mods.iter().map(|m| m.path.clone()).collect();
    let main = mods.iter().find(|m| m.is_main).map(|m| m.path.clone());
    shutdown(dbg, pid).await;

    assert!(
        paths.iter().any(|p| *p == fx.newprog),
        "after exec the new program must appear in modules(), got {paths:?}"
    );
    assert!(
        !paths.iter().any(|p| *p == fx.execer),
        "the replaced image must be GONE from modules(), got {paths:?}"
    );
    assert_eq!(
        main.as_deref(),
        Some(fx.newprog.as_str()),
        "the MAIN module after exec must be the new program"
    );
}

/// Proves: the same for `memory_maps()` — no region backed by the replaced
/// file survives the exec, and the new file is mapped executable.
#[tokio::test(flavor = "multi_thread")]
async fn after_execve_the_map_drops_every_region_of_the_replaced_image() {
    let fx = fixtures!();
    let (dbg, pid) = through_exec(&fx).await;
    let maps = dbg.memory_maps().await.expect("memory_maps after exec");
    let old: Vec<String> = maps
        .iter()
        .filter_map(|m| m.name.clone())
        .filter(|n| n.contains("execer"))
        .collect();
    let has_new_exec = maps
        .iter()
        .any(|m| m.name.as_deref().is_some_and(|n| n.contains("newprog")) && m.executable);
    shutdown(dbg, pid).await;

    assert!(
        old.is_empty(),
        "regions of the replaced image must be gone, found {old:?}"
    );
    assert!(
        has_new_exec,
        "the new image must have an executable mapping after the exec"
    );
}

/// Proves: the SYMBOLS reachable through the live view are the new program's.
///
/// The chain a real caller uses is `modules()` → main module path → parse that
/// ELF. So this resolves `rustre_marker_new` (which exists only in the
/// replacement) through the path the LIVE debugger reports, and checks that
/// `rustre_marker_old` (which existed only in the replaced image) resolves to
/// nothing. A debugger that kept the old module would answer the second one
/// with a confident, valid-looking address into memory that is no longer
/// mapped — the failure this whole file exists to catch.
#[tokio::test(flavor = "multi_thread")]
async fn after_execve_symbols_come_from_the_new_program_not_the_replaced_one() {
    let fx = fixtures!();
    let (dbg, pid) = through_exec(&fx).await;
    let mods = dbg.modules().await.expect("modules after exec");
    let main = mods
        .iter()
        .find(|m| m.is_main)
        .map(|m| m.path.clone())
        .expect("there must be a main module after the exec");
    shutdown(dbg, pid).await;

    let prov = symtab_of(&main).expect("the live main module must be a parseable ELF");
    let new = prov
        .lookup_name("rustre_marker_new")
        .expect("the new program's own symbol must resolve through the LIVE module path");
    let want = nm_address(&fx.newprog, "rustre_marker_new").expect("nm must list rustre_marker_new");
    assert_eq!(
        new.address,
        want,
        "the resolved address must be the one nm reports for the -no-pie new image"
    );
    assert!(
        prov.lookup_name("rustre_marker_old").is_none(),
        "the replaced program's symbol must NOT be resolvable after the exec"
    );
}

/// Proves: `execve` preserves the pid, so the debugger must keep speaking for
/// the SAME process — the identity that survives is the process, not the
/// program.
///
/// A backend that re-derived its pid from the exec trap, or gave up and
/// returned `NotAttached`, would be wrong in opposite directions; both are
/// excluded here by reading registers out of the post-exec process.
#[tokio::test(flavor = "multi_thread")]
async fn execve_preserves_the_process_identity_the_debugger_speaks_for() {
    let fx = fixtures!();
    let (dbg, pid) = through_exec(&fx).await;
    let tid = dbg
        .current_thread()
        .await
        .expect("current thread must still be known after the exec");
    let regs = dbg.get_registers(tid).await;
    let mods = dbg.modules().await.unwrap_or_default();
    let still_new = mods.iter().any(|m| m.path == fx.newprog);
    shutdown(dbg, pid).await;

    assert_eq!(tid.0, pid, "execve keeps the pid; the main thread's tid equals it");
    let regs = regs.expect("registers must still be readable after the exec");
    assert_ne!(regs.pc, 0, "the post-exec pc must be a real address");
    assert!(still_new, "the process must still be running the new image");
}

/// Proves: the CPU and the post-exec view agree — the live program counter
/// falls inside a module `modules()` reports, and the bytes at the address the
/// live main module's symbol table gives for `rustre_marker_new` are the bytes
/// that function has on disk in the NEW program.
///
/// The first draft of this test asserted the pc was inside the MAIN module and
/// failed with `pc 0x76b6_9ccc_e540 ... [0x400000, 0x405000)`. The TEST was
/// wrong, not the backend: the fixture is parked at `raise(SIGTRAP)`, which
/// executes inside libc, so the pc is legitimately in a shared library. What is
/// actually worth binding is the round trip view -> address -> tracee memory,
/// which is what a stale module list would corrupt: it would hand out an
/// address from the REPLACED image, and the bytes read there would not be the
/// function's.
#[tokio::test(flavor = "multi_thread")]
async fn after_execve_the_cpu_and_the_view_agree_on_the_new_image() {
    let fx = fixtures!();
    let (dbg, pid) = through_exec(&fx).await;
    let tid = dbg.current_thread().await.expect("current thread");
    let regs = dbg.get_registers(tid).await.expect("registers");
    let mods = dbg.modules().await.expect("modules");
    let main = mods
        .iter()
        .find(|m| m.is_main)
        .cloned()
        .expect("a main module");

    let pc = regs.pc;
    let containing: Vec<String> = mods
        .iter()
        .filter(|m| pc >= m.base.as_u64() && pc < m.base.as_u64() + m.size)
        .map(|m| m.path.clone())
        .collect();

    let prov = symtab_of(&main.path).expect("the live main module must parse");
    let marker = prov
        .lookup_name("rustre_marker_new")
        .expect("rustre_marker_new via the live main module");
    let live = dbg
        .read_memory(rustre_core::address::Address::new(marker.address), 8)
        .await;
    shutdown(dbg, pid).await;

    assert!(
        !containing.is_empty(),
        "pc {pc:#x} falls outside every module the debugger reports: {:?}",
        mods.iter().map(|m| &m.path).collect::<Vec<_>>()
    );
    assert!(
        !containing.iter().any(|p| p.contains("execer")),
        "the pc must not be attributed to the replaced image, got {containing:?}"
    );

    let bytes = std::fs::read(&fx.newprog).expect("read the new program");
    let secs = sections(&bytes);
    let (_, text_off, text_size) = secs
        .iter()
        .find(|s| s.0 == ".text")
        .cloned()
        .expect(".text in the new program");
    // `-no-pie`, so the section's virtual address is its load address; recover
    // it from the same header the parser used.
    let text_addr = {
        let shoff = u64le(&bytes, 0x28) as usize;
        let shentsize = u16le(&bytes, 0x3A) as usize;
        let idx = secs.iter().position(|s| s.0 == ".text").expect(".text");
        u64le(&bytes, shoff + idx * shentsize + 0x10)
    };
    assert!(
        marker.address >= text_addr && marker.address < text_addr + text_size as u64,
        "rustre_marker_new {:#x} is outside .text [{text_addr:#x}, +{text_size:#x})",
        marker.address
    );
    let file_off = text_off + (marker.address - text_addr) as usize;
    let on_disk = &bytes[file_off..file_off + 8];
    let live = live.expect("read_memory at the live-resolved address must succeed");
    assert_eq!(
        live.as_slice(),
        on_disk,
        "the bytes at {:#x} in the running process must be the NEW program's function",
        marker.address
    );
}

/// Proves: when the tracee's forked child dies, the `SIGCHLD` the kernel
/// sends the parent reaches the debugger's caller as a `Signal` stop carrying
/// signal 17, attributed to the parent.
///
/// Why it matters: `SIGCHLD` is the ONLY notification a debugger of the parent
/// gets about a child it is not following. Swallowing it, or attributing it to
/// the untraced child, would leave the caller with no way to know the fork
/// finished — and the backend's `waitpid(-1, __WALL)` makes the second mistake
/// easy to make.
#[tokio::test(flavor = "multi_thread")]
async fn the_parent_is_told_about_its_dead_child_through_sigchld() {
    let fx = fixtures!();
    let dbg = LinuxDebugger::new();
    let pid = dbg
        .launch(opts(&fx.reaper, &fx.reaper, false))
        .await
        .expect("the reaper fixture must launch under ptrace");

    // The SIGCHLD and the fixture's own raise(SIGTRAP) race, so collect a few
    // bounded stops rather than assuming an order.
    let mut signals: Vec<(u32, i32, String)> = Vec::new();
    for _ in 0..4 {
        let Some(ev) = try_resume(&dbg).await else { break };
        if let StopReason::Signal { signum, signame, .. } = &ev.reason {
            signals.push((ev.pid.0, *signum, signame.clone()));
        }
    }
    shutdown(dbg, pid.0).await;

    let chld: Vec<&(u32, i32, String)> = signals.iter().filter(|s| s.1 == SIGCHLD).collect();
    assert!(
        !chld.is_empty(),
        "the parent must be told its child died; stops seen: {signals:?}"
    );
    for s in chld {
        assert_eq!(
            s.0, pid.0,
            "SIGCHLD must be attributed to the PARENT, not to the child that raised it"
        );
    }
}

/// The RED for signal NAMING. `StopReason::Signal` carries a `signame`
/// alongside the number, and for `SIGCHLD` — the one signal a fork is
/// guaranteed to produce — it reads `"SIG17"`.
///
/// Measured, from the `#[ignore]`d `follow_forks` run in this file:
/// `Signal { signum: 17, signame: "SIG17", address: None }`.
///
/// | row | expected (external truth) | reachable with what the crate already has | obtained today |
/// |---|---|---|---|
/// | `signame` for 17 | `SIGCHLD` (`kill -l 17`) | yes — one arm in `signal_name` at `linux_debugger.rs:2220`, which already names 8 signals | `SIG17` |
/// | signals named at all | 31 standard signals | yes — same `match`; `libc` exports every `SIG*` constant used | 8 (`SIGTRAP`, `SIGSEGV`, `SIGILL`, `SIGABRT`, `SIGBUS`, `SIGFPE`, `SIGCONT`, `SIGSTOP`) |
/// | the number itself | 17 | already correct | 17 — so this is a naming gap, NOT a wrong reading |
///
/// Command producing the external truth: `kill -l 17` prints `CHLD`; the full
/// list is `kill -l`.
///
/// Not a cosmetic complaint: `SIGCHLD`, `SIGCHLD`-vs-`SIGSTOP` and the
/// realtime signals are exactly what a fork/exec session is full of, and
/// `"SIG17"` forces every caller to re-implement the table the crate already
/// half-owns. The fix is additive and cannot change any number.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "signal_name() on Linux names only 8 signals; SIGCHLD comes back as SIG17"]
async fn a_signal_stop_should_name_sigchld_not_sig17() {
    let fx = fixtures!();
    let dbg = LinuxDebugger::new();
    let pid = dbg
        .launch(opts(&fx.reaper, &fx.reaper, false))
        .await
        .expect("launch");
    let mut names = Vec::new();
    for _ in 0..4 {
        let Some(ev) = try_resume(&dbg).await else { break };
        if let StopReason::Signal { signum, signame, .. } = &ev.reason {
            if *signum == SIGCHLD {
                names.push(signame.clone());
            }
        }
    }
    shutdown(dbg, pid.0).await;

    assert!(!names.is_empty(), "no SIGCHLD stop was observed at all");
    for n in names {
        assert_eq!(n, "SIGCHLD", "signal 17 must be named, not numbered");
    }
}

/// Housekeeping with teeth: no fixture process may outlive this file's tests.
///
/// The fixtures spin in `for(;;)`, and the fork tests create a process the
/// debugger is NOT tracing and therefore cannot kill for us. An orphan would
/// burn a core for the rest of the session and, worse, could be delivered to a
/// later test's `waitpid(-1)`.
#[tokio::test(flavor = "multi_thread")]
async fn zz_no_fixture_process_is_left_behind() {
    // Runs last by name under `--test-threads=1`, which orders tests
    // alphabetically.
    for name in ["forker", "execer", "newprog", "reaper"] {
        let alive = std::process::Command::new("pgrep")
            .args(["-x", name])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        assert!(
            alive.is_empty(),
            "fixture `{name}` left running as pid(s) {alive}"
        );
    }
}
