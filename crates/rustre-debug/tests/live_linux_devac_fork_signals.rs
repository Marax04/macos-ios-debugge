//! DE-VACUATION of the fork/exec and signal suites: every claim here is
//! anchored to something the debugger did not produce.
//!
//! The falsification campaign (STATUS.md, «LA FALSIFICAZIONE») shifted the one
//! external oracle each live suite consults — the `nm` symbol table — and
//! measured how many tests noticed. `live_linux_fork_exec.rs` lost **1 of 11**
//! and `live_linux_signals.rs` **1 of 8**: almost every assertion in those two
//! files compares one answer of the crate against another answer of the crate,
//! or against a constant typed on the next line.
//!
//! The oracle used here is the one the two subjects make available for free and
//! nobody was reading: **what the program itself writes down**. The fixtures
//! append lines to a log file whose path arrives in `argv`, so
//!
//! * for **fork**, the pids on the `PARENT` and `CHILD` lines are written by
//!   the two processes themselves. "Which process is the debugger speaking
//!   for?" stops being a question answered by the debugger;
//! * for **exec**, `OLD` and `NEWIMAGE` say when the image really changed, so
//!   the view can be checked at the moment the program declares the flip
//!   instead of at the moment the view says so;
//! * for **signals**, the handler writes its own line and exits with a code
//!   taken from `argv` — a number this file does not compile into the fixture,
//!   used twice with two different values so a backend that reports a constant
//!   cannot pass — and the fault fixture writes a line BEFORE and a line AFTER
//!   the faulting instruction, so "the signal was really delivered" is decided
//!   by a line that must be ABSENT.
//!
//! Every assertion is a PAIR or a SET, never a single count: the workflow-6
//! round measured twice that one cell fails to separate two candidates while
//! the pair separates them.
//!
//! Why a log file and not stdout: `OutputRedirect::stdout` is documented in
//! `lib.rs` as **not implemented by either backend**, so a test that read the
//! tracee's stdout through the crate would be reading a feature that does not
//! exist. The file is the same evidence by a path the crate is not on.
#![cfg(target_os = "linux")]

use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::{DebugEvent, Debugger, LaunchOptions, OutputRedirect, StopReason};
use std::time::Duration;

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures — every one of them writes down what it did
// ─────────────────────────────────────────────────────────────────────────────

/// The logging helper shared by all fixtures. `open`/`write`, not `stdio`,
/// because one of the writers is a SIGNAL HANDLER and `fprintf` is not
/// async-signal-safe; a corrupted log would be an oracle that lies. `O_APPEND`
/// so two processes writing at once cannot overwrite each other's line.
const SAY_C: &str = r#"
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
static void say(const char *log, const char *what, long n) {
    char buf[160];
    char t[24];
    int i = 0, j, k = 0;
    long v = n < 0 ? -n : n;
    while (what[i] && i < 64) { buf[i] = what[i]; i++; }
    buf[i++] = ' ';
    if (n < 0) { buf[i++] = '-'; }
    do { t[k++] = (char)(48 + (v % 10)); v /= 10; } while (v);
    for (j = k - 1; j >= 0; j--) { buf[i++] = t[j]; }
    buf[i++] = '\n';
    {
        int fd = open(log, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd < 0) { _exit(90); }
        if (write(fd, buf, (size_t)i) != (ssize_t)i) { _exit(91); }
        close(fd);
    }
}
"#;

/// A real `fork()`. The parent and the child each write their OWN pid, then the
/// child replaces its image and the parent parks in `raise(SIGTRAP)` while both
/// processes are alive — the only moment at which "who stopped?" has two
/// possible wrong answers.
///
/// `argv[1]` log, `argv[2]` the program the child `execve`s.
const FORKER_C: &str = r#"
#include <signal.h>
int main(int argc, char **argv) {
    pid_t p;
    if (argc < 3) { _exit(92); }
    p = fork();
    if (p == 0) {
        say(argv[1], "CHILD", (long)getpid());
        execl(argv[2], argv[2], argv[1], (char *)0);
        _exit(93);
    }
    say(argv[1], "PARENT", (long)getpid());
    raise(SIGTRAP);
    for (;;) { pause(); }
    return 0;
}
"#;

/// The program that replaces itself. It says `OLD` before the `execve` and the
/// replacement says `NEWIMAGE` after it, so the log records the exact moment
/// the image changed.
const EXECER_C: &str = r#"
#include <signal.h>
__attribute__((noinline)) int rustre_devac_only_old(int x) { return x * 7; }
int main(int argc, char **argv) {
    volatile int r;
    if (argc < 3) { _exit(92); }
    r = rustre_devac_only_old(2);
    (void)r;
    say(argv[1], "OLD", (long)getpid());
    raise(SIGTRAP);
    execl(argv[2], argv[2], argv[1], (char *)0);
    _exit(93);
}
"#;

/// The replacement image, also used as the forker child's new image.
const NEWPROG_C: &str = r#"
#include <signal.h>
__attribute__((noinline)) int rustre_devac_only_new(int x) { return x - 13; }
int main(int argc, char **argv) {
    volatile int r;
    if (argc < 2) { _exit(92); }
    r = rustre_devac_only_new(1);
    (void)r;
    say(argv[1], "NEWIMAGE", (long)getpid());
    raise(SIGTRAP);
    for (;;) { pause(); }
    return 0;
}
"#;

/// The signal fixture. `argv[1]` log, `argv[2]` mode, `argv[3]` the exit code
/// the handler must use — passed in rather than compiled in, so a run with a
/// different argument must produce a different answer.
///
/// * `handled`   — install a SIGUSR1 handler that logs and `_exit`s with that
///                 code, then say `READY` and sleep.
/// * `unhandled` — say `READY` and sleep, with NO handler: SIGUSR1 must kill.
/// * `segv`      — say `BEFORE`, dereference NULL, say `AFTER`. The `AFTER`
///                 line must never appear: it is the witness a swallowed fault
///                 would leave behind.
const SIGNALLER_C: &str = r#"
#include <signal.h>
static const char *g_log;
static int g_code;
static void on_usr1(int s) {
    (void)s;
    say(g_log, "HANDLER", (long)g_code);
    _exit(g_code);
}
int main(int argc, char **argv) {
    if (argc < 4) { _exit(92); }
    g_log = argv[1];
    g_code = atoi(argv[3]);
    if (!strcmp(argv[2], "handled")) {
        signal(SIGUSR1, on_usr1);
        say(g_log, "READY", (long)getpid());
        for (;;) { pause(); }
    } else if (!strcmp(argv[2], "unhandled")) {
        say(g_log, "READY", (long)getpid());
        for (;;) { pause(); }
    } else if (!strcmp(argv[2], "segv")) {
        volatile int *p = (volatile int *)0;
        volatile int v;
        say(g_log, "BEFORE", (long)getpid());
        v = *p;
        (void)v;
        say(g_log, "AFTER", (long)getpid());
    }
    return 0;
}
"#;

struct Fixtures {
    dir: std::path::PathBuf,
    _dir: tempfile::TempDir,
    forker: String,
    execer: String,
    newprog: String,
    signaller: String,
}

/// Compile the four fixtures. `None` when this machine has no working `cc` —
/// a skip, not a failure.
fn build() -> Option<Fixtures> {
    let dir = tempfile::TempDir::new().ok()?;
    let mut out = Vec::new();
    for (name, src) in [
        ("dv_forker", FORKER_C),
        ("dv_execer", EXECER_C),
        ("dv_newprog", NEWPROG_C),
        ("dv_signaller", SIGNALLER_C),
    ] {
        let c = dir.path().join(format!("{name}.c"));
        let bin = dir.path().join(name);
        std::fs::write(&c, format!("{SAY_C}\n{src}")).ok()?;
        let st = std::process::Command::new("cc")
            .args([c.to_str()?, "-no-pie", "-O0", "-g", "-o", bin.to_str()?])
            .output()
            .ok()?;
        if !st.status.success() {
            eprintln!("cc failed for {name}: {}", String::from_utf8_lossy(&st.stderr));
            return None;
        }
        out.push(bin.to_str()?.to_string());
    }
    Some(Fixtures {
        dir: dir.path().to_path_buf(),
        _dir: dir,
        forker: out[0].clone(),
        execer: out[1].clone(),
        newprog: out[2].clone(),
        signaller: out[3].clone(),
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

// ─────────────────────────────────────────────────────────────────────────────
// The oracle: what the PROGRAM wrote down
// ─────────────────────────────────────────────────────────────────────────────

/// One line of the log: a tag and the number that follows it.
type Line = (String, i64);

fn read_log(path: &std::path::Path) -> Vec<Line> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let tag = it.next()?.to_string();
            let n = it.next()?.parse::<i64>().ok()?;
            Some((tag, n))
        })
        .collect()
}

/// The number on the first line tagged `tag`, or `None` when the program never
/// wrote one. `None` is a distinct answer from "wrote zero": a test that read a
/// missing line as a value would assert on a fact the program never stated.
fn tagged(lines: &[Line], tag: &str) -> Option<i64> {
    lines.iter().find(|(t, _)| t == tag).map(|(_, n)| *n)
}

fn has(lines: &[Line], tag: &str) -> bool {
    tagged(lines, tag).is_some()
}

/// Wait until every tag in `want` has appeared, or give up. The fixtures write
/// from two processes, so a test must not read the log at an arbitrary moment
/// and call a not-yet-written line a defect.
fn await_lines(path: &std::path::Path, want: &[&str], ms: u64) -> Vec<Line> {
    let deadline = std::time::Instant::now() + Duration::from_millis(ms);
    loop {
        let lines = read_log(path);
        if want.iter().all(|w| has(&lines, w)) || std::time::Instant::now() > deadline {
            return lines;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn opts(exe: &str, args: &[&str]) -> LaunchOptions {
    LaunchOptions {
        executable: exe.to_string(),
        args: args.iter().map(|s| (*s).to_string()).collect(),
        env: std::collections::HashMap::new(),
        working_dir: None,
        stop_at_entry: false,
        follow_forks: false,
        redirect: OutputRedirect::default(),
    }
}

/// Resume past thread births and library events, bounded. A hang is not a
/// failure anyone can read, so a timeout comes back as `None` instead of a
/// panic that would leave a live tracee behind.
async fn resume_past_noise(dbg: &LinuxDebugger) -> Option<DebugEvent> {
    let mut ev = tokio::time::timeout(Duration::from_secs(20), dbg.continue_execution())
        .await
        .ok()?
        .ok()?;
    for _ in 0..64 {
        if matches!(
            ev.reason,
            StopReason::ThreadCreate { .. }
                | StopReason::LibraryLoad { .. }
                | StopReason::LibraryUnload { .. }
        ) {
            ev = tokio::time::timeout(Duration::from_secs(20), dbg.continue_execution())
                .await
                .ok()?
                .ok()?;
        } else {
            break;
        }
    }
    Some(ev)
}

/// Is `tracer`, as `/proc` reports it, compatible with THIS test process being
/// the one holding the attachment?
///
/// ⚠ Measured, and it corrected this file's first draft. `TracerPid` in
/// `/proc/<pid>/status` is `task_pid_nr_ns(tracer)`: the **TID of the tracing
/// task**, not the tgid of the tracing process. The Linux backend does its
/// `fork`+`PTRACE_TRACEME`+`exec` inside a dedicated thread (`spawn_loop`,
/// `linux_debugger.rs:1149`) because ptrace attachments are owned by the thread
/// that made them, so the number reported is that thread's tid and never the
/// pid. The first version asserted `TracerPid == std::process::id()` and went
/// red for that reason alone:
///
/// ```text
/// the process that printed PARENT (12668) reports TracerPid Some(12667);
/// this test process is 12504
/// ```
///
/// The claim that survives is stronger than "nonzero", which any attachment by
/// anyone satisfies: the tracer must be a task of THIS process, checked against
/// `/proc/self/task` — or, failing that, a tid that no longer exists anywhere.
///
/// That last clause is the SECOND correction this one assertion forced, and it
/// records a real property of the backend. In 2 runs out of 6 the tracee was
/// alive with `TracerPid: 3141` while `/proc/3141` did not exist at all and the
/// tid was absent from a task list that ran `2978, 3092..3120` — i.e. the
/// ptrace-owning thread had been created after those and had already EXITED,
/// leaving its tracee naming a dead tracer:
///
/// ```text
/// PARENT (3142) reports TracerPid Some(3141) ... tasks=["2978","3092",..,"3120"]
/// status=Err(NotFound)
/// ```
///
/// So a tid that resolves to nothing is accepted (it cannot be another
/// debugger's), while a tid that resolves to a LIVE task outside this process
/// still fails — which is the case the assertion exists to catch.
fn tracer_is_this_process(tracer: u32) -> bool {
    if tracer == 0 {
        return false;
    }
    if tracer == std::process::id()
        || std::path::Path::new(&format!("/proc/self/task/{tracer}")).exists()
    {
        return true;
    }
    // Measured second correction, see the doc above: the tid may name a thread
    // that no longer exists. A tid that exists and is NOT ours is a different
    // tracer and must still fail.
    !std::path::Path::new(&format!("/proc/{tracer}")).exists()
}

/// A deadline on a tracee that may never stop again.
///
/// WARNING, measured, and it is a property of the BACKEND, not of these tests.
/// The `tokio::time::timeout` every live suite wraps `continue_execution` in
/// does NOT bound it: the call blocks inside its own `poll`, so the task never
/// yields and the timer never gets to fire. Reproduced while falsifying this
/// file - with the exec fixture mutated to spin instead of calling `execl`, the
/// run had to be killed after **10 minutes**, with `dv_execer` still alive and
/// no verdict printed for any test.
///
/// The only thing that unblocks a `waitpid` on a running tracee is an event, so
/// this arms one: unless the guard is disarmed first, `SIGKILL` reaches the
/// tracee and the blocked resume comes back with a `ProcessExit` a test can
/// assert on. A test that finishes normally disarms it and nothing is killed.
struct Watchdog {
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Watchdog {
    fn arm(pid: i64, ms: u64) -> Self {
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = done.clone();
        let handle = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_millis(ms);
            while std::time::Instant::now() < deadline {
                if flag.load(std::sync::atomic::Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            hard_kill(&[pid]);
        });
        Self { done, handle: Some(handle) }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.done.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// `TracerPid` from `/proc/<pid>/status`: 0 means nobody is tracing it.
fn tracer_pid(pid: i64) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("TracerPid:"))
        .and_then(|r| r.trim().parse().ok())
}

/// The pids the kernel calls children of `parent`.
fn children_of(parent: i64) -> Vec<i64> {
    let mut v = Vec::new();
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return v;
    };
    let want = parent.to_string();
    for e in rd.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i64>() else {
            continue;
        };
        let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
            continue;
        };
        if status
            .lines()
            .filter_map(|l| l.strip_prefix("PPid:"))
            .any(|r| r.trim() == want)
        {
            v.push(pid);
        }
    }
    v
}

fn hard_kill(pids: &[i64]) {
    for p in pids {
        if *p > 0 {
            let _ = std::process::Command::new("kill")
                .args(["-9", &p.to_string()])
                .output();
        }
    }
}

/// End the session: `kill -9` FIRST, the debugger's own `kill()` second and
/// under a timeout. The order is the one `live_linux_fork_exec.rs` documents as
/// measured — `Debugger::kill()` does not return while the tracee is RUNNING,
/// which is the state every fixture here is left in after its `for(;;)`.
async fn shutdown(dbg: LinuxDebugger, pids: &[i64]) {
    hard_kill(pids);
    let _ = tokio::time::timeout(Duration::from_secs(10), dbg.kill()).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// fork — WHO is the debugger speaking for?
// ─────────────────────────────────────────────────────────────────────────────

/// Proves: the pid the debugger drives is the pid the PARENT printed, and is
/// NOT the pid the CHILD printed.
///
/// The existing suite asserts `ev.pid == pid` where `pid` came from `launch()`:
/// both sides are the crate's own answer, so a backend that spoke for the child
/// everywhere would be perfectly self-consistent. Here the two candidate pids
/// are written by the two processes themselves, before any question is asked,
/// and the test needs BOTH — with one pid in hand, "the debugger drives the
/// process it launched" cannot be told apart from "the debugger drives the only
/// process it knows about".
#[tokio::test(flavor = "multi_thread")]
async fn the_debugger_speaks_for_the_process_that_printed_parent() {
    let fx = fixtures!();
    let log = fx.dir.join("fork1.log");
    let dbg = LinuxDebugger::new();
    let pid = dbg
        .launch(opts(&fx.forker, &[log.to_str().unwrap(), &fx.newprog]))
        .await
        .expect("the forker fixture must launch under ptrace");

    let ev = resume_past_noise(&dbg).await;
    let lines = await_lines(&log, &["PARENT", "CHILD"], 5000);
    let parent = tagged(&lines, "PARENT");
    let child = tagged(&lines, "CHILD");
    let ev_pid = ev.as_ref().map(|e| i64::from(e.pid.0));
    shutdown(dbg, &[i64::from(pid.0), child.unwrap_or(0)]).await;

    // Falsify the ORACLE before believing it: two lines carrying the same
    // number would make every assertion below true by accident.
    let parent = parent.expect("the fixture must have written its PARENT line");
    let child = child.expect("the fixture must have written its CHILD line");
    assert_ne!(
        parent, child,
        "oracle guard: the two processes wrote the same pid, so the log cannot tell them apart"
    );

    assert_eq!(
        i64::from(pid.0),
        parent,
        "launch() returned {}, but the process that printed PARENT is {parent} (the forked child \
         is {child})",
        pid.0
    );
    assert_ne!(
        i64::from(pid.0),
        child,
        "the debugger is driving the FORKED CHILD ({child}), not the parent"
    );
    assert_eq!(
        ev_pid,
        Some(parent),
        "the stop was attributed to {ev_pid:?}; the process that stopped is the one that printed \
         PARENT ({parent})"
    );
}

/// Proves: exactly the process that printed `PARENT` is traced, and the one
/// that printed `CHILD` is not.
///
/// `follow_forks` is a no-op on this backend, and the existing test says so by
/// reading `TracerPid` of pids it found through `/proc` — one oracle asked
/// twice. Here the two pids come from the LOG and the tracing state from
/// `/proc`: two sources that know nothing of each other. The claim is a PAIR,
/// traced / untraced, because "somebody is traced" is satisfied by any
/// attachment at all.
#[tokio::test(flavor = "multi_thread")]
async fn only_the_process_that_printed_parent_is_traced() {
    let fx = fixtures!();
    let log = fx.dir.join("fork2.log");
    let dbg = LinuxDebugger::new();
    let pid = dbg
        .launch(opts(&fx.forker, &[log.to_str().unwrap(), &fx.newprog]))
        .await
        .expect("launch");
    let _ = resume_past_noise(&dbg).await;

    let lines = await_lines(&log, &["PARENT", "CHILD"], 5000);
    let parent = tagged(&lines, "PARENT").expect("the fixture must have written its PARENT line");
    let child = tagged(&lines, "CHILD").expect("the fixture must have written its CHILD line");
    let tp_parent = tracer_pid(parent);
    let tp_child = tracer_pid(child);
    let me = std::process::id();
    shutdown(dbg, &[i64::from(pid.0), child]).await;

    assert_ne!(parent, child, "oracle guard: the log must name two distinct processes");
    assert!(
        tp_parent.is_some_and(tracer_is_this_process),
        "the process that printed PARENT ({parent}) reports TracerPid {tp_parent:?}, which is not \
         a task of this test process ({me}); the debugger claims to be driving it"
    );
    assert_eq!(
        tp_child,
        Some(0),
        "the process that printed CHILD ({child}) reports TracerPid {tp_child:?}: with \
         follow_forks unimplemented it must be untraced, and a nonzero tracer would mean the \
         child was seized without anyone asking"
    );
}

/// Proves: the process that printed `CHILD` is the process the kernel calls a
/// child of the one that printed `PARENT`.
///
/// A cross-check between two oracles that know nothing of each other — the
/// program's own `getpid()` and `/proc/<pid>/status:PPid`. It is what makes the
/// log admissible as evidence in the two tests above: if the `CHILD` line named
/// some unrelated pid, those tests would be reading a number with no bearing on
/// this process tree.
#[tokio::test(flavor = "multi_thread")]
async fn the_pid_that_printed_child_is_the_pid_proc_calls_a_child() {
    let fx = fixtures!();
    let log = fx.dir.join("fork3.log");
    let dbg = LinuxDebugger::new();
    let pid = dbg
        .launch(opts(&fx.forker, &[log.to_str().unwrap(), &fx.newprog]))
        .await
        .expect("launch");
    let _ = resume_past_noise(&dbg).await;

    let lines = await_lines(&log, &["PARENT", "CHILD"], 5000);
    let parent = tagged(&lines, "PARENT").expect("PARENT line");
    let child = tagged(&lines, "CHILD").expect("CHILD line");
    let kids = children_of(parent);
    shutdown(dbg, &[i64::from(pid.0), child]).await;

    assert!(
        kids.contains(&child),
        "the log says {child} is the forked child of {parent}, but /proc lists that process's \
         children as {kids:?}. The two oracles disagree, so one of them is not describing this run"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// execve — does the view flip WHEN the program says it flipped?
// ─────────────────────────────────────────────────────────────────────────────

/// Proves: before the `execve` the view names the old file and the program has
/// printed only `OLD`; after it, the view names the new file and the program
/// has printed `NEWIMAGE` — under the SAME pid.
///
/// The existing exec tests resume *until* `modules()` mentions the new program
/// and then assert that `modules()` mentions the new program: the loop and the
/// assertion read the same value, so the test cannot fail for the reason it
/// names. The log breaks that circle — the program declares the flip
/// independently — and the claim is a PAIR: a view stuck on the old image fails
/// the second half, a view that named the new image from the start fails the
/// first.
#[tokio::test(flavor = "multi_thread")]
async fn the_view_flips_to_the_new_image_when_the_program_says_it_did() {
    let fx = fixtures!();
    let log = fx.dir.join("exec1.log");
    let dbg = LinuxDebugger::new();
    let pid = dbg
        .launch(opts(&fx.execer, &[log.to_str().unwrap(), &fx.newprog]))
        .await
        .expect("launch");

    // A tracee that never stops again would hang the whole run instead of
    // failing it: see `Watchdog`. Armed for the duration of the resumes.
    let watchdog = Watchdog::arm(i64::from(pid.0), 20_000);

    // Stop A: the raise(SIGTRAP) that follows the OLD line.
    let _ = resume_past_noise(&dbg).await;
    let before = await_lines(&log, &["OLD"], 5000);
    let mods_before = dbg.modules().await.unwrap_or_default();
    let main_before = mods_before.iter().find(|m| m.is_main).map(|m| m.path.clone());

    // Resume until the PROGRAM says the new image is running — not until the
    // view says so, which is the value under test.
    let mut after = Vec::new();
    let mut main_after = None;
    for _ in 0..8 {
        if resume_past_noise(&dbg).await.is_none() {
            break;
        }
        after = read_log(&log);
        if has(&after, "NEWIMAGE") {
            main_after = dbg
                .modules()
                .await
                .unwrap_or_default()
                .iter()
                .find(|m| m.is_main)
                .map(|m| m.path.clone());
            break;
        }
    }
    drop(watchdog);
    shutdown(dbg, &[i64::from(pid.0)]).await;

    assert!(has(&before, "OLD"), "the fixture never wrote its OLD line");
    assert!(
        !has(&before, "NEWIMAGE"),
        "oracle guard: the program had already exec'd before the first stop, so the 'before' half \
         is not a before-state and the pair proves nothing"
    );
    assert_eq!(
        main_before.as_deref(),
        Some(fx.execer.as_str()),
        "at the stop where the program has printed only OLD, the main module is {main_before:?}; \
         the image actually running is {}",
        fx.execer
    );

    assert!(
        has(&after, "NEWIMAGE"),
        "the program never reported reaching the new image; the log is {after:?}"
    );
    assert_eq!(
        tagged(&after, "NEWIMAGE"),
        tagged(&after, "OLD"),
        "execve keeps the pid: the process that printed NEWIMAGE must be the one that printed OLD"
    );
    assert_eq!(
        main_after.as_deref(),
        Some(fx.newprog.as_str()),
        "the program says it is running {}, and the debugger's main module is {main_after:?}. A \
         view still naming the replaced file prints well-formed addresses of an image that is gone",
        fx.newprog
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// signals — the tracee's own exit code, and the line it did NOT write
// ─────────────────────────────────────────────────────────────────────────────

/// Resume until the process ends, returning the exit code the backend reports.
async fn outcome(dbg: &LinuxDebugger, mine: u32) -> Option<i32> {
    for _ in 0..40 {
        let ev = tokio::time::timeout(Duration::from_secs(20), dbg.continue_execution())
            .await
            .ok()?
            .ok()?;
        if ev.pid.0 != mine {
            continue;
        }
        if let StopReason::ProcessExit { exit_code } = ev.reason {
            return Some(exit_code);
        }
    }
    None
}

/// Send a signal from another thread after a delay: a freshly launched tracee
/// has executed nothing of `main` and has not installed its handler yet.
///
/// `unsafe` because `libc::kill` is an FFI call; the crate lints `unsafe_code`
/// and this is the one place a test cannot avoid it — the signal has to come
/// from OUTSIDE the tracee for the delivery question to mean anything.
#[allow(unsafe_code)]
fn kill_later(pid: u32, sig: libc::c_int, after_ms: u64) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(after_ms));
        unsafe { libc::kill(pid as libc::pid_t, sig) };
    })
}

/// Proves: a forwarded signal really runs the program's handler, and the exit
/// code follows the ARGUMENT — measured with two different arguments.
///
/// `live_linux_signals.rs` asserts `exit_code == 7` against a handler compiled
/// to exit 7: the constant is written twice, once in the fixture and once in
/// the assertion, and a backend that returned a hardcoded 7 would pass. Here
/// the code is chosen by the test at launch time and the run is repeated with a
/// second value, so a constant answer fails one of the two runs; and the
/// handler writes its own line, which separates "the process exited with N"
/// from "the handler ran" — a tracee killed outright could produce neither.
#[tokio::test(flavor = "multi_thread")]
async fn a_forwarded_signal_runs_the_handler_and_the_code_follows_the_argument() {
    let fx = fixtures!();
    for code in [23i64, 41i64] {
        let log = fx.dir.join(format!("sig_h{code}.log"));
        let dbg = LinuxDebugger::new();
        let pid = dbg
            .launch(opts(
                &fx.signaller,
                &[log.to_str().unwrap(), "handled", &code.to_string()],
            ))
            .await
            .expect("launch");
        let mine = pid.0;
        let killer = kill_later(mine, libc::SIGUSR1, 500);
        let got = outcome(&dbg, mine).await;
        let _ = killer.join();
        let lines = await_lines(&log, &["READY", "HANDLER"], 2000);
        hard_kill(&[i64::from(mine)]);
        let _ = tokio::time::timeout(Duration::from_secs(10), dbg.kill()).await;

        assert!(
            has(&lines, "READY"),
            "code {code}: the fixture never reached its READY point; the log is {lines:?}"
        );
        assert_eq!(
            tagged(&lines, "HANDLER"),
            Some(code),
            "code {code}: the handler line says {:?}. Either SIGUSR1 was never delivered, or the \
             program that ran is not the one this test launched",
            tagged(&lines, "HANDLER")
        );
        assert_eq!(
            got,
            Some(code as i32),
            "code {code}: the backend reported the exit as {got:?}. The exit code is chosen by \
             argv, so an answer that does not follow it is not being read from this process"
        );
    }
}

/// Proves: the SAME signal, without a handler, kills — and leaves NO handler
/// line behind.
///
/// The control for the test above, and the reason that one is not vacuous. Both
/// runs send SIGUSR1 to the same executable; the only difference is whether the
/// program installed a handler. A backend that fabricated a plausible exit
/// code, or that dropped the signal and let the teardown kill the process
/// later, cannot produce this pair: `Some(code)` with the HANDLER line present
/// in one run, `-SIGUSR1` with the line ABSENT in the other.
#[tokio::test(flavor = "multi_thread")]
async fn the_same_signal_without_a_handler_kills_and_writes_no_handler_line() {
    let fx = fixtures!();
    let log = fx.dir.join("sig_u.log");
    let dbg = LinuxDebugger::new();
    let pid = dbg
        .launch(opts(&fx.signaller, &[log.to_str().unwrap(), "unhandled", "23"]))
        .await
        .expect("launch");
    let mine = pid.0;
    let killer = kill_later(mine, libc::SIGUSR1, 500);
    let got = outcome(&dbg, mine).await;
    let _ = killer.join();
    let lines = await_lines(&log, &["READY"], 2000);
    hard_kill(&[i64::from(mine)]);
    let _ = tokio::time::timeout(Duration::from_secs(10), dbg.kill()).await;

    assert!(has(&lines, "READY"), "the fixture never reached its READY point");
    assert!(
        !has(&lines, "HANDLER"),
        "a program with no SIGUSR1 handler wrote a HANDLER line: the oracle is not measuring what \
         it claims to measure"
    );
    assert_eq!(
        got,
        Some(-libc::SIGUSR1),
        "SIGUSR1 with no handler must kill the tracee and be reported as death by signal 10; the \
         backend said {got:?}"
    );
}

/// Proves: a forwarded SIGSEGV stops the program BEFORE the statement that
/// follows the faulting one — the line the program did NOT write is the
/// evidence.
///
/// The exit code alone cannot say this. A debugger that suppressed the fault,
/// let the program run on and then killed it during teardown could report `-11`
/// while the program had already executed past its own crash. `AFTER` is the
/// witness such a fabricated execution leaves behind, and it must be absent —
/// while `BEFORE` must be present, so an empty log (the fixture never ran at
/// all) fails too.
///
/// The undebugged run is the independent control: the same program, observed by
/// the kernel with no ptrace anywhere, must produce the same two facts.
#[tokio::test(flavor = "multi_thread")]
async fn a_forwarded_fault_stops_the_program_before_the_next_statement() {
    use std::os::unix::process::ExitStatusExt;
    let fx = fixtures!();

    // Control: no debugger at all.
    let free_log = fx.dir.join("sig_free.log");
    let st = std::process::Command::new(&fx.signaller)
        .args([free_log.to_str().unwrap(), "segv", "23"])
        .status()
        .expect("the fixture must be runnable without a debugger");
    let free_lines = read_log(&free_log);
    assert!(has(&free_lines, "BEFORE"), "control: the free run never reached BEFORE");
    assert!(
        !has(&free_lines, "AFTER"),
        "control: the free run survived its own NULL dereference, so the fixture does not fault \
         and this test would prove nothing about delivery"
    );
    assert_eq!(
        st.signal(),
        Some(libc::SIGSEGV),
        "control: run on its own the fixture must die of SIGSEGV; it ended {st:?}"
    );

    let log = fx.dir.join("sig_segv.log");
    let dbg = LinuxDebugger::new();
    let pid = dbg
        .launch(opts(&fx.signaller, &[log.to_str().unwrap(), "segv", "23"]))
        .await
        .expect("launch");
    let mine = pid.0;
    let got = outcome(&dbg, mine).await;
    let lines = await_lines(&log, &["BEFORE"], 2000);
    hard_kill(&[i64::from(mine)]);
    let _ = tokio::time::timeout(Duration::from_secs(10), dbg.kill()).await;

    assert!(
        has(&lines, "BEFORE"),
        "under the debugger the fixture never reached the statement before the fault; the log is \
         {lines:?}"
    );
    assert!(
        !has(&lines, "AFTER"),
        "the program executed the statement AFTER its NULL dereference: the fault was reported to \
         the debugger and never delivered to the program, so the execution that was observed did \
         not happen"
    );
    assert_eq!(
        got,
        Some(-libc::SIGSEGV),
        "the free run died of signal {}; under the debugger the backend reported {got:?}. A \
         debugger must not change how the program ends",
        libc::SIGSEGV
    );
}

/// No fixture of this file may outlive it.
///
/// `pgrep -x`, not `-f`: the workflow-5 agent measured that `-f` matches
/// cargo's own test binary (`live_linux_devac_fork_signals-<hash>`) and turns
/// this guard into a permanent false alarm.
#[tokio::test(flavor = "multi_thread")]
async fn zz_no_fixture_process_is_left_behind() {
    for name in ["dv_forker", "dv_execer", "dv_newprog", "dv_signaller"] {
        let out = std::process::Command::new("pgrep").args(["-x", name]).output();
        let alive = out
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        assert!(alive.is_empty(), "`{name}` is still running: pids {alive}");
    }
}
