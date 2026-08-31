//! LIVE Linux debugger coverage for the *inspection* half of the `Debugger`
//! trait: `threads`, `current_thread`, `modules`, `memory_maps`, `backtrace`,
//! `target_pid` and `is_attached`.
//!
//! Every test here drives a REAL process: a small pthread fixture is compiled
//! with `cc` into a temp dir, launched under `ptrace(2)` via `LinuxDebugger`,
//! resumed to a known synchronisation point (`raise(SIGTRAP)`, reached only
//! after the worker thread is live) and then interrogated. Nothing here is
//! built in memory — a struct literal proves the type compiles, not that the
//! backend reads `/proc` correctly.
#![cfg(target_os = "linux")]

use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_core::address::Address;
use rustre_debug::{DebugError, Debugger, LaunchOptions, OutputRedirect, StopReason, ThreadId};
use std::collections::HashMap;
use std::time::Duration;

/// Worker spins forever so the secondary thread is guaranteed alive when the
/// main thread reaches `raise(SIGTRAP)`; main spins afterwards so the process
/// cannot exit under us while we inspect it.
const FIXTURE_C: &str = r#"
#include <pthread.h>
#include <signal.h>
static volatile int ready = 0;
static void *worker(void *arg) { (void)arg; ready = 1; for (;;) { } return 0; }
int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    while (!ready) { }
    raise(SIGTRAP);
    for (;;) { }
    return 0;
}
"#;

/// Compile the fixture; `None` when this machine has no working `cc`.
fn build_fixture(tag: &str) -> Option<String> {
    let dir = std::env::temp_dir();
    let src = dir.join(format!("rustre_tm_{tag}_{}.c", std::process::id()));
    let bin = dir.join(format!("rustre_tm_{tag}_{}", std::process::id()));
    std::fs::write(&src, FIXTURE_C).ok()?;
    let out = std::process::Command::new("cc")
        .arg(src.to_str()?)
        .arg("-o")
        .arg(bin.to_str()?)
        .arg("-lpthread")
        .arg("-O0")
        .output()
        .ok()?;
    let _ = std::fs::remove_file(&src);
    if !out.status.success() {
        return None;
    }
    Some(bin.to_str()?.to_string())
}

fn opts_for(bin: &str) -> LaunchOptions {
    LaunchOptions {
        executable: bin.to_string(),
        args: vec![],
        env: HashMap::new(),
        working_dir: None,
        stop_at_entry: false,
        follow_forks: false,
        redirect: OutputRedirect::default(),
    }
}

/// A live target parked at its own `SIGTRAP`, plus the fixture path so the
/// caller can compare `modules()` against the binary that is really running.
struct Target {
    dbg: LinuxDebugger,
    bin: String,
    pid: u32,
}

impl Target {
    /// Launch the fixture and resume past any thread-birth stops.
    ///
    /// The loop consumes exactly the `ThreadCreate` stops the kernel chooses to
    /// deliver and stops the moment a stop is something else — resuming *until*
    /// a condition holds would block forever on a platform that never sends
    /// another stop, which is a hang, not a failure.
    async fn start(tag: &str) -> Option<Self> {
        let bin = build_fixture(tag)?;
        let dbg = LinuxDebugger::new();
        let pid = dbg
            .launch(opts_for(&bin))
            .await
            .expect("the pthread fixture must launch under ptrace");
        let mut ev = tokio::time::timeout(Duration::from_secs(30), dbg.continue_execution())
            .await
            .expect("continue_execution must not hang")
            .expect("continue_execution must not error");
        for _ in 0..64 {
            match ev.reason {
                StopReason::ThreadCreate { .. } => {
                    ev = tokio::time::timeout(Duration::from_secs(30), dbg.continue_execution())
                        .await
                        .expect("continue_execution must not hang")
                        .expect("continue_execution must not error");
                }
                _ => break,
            }
        }
        Some(Self {
            dbg,
            bin,
            pid: pid.0,
        })
    }
}

impl Target {
    /// Tear the tracee down through the debugger itself.
    ///
    /// This is NOT optional politeness. The backend's event loop reaps with
    /// `waitpid(-1, __WALL)`, which is process-global: a debugger whose loop is
    /// still running when the next test launches its own child will reap that
    /// child's stops. Measured while writing this file — with only the
    /// `Drop`-time `kill -9` for teardown, three tests failed with a
    /// `current_thread()` from a PREVIOUS test's process and a thread list of
    /// one. Ending the session explicitly stops that loop.
    async fn shutdown(self) {
        let _ = self.dbg.kill().await;
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        // SIGKILL directly: the fixture spins forever, so leaking it costs a
        // whole core for the rest of the run.
        // Safety net only — `shutdown` is the real teardown. `output()` rather
        // than `status()` so "No such process" does not pollute the test log
        // when the process is already gone.
        let _ = std::process::Command::new("kill")
            .arg("-9")
            .arg(self.pid.to_string())
            .output();
        let _ = std::fs::remove_file(&self.bin);
    }
}

/// The tids `/proc/<pid>/task` really lists, read independently of the crate.
fn proc_task_tids(pid: u32) -> Vec<u32> {
    let mut v: Vec<u32> = std::fs::read_dir(format!("/proc/{pid}/task"))
        .expect("/proc/<pid>/task must exist for a live process")
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    v.sort_unstable();
    v
}

macro_rules! live {
    ($t:expr) => {
        match Target::start($t).await {
            Some(t) => t,
            None => {
                eprintln!("skipping: no working `cc` to build the pthread fixture");
                return;
            }
        }
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// is_attached / target_pid
// ─────────────────────────────────────────────────────────────────────────────

/// `is_attached`/`target_pid` must report the state a caller can act on, and
/// the pid must be the one the kernel really gave the child.
///
/// This is the right behaviour because every other method on the trait is only
/// meaningful while attached: a debugger that says "attached" with no process,
/// or reports a pid that is not the tracee, makes each subsequent answer
/// unfalsifiable. Verified against `/proc/<pid>` rather than against the value
/// `launch` returned, so the two cannot agree while both being wrong.
#[tokio::test]
async fn attachment_state_and_pid_match_the_real_child() {
    let fresh = LinuxDebugger::new();
    assert!(!fresh.is_attached(), "a new debugger owns no process");
    assert_eq!(fresh.target_pid(), None, "no process means no pid");

    let t = live!("state");
    assert!(t.dbg.is_attached(), "after launch a process is attached");
    assert_eq!(
        t.dbg.target_pid().map(|p| p.0),
        Some(t.pid),
        "target_pid must be the launched child"
    );
    assert!(
        std::path::Path::new(&format!("/proc/{}", t.pid)).is_dir(),
        "the reported pid must be a process that actually exists"
    );
    let comm = std::fs::read_to_string(format!("/proc/{}/comm", t.pid)).unwrap_or_default();
    assert!(
        !comm.trim().is_empty(),
        "the reported pid must name a live task, got an empty comm"
    );

    t.shutdown().await;
}

/// After `kill`, the inspection methods must FAIL rather than answer from
/// stale bookkeeping.
///
/// An empty `Ok(vec![])` and an error are opposite claims: the first says the
/// process has no threads/modules, the second says there is no process. A
/// caller polling a dead target would loop forever on the first.
#[tokio::test]
async fn inspection_fails_after_the_process_is_killed() {
    let t = live!("killed");
    t.dbg
        .kill()
        .await
        .expect("kill must succeed on a live tracee");

    assert!(!t.dbg.is_attached(), "kill must clear the attachment");
    assert_eq!(t.dbg.target_pid(), None, "kill must clear the pid");
    assert!(
        t.dbg.threads().await.is_err(),
        "threads() on a killed target must error"
    );
    assert!(
        t.dbg.modules().await.is_err(),
        "modules() on a killed target must error"
    );
    assert!(
        t.dbg.memory_maps().await.is_err(),
        "memory_maps() on a killed target must error"
    );

    t.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// threads / current_thread
// ─────────────────────────────────────────────────────────────────────────────

/// `threads()` must enumerate exactly what `/proc/<pid>/task` lists.
///
/// That directory IS the kernel's thread list, so any difference is the
/// backend's error, not the kernel's. The fixture guarantees at least two live
/// threads at the sync point, which is what separates "reads the task dir"
/// from "returns the pid it already knew".
#[tokio::test]
async fn threads_enumerate_every_live_task() {
    let t = live!("threads");
    let mut got: Vec<u32> = t
        .dbg
        .threads()
        .await
        .expect("threads() must succeed on a live target")
        .into_iter()
        .map(|x| x.0)
        .collect();
    got.sort_unstable();
    let expected = proc_task_tids(t.pid);

    assert!(
        got.contains(&t.pid),
        "the main thread's tid equals the pid on Linux; got {got:?}"
    );
    assert_eq!(got, expected, "threads() must match /proc/{}/task exactly", t.pid);
    assert!(
        got.len() >= 2,
        "the pthread fixture is parked after its worker is live, so at least two \
         threads must be visible; got {got:?}"
    );
    let mut dedup = got.clone();
    dedup.dedup();
    assert_eq!(dedup.len(), got.len(), "threads() must not repeat a tid");

    t.shutdown().await;
}

/// `current_thread()` must name a thread that `threads()` also lists, and it
/// must be the thread that actually caused the stop.
///
/// A stop is attributed to one thread; a `current_thread` that answers with a
/// tid outside the live set would send every per-tid call (`get_registers`,
/// `single_step`, `backtrace`) at a thread that does not exist.
#[tokio::test]
async fn current_thread_is_a_live_thread_of_this_process() {
    let t = live!("current");
    let cur = t
        .dbg
        .current_thread()
        .await
        .expect("current_thread() must succeed while stopped");
    let live: Vec<u32> = t
        .dbg
        .threads()
        .await
        .expect("threads() must succeed")
        .into_iter()
        .map(|x| x.0)
        .collect();
    assert!(
        live.contains(&cur.0),
        "current_thread() returned {cur:?}, which threads() does not list: {live:?}"
    );
    assert!(
        std::path::Path::new(&format!("/proc/{}/task/{}", t.pid, cur.0)).is_dir(),
        "current_thread() must name a task that really exists"
    );
    assert_eq!(
        cur.0, t.pid,
        "the fixture raises SIGTRAP on its MAIN thread, so the stop must be \
         attributed to the main tid"
    );

    t.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// modules
// ─────────────────────────────────────────────────────────────────────────────

/// `modules()` must report the main executable, at its real load base, with a
/// path that is the binary on disk.
///
/// The main module is the anchor every address in a report is relative to: get
/// its base wrong and every symbolised address is wrong by a constant. The
/// base is cross-checked against the first mapping of that path in
/// `/proc/<pid>/maps`, read here directly.
#[tokio::test]
async fn modules_report_the_main_executable_at_its_real_base() {
    let t = live!("modules");
    let mods = t
        .dbg
        .modules()
        .await
        .expect("modules() must succeed on a live target");
    assert!(
        !mods.is_empty(),
        "a live process always has at least one module"
    );

    let mains: Vec<_> = mods.iter().filter(|m| m.is_main).collect();
    assert_eq!(
        mains.len(),
        1,
        "exactly one module is the main executable: {mains:?}"
    );
    let main = mains[0];
    assert_eq!(
        main.path, t.bin,
        "the main module's path must be the binary that was launched"
    );
    let base_name = std::path::Path::new(&t.bin)
        .file_name()
        .and_then(|s| s.to_str())
        .expect("the fixture path has a basename");
    assert_eq!(
        main.name, base_name,
        "the module name must be the basename of its path"
    );
    assert_ne!(main.base.0, 0, "a mapped module cannot be based at 0");

    // Ground truth straight out of /proc, not out of the crate.
    let maps = std::fs::read_to_string(format!("/proc/{}/maps", t.pid))
        .expect("/proc/<pid>/maps must be readable for our own tracee");
    let first_base = maps
        .lines()
        .find(|l| l.ends_with(&t.bin))
        .and_then(|l| l.split('-').next())
        .and_then(|h| u64::from_str_radix(h, 16).ok())
        .expect("the fixture must be mapped in its own /proc/<pid>/maps");
    assert_eq!(
        main.base.0, first_base,
        "the main module base must be the first mapping of that file"
    );

    // libc is dynamically linked into the fixture, so more than one module
    // must be visible — a backend that only reported the executable would pass
    // every assertion above.
    assert!(
        mods.len() >= 2,
        "the fixture links libc/libpthread dynamically, so several modules must \
         be reported; got {:?}",
        mods.iter().map(|m| &m.name).collect::<Vec<_>>()
    );
    let mut paths: Vec<&str> = mods.iter().map(|m| m.path.as_str()).collect();
    paths.sort_unstable();
    let n = paths.len();
    paths.dedup();
    assert_eq!(paths.len(), n, "modules() must report each mapped file once");

    t.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// memory_maps
// ─────────────────────────────────────────────────────────────────────────────

/// `memory_maps()` must reproduce the live `/proc/<pid>/maps` layout: same
/// region count, same bases, non-empty sizes, and permissions that agree.
///
/// The map is what makes an address meaningful (is it code? is it writable?),
/// so a region that is missing or mis-permissioned silently changes the answer
/// to "can I plant a breakpoint here".
#[tokio::test]
async fn memory_maps_reproduce_proc_maps() {
    let t = live!("maps");
    let maps = t
        .dbg
        .memory_maps()
        .await
        .expect("memory_maps() must succeed");
    assert!(!maps.is_empty(), "a live process always has mappings");

    let raw = std::fs::read_to_string(format!("/proc/{}/maps", t.pid))
        .expect("/proc/<pid>/maps must be readable");
    let raw_bases: Vec<u64> = raw
        .lines()
        .filter_map(|l| u64::from_str_radix(l.split('-').next()?, 16).ok())
        .collect();

    for m in &maps {
        assert!(m.size > 0, "a mapping of zero bytes is not a mapping: {m:?}");
        assert!(
            raw_bases.contains(&m.base.0),
            "memory_maps() reported base {:#x}, which /proc/<pid>/maps does not list",
            m.base.0
        );
    }
    // Same population, not merely a subset: a parser that dropped every line it
    // did not understand would pass the loop above.
    assert_eq!(
        maps.len(),
        raw_bases.len(),
        "memory_maps() must report as many regions as /proc/<pid>/maps has lines"
    );
    assert!(
        maps.iter().any(|m| m.executable && m.readable),
        "a running process must have at least one r-x region"
    );
    assert!(
        maps.iter().any(|m| m.writable && !m.executable),
        "a running process must have at least one writable data region"
    );
    assert!(
        maps.iter().any(|m| m.name.as_deref() == Some("[stack]")),
        "the main thread's [stack] must appear in the map"
    );

    // Cross-check with the OTHER parser in the same backend: every module base
    // must be an address the map also covers. The two read the same lines with
    // different column counts and have drifted apart before.
    let mods = t.dbg.modules().await.expect("modules() must succeed");
    for m in &mods {
        assert!(
            maps.iter()
                .any(|r| m.base.0 >= r.base.0 && m.base.0 < r.base.0 + r.size),
            "module {} is based at {:#x}, which no reported mapping covers",
            m.name,
            m.base.0
        );
    }

    t.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// backtrace
// ─────────────────────────────────────────────────────────────────────────────

/// `backtrace()` on the stopped thread must produce a coherent stack: frames
/// indexed from 0 upward, frame 0's PC inside an executable mapping, every
/// stack pointer inside a mapped region, and no more frames than this backend
/// declares it walks.
///
/// Those are the properties a caller can rely on without symbols. A frame
/// whose PC is not executable is not a return address, and an index sequence
/// with a hole makes "the caller of frame N" meaningless.
#[tokio::test]
async fn backtrace_frames_are_coherent_against_the_live_memory_map() {
    let t = live!("bt");
    let tid = t
        .dbg
        .current_thread()
        .await
        .expect("current_thread() must succeed");
    let frames = t
        .dbg
        .backtrace(tid)
        .await
        .expect("backtrace() must succeed for the stopped thread");
    assert!(
        !frames.is_empty(),
        "a stopped thread always has at least one frame"
    );
    assert!(
        frames.len() <= t.dbg.backtrace_frame_cap(),
        "backtrace() returned {} frames but this backend declares a cap of {}",
        frames.len(),
        t.dbg.backtrace_frame_cap()
    );

    for (i, f) in frames.iter().enumerate() {
        assert_eq!(
            f.index, i,
            "frame indices must be 0..n with no holes: {frames:?}"
        );
    }

    let maps = t
        .dbg
        .memory_maps()
        .await
        .expect("memory_maps() must succeed");
    let covers = |a: Address| {
        maps.iter()
            .find(|r| a.0 >= r.base.0 && a.0 < r.base.0 + r.size)
    };
    let pc0 = frames[0].pc;
    let r = covers(pc0).unwrap_or_else(|| panic!("frame 0 pc {:#x} is unmapped", pc0.0));
    assert!(
        r.executable,
        "frame 0 pc {:#x} lands in a non-executable region {:?}",
        pc0.0, r.name
    );
    for f in &frames {
        assert!(
            covers(f.sp).is_some(),
            "frame {} has stack pointer {:#x}, which no mapping covers",
            f.index,
            f.sp.0
        );
    }

    t.shutdown().await;
}

/// A tid that belongs to no thread of this process must be REFUSED.
///
/// Silently unwinding the wrong (or the attached) thread would be the worst
/// outcome: the caller gets a plausible stack for a thread it never asked
/// about. An error is the only answer that cannot be mistaken for data.
#[tokio::test]
async fn backtrace_refuses_a_tid_that_is_not_ours() {
    let t = live!("btbogus");
    let live: Vec<u32> = t
        .dbg
        .threads()
        .await
        .expect("threads() must succeed")
        .into_iter()
        .map(|x| x.0)
        .collect();
    // A tid far above the live set; re-checked against /proc so we cannot
    // accidentally pick a real one.
    let bogus = live.iter().max().copied().unwrap_or(1) + 900_000;
    assert!(
        !std::path::Path::new(&format!("/proc/{}/task/{bogus}", t.pid)).exists(),
        "the test's bogus tid must really not exist"
    );

    match t.dbg.backtrace(ThreadId(bogus)).await {
        Err(_) => {}
        Ok(frames) => panic!(
            "backtrace({bogus}) must fail for a tid this process does not own, \
             got {} frames: {frames:?}",
            frames.len()
        ),
    }

    t.shutdown().await;
}

/// The secondary thread created by `pthread_create` must be unwindable too.
///
/// `threads()` advertising a thread that `backtrace()` cannot walk is the
/// difference between enumerating threads and debugging them, and it is the
/// exact gap the trait doc-comment on `threads()` warns about.
#[tokio::test]
async fn every_enumerated_thread_can_be_unwound() {
    let t = live!("btall");
    let main = t
        .dbg
        .current_thread()
        .await
        .expect("current_thread() must succeed");
    let tids = t.dbg.threads().await.expect("threads() must succeed");
    let secondary: Vec<ThreadId> = tids.into_iter().filter(|x| *x != main).collect();
    assert!(
        !secondary.is_empty(),
        "the fixture must expose a secondary thread for this test to mean anything"
    );

    for tid in secondary {
        match t.dbg.backtrace(tid).await {
            Ok(frames) => assert!(
                !frames.is_empty(),
                "backtrace({tid:?}) succeeded with zero frames — a live thread \
                 always has at least one"
            ),
            Err(DebugError::Unsupported(_)) => {}
            Err(e) => {
                panic!("threads() advertised {tid:?} but backtrace() could not walk it: {e:?}")
            }
        }
    }

    t.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Falsification guards
// ─────────────────────────────────────────────────────────────────────────────
//
// The workflow-5 falsification campaign shifted the one external symbol oracle
// (`nm`, by `0x40`) under every live suite and re-ran them. This file lost ONE
// test of nine — for the simple reason that it never consulted `nm` at all.
// That is not innocence: it means the strongest claims here are checked against
// something weaker than a symbol table.
//
// Two of them were checked against nothing outside the crate at all:
//
// * `backtrace_frames_are_coherent_against_the_live_memory_map` asserts that
//   frame indices run 0..n, that frame 0's pc is executable and that every sp
//   is mapped. Every one of those holds for a walk that returns the wrong
//   frames: any address inside `.text` is executable, any address inside the
//   stack region is a plausible sp. It checks that the shape of a stack is a
//   stack, never that it is THIS program's stack.
// * `memory_maps_reproduce_proc_maps` compares bases and the region COUNT, and
//   its own doc-comment promises "permissions that agree" — which no assertion
//   in it checks. The end of each region is not checked either, so a parser
//   that read the wrong column for the size passes.
//
// `modules_report_the_main_executable_at_its_real_base` is the strong one of
// the three: it already reads `/proc/<pid>/maps` directly. But it only requires
// `len() >= 2`, so a backend that reported the executable and one library out
// of five would pass.
//
// The guards below fix all three against ground truth the crate does not
// produce: `nm -S` for the call chain, and the kernel's own text file for the
// map, compared as SETS rather than as counts — a count stays green when the
// truth underneath it moves, an exact set does not.

/// A fixture with a call chain that is unambiguous from the source: `main`
/// calls `level1` calls `level2` calls `level3`, which raises SIGTRAP and then
/// spins so the process cannot exit while we walk its stack.
const CHAIN_C: &str = r#"
#include <signal.h>
__attribute__((noinline)) void level3(void) { raise(SIGTRAP); for (;;) { } }
__attribute__((noinline)) void level2(void) { level3(); }
__attribute__((noinline)) void level1(void) { level2(); }
int main(void) { level1(); return 0; }
"#;

/// The chain as the SOURCE states it, innermost first. This is the ground
/// truth: it comes from the C above, not from any address.
const CHAIN: [&str; 4] = ["level3", "level2", "level1", "main"];

/// Build the call-chain fixture `-no-pie`, so the addresses `nm` prints are the
/// addresses the process really executes. `None` when `cc` is unusable here.
fn build_chain_fixture() -> Option<std::path::PathBuf> {
    let dir = std::env::temp_dir();
    let src = dir.join(format!("rustre_chain_{}.c", std::process::id()));
    let bin = dir.join(format!("rustre_chain_{}", std::process::id()));
    std::fs::write(&src, CHAIN_C).ok()?;
    let out = std::process::Command::new("cc")
        .args(["-no-pie", "-O0", "-g"])
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .output()
        .ok()?;
    let _ = std::fs::remove_file(&src);
    if !out.status.success() {
        return None;
    }
    Some(bin)
}

/// `(name, start, end)` for every TEXT symbol, from `nm -S --defined-only`.
///
/// The SIZE column is what makes this an interval rather than a point, and an
/// interval is what turns a program counter into a function name without asking
/// the crate under test to do it.
fn nm_text_ranges(exe: &std::path::Path) -> Vec<(String, u64, u64)> {
    let out = std::process::Command::new("nm")
        .args(["-S", "--defined-only"])
        .arg(exe)
        .output()
        .expect("nm -S --defined-only must be available");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() != 4 {
                return None;
            }
            let addr = u64::from_str_radix(f[0], 16).ok()?;
            let size = u64::from_str_radix(f[1], 16).ok()?;
            (f[2] == "T" || f[2] == "t").then(|| (f[3].to_string(), addr, addr + size))
        })
        .collect()
}

/// `backtrace()` must name the call chain the SOURCE describes, in order.
///
/// This is the guard against the vacuity of
/// `backtrace_frames_are_coherent_against_the_live_memory_map`, which checks
/// that frame 0 is executable and every sp is mapped — properties any wrong
/// walk of a real process satisfies. Here each frame's pc is turned into a
/// function name by `nm -S`, ground truth the crate never touches, and the
/// four fixture frames that appear must be exactly `level3, level2, level1,
/// main` in that order.
///
/// Frames belonging to libc (the `raise` machinery below `level3`, and
/// `__libc_start_call_main` above `main`) are not named by `nm` on this
/// executable and are deliberately ignored: the claim is about the ORDER and
/// IDENTITY of the fixture's own frames, and a walk that lost `level2`, or
/// returned the chain reversed, or duplicated a frame, fails it.
#[tokio::test]
async fn backtrace_names_the_call_chain_the_source_describes() {
    let Some(bin) = build_chain_fixture() else {
        eprintln!("skipping: no working `cc -no-pie` to build the call-chain fixture");
        return;
    };
    let ranges = nm_text_ranges(&bin);
    for want in CHAIN {
        assert!(
            ranges.iter().any(|(n, s, e)| n == want && e > s),
            "guard: `nm -S` must give `{want}` a non-empty range, otherwise this test has no \
             oracle; got {ranges:?}"
        );
    }

    let dbg = LinuxDebugger::new();
    let pid = dbg
        .launch(opts_for(bin.to_str().expect("utf-8 fixture path")))
        .await
        .expect("the call-chain fixture must launch under ptrace")
        .0;
    // Resume to the fixture's own `raise(SIGTRAP)`; thread births and library
    // events are not stops of interest and there are none in this fixture.
    let mut walked = None;
    for _ in 0..16 {
        let Ok(_ev) = tokio::time::timeout(Duration::from_secs(30), dbg.continue_execution())
            .await
            .expect("continue_execution must not hang")
        else {
            break;
        };
        let Ok(tid) = dbg.current_thread().await else { break };
        if let Ok(frames) = dbg.backtrace(tid).await {
            walked = Some(frames);
            break;
        }
    }
    let frames = walked.expect("the fixture must stop at its own raise(SIGTRAP) and be walkable");
    let named: Vec<String> = frames
        .iter()
        .filter_map(|f| {
            ranges
                .iter()
                .find(|(_, s, e)| f.pc.0 >= *s && f.pc.0 < *e)
                .map(|(n, _, _)| n.clone())
        })
        .filter(|n| CHAIN.contains(&n.as_str()))
        .collect();
    let raw: Vec<String> = frames.iter().map(|f| format!("{:#x}", f.pc.0)).collect();
    let _ = dbg.kill().await;
    let _ = std::fs::remove_file(&bin);

    assert_eq!(
        named,
        CHAIN.to_vec(),
        "the stack walk named {named:?}, but the source says the chain is {CHAIN:?} \
         (pid {pid}, raw frame pcs {raw:?}); coherent-looking frames are not the same as the \
         right frames"
    );
}

/// `modules()` must report EXACTLY the file-backed mappings the kernel lists.
///
/// `modules_report_the_main_executable_at_its_real_base` requires `len() >= 2`,
/// which a backend reporting the executable and one library out of five
/// satisfies, and which stays green whatever the truth underneath does. A count
/// is slack; the set of PATHS is not — this fails if a module is invented, and
/// it fails if one is dropped.
#[tokio::test]
async fn modules_are_exactly_the_file_backed_mappings_the_kernel_lists() {
    let t = live!("modset");
    let mods = t.dbg.modules().await.expect("modules() must succeed on a live target");
    let raw = std::fs::read_to_string(format!("/proc/{}/maps", t.pid))
        .expect("/proc/<pid>/maps must be readable for our own tracee");

    // Column 6 of a maps line is the backing file, when there is one. Only
    // absolute paths are real files: `[stack]`, `[vdso]` and friends are
    // kernel-synthesised names, not modules.
    let mut kernel: Vec<&str> = raw
        .lines()
        .filter_map(|l| l.split_whitespace().nth(5))
        .filter(|p| p.starts_with('/'))
        .collect();
    kernel.sort_unstable();
    kernel.dedup();
    assert!(
        kernel.len() >= 2,
        "guard: the fixture links libc dynamically, so the kernel must list several backing \
         files; got {kernel:?}"
    );

    let mut got: Vec<&str> = mods.iter().map(|m| m.path.as_str()).collect();
    got.sort_unstable();
    let before_dedup = got.len();
    got.dedup();
    assert_eq!(before_dedup, got.len(), "modules() must report each mapped file once, got {got:?}");
    assert_eq!(
        got, kernel,
        "modules() reported {got:?} but /proc/{}/maps is backed by {kernel:?}; the two must be \
         the same set, not merely overlap",
        t.pid
    );

    t.shutdown().await;
}

/// `memory_maps()` must reproduce the kernel's EXTENTS and PERMISSION BITS, not
/// only its bases.
///
/// `memory_maps_reproduce_proc_maps` promises in its own doc-comment
/// "permissions that agree" and then asserts nothing about them; it also never
/// checks where a region ENDS, so a parser that took the wrong column for the
/// size passes it. Both are checked here against `/proc/<pid>/maps` line by
/// line, and in both directions: every kernel region must be reported, and
/// every reported region must be a kernel one.
#[tokio::test]
async fn memory_maps_reproduce_the_kernels_extents_and_permission_bits() {
    let t = live!("perms");
    let maps = t.dbg.memory_maps().await.expect("memory_maps() must succeed");
    let raw = std::fs::read_to_string(format!("/proc/{}/maps", t.pid))
        .expect("/proc/<pid>/maps must be readable");

    // (base, end, "rwx") straight out of the kernel's text file.
    let kernel: Vec<(u64, u64, String)> = raw
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let (range, perm) = (it.next()?, it.next()?);
            let (a, b) = range.split_once('-')?;
            Some((
                u64::from_str_radix(a, 16).ok()?,
                u64::from_str_radix(b, 16).ok()?,
                perm.chars().take(3).collect::<String>(),
            ))
        })
        .collect();
    assert!(!kernel.is_empty(), "the kernel listed no mappings for a live process");
    assert!(
        kernel.iter().any(|(_, _, p)| p == "r-x"),
        "guard: a running process must have an r-x mapping, so the oracle itself is suspect: \
         {kernel:?}"
    );

    let reported: Vec<(u64, u64, String)> = maps
        .iter()
        .map(|m| {
            (
                m.base.0,
                m.base.0 + m.size,
                format!(
                    "{}{}{}",
                    if m.readable { "r" } else { "-" },
                    if m.writable { "w" } else { "-" },
                    if m.executable { "x" } else { "-" }
                ),
            )
        })
        .collect();

    let missing: Vec<&(u64, u64, String)> =
        kernel.iter().filter(|k| !reported.contains(k)).collect();
    let invented: Vec<&(u64, u64, String)> =
        reported.iter().filter(|r| !kernel.contains(r)).collect();
    let pid = t.pid;
    t.shutdown().await;

    assert!(
        missing.is_empty() && invented.is_empty(),
        "memory_maps() and /proc/{pid}/maps disagree on {} region(s) the kernel lists and {} the \
         backend invented; kernel-only {:x?}, backend-only {:x?}. Each triple is \
         (base, end, permissions): a difference in the third field is a wrong answer to \
         \"can I plant a breakpoint here\", a difference in the second is a wrong size",
        missing.len(),
        invented.len(),
        &missing[..missing.len().min(4)],
        &invented[..invented.len().min(4)]
    );
}

/// No fixture process may outlive this suite.
///
/// Named `zz_` so it runs last under `--test-threads=1`. `-x` matches the
/// process NAME exactly; `-f` was measured in `live_linux_falsification.rs` to
/// match cargo's own `live_linux_threads_modules-<hash>` binary, so a check
/// written that way reports the thing looking for orphans as an orphan.
#[tokio::test]
async fn zz_no_orphan_thread_fixture_survives() {
    let pid = std::process::id();
    let mut names = vec![format!("rustre_chain_{pid}")];
    // Every tag `live!` is invoked with in this file: the fixture is named
    // `rustre_tm_<tag>_<pid>`, so the check has to name them one by one — a
    // prefix match would be `pgrep -f`, which matches this very test binary.
    for tag in
        ["state", "killed", "threads", "current", "modules", "maps", "bt", "btbogus", "btall",
         "modset", "perms"]
    {
        names.push(format!("rustre_tm_{tag}_{pid}"));
    }
    // Linux truncates a process name to 15 characters (`TASK_COMM_LEN - 1`), and
    // `pgrep -x` matches that truncated name. Measured: the untruncated
    // `rustre_chain_<pid>` is 18 characters, and pgrep answers
    // "pattern that searches for process name longer than 15 characters will
    // result in zero matches" — i.e. this guard could never have gone red, the
    // same shape of self-satisfying check `live_linux_falsification.rs` found in
    // its own orphan test.
    for name in names.iter().map(|n| n.chars().take(15).collect::<String>()) {
        let Ok(out) = std::process::Command::new("pgrep").args(["-x", &name]).output() else {
            eprintln!("[test] pgrep is unavailable; the orphan check cannot run");
            return;
        };
        let listed: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        assert!(
            listed.is_empty(),
            "the suite left {} `{name}` process(es) behind: {listed:?}",
            listed.len()
        );
    }
}

/// A SIGTRAP the PROGRAM raised must not be reported as a single step.
///
/// MEASURED RED, and left `#[ignore]` because the fix is a backend change, not
/// a test change. The fixture calls `raise(SIGTRAP)` and the debugger has never
/// requested a step; the backend answers
/// `SingleStep { address: Address(0x7f6174c9ec0c) }`.
///
/// Why it matters rather than being a naming quibble: `StopReason::SingleStep`
/// is the answer to "did the step I asked for complete?", and a caller that is
/// not stepping has no reason to expect it. A stepping loop that resumes on
/// every `SingleStep` will resume straight through a trap the program raised
/// deliberately — a `__builtin_trap`, an assertion, a debugger-detection probe
/// — and report that the step finished. The three cases the backend can
/// actually distinguish are: a SIGTRAP after a step it requested, a SIGTRAP
/// with one of its own `0xCC` bytes at `pc - 1`, and a SIGTRAP that is neither.
/// The third has no variant of its own here and is being folded into the first.
///
/// Found while writing `backtrace_names_the_call_chain_the_source_describes`,
/// which needs this stop only as a synchronisation point and so is indifferent
/// to what it is called. `Target::start` above is indifferent for the same
/// reason: it resumes past `ThreadCreate` and accepts whatever comes next,
/// which is why the whole file could rest on this stop for as long as it has
/// without anyone reading its name.
#[tokio::test]
#[ignore = "backend reports a program's own raise(SIGTRAP) as StopReason::SingleStep; backend fix, not a test fix"]
async fn a_sigtrap_the_program_raised_is_not_a_single_step() {
    let Some(bin) = build_chain_fixture() else {
        eprintln!("skipping: no working `cc -no-pie` to build the call-chain fixture");
        return;
    };
    let dbg = LinuxDebugger::new();
    dbg.launch(opts_for(bin.to_str().expect("utf-8 fixture path")))
        .await
        .expect("the call-chain fixture must launch under ptrace");
    let ev = tokio::time::timeout(Duration::from_secs(30), dbg.continue_execution())
        .await
        .expect("continue_execution must not hang")
        .expect("continue_execution must not error");
    let reason = format!("{:?}", ev.reason);
    let stepped = matches!(ev.reason, StopReason::SingleStep { .. });
    let _ = dbg.kill().await;
    let _ = std::fs::remove_file(&bin);
    assert!(
        !stepped,
        "the program called raise(SIGTRAP) and nothing ever asked this debugger to step, but \
         the stop came back as {reason}"
    );
}
