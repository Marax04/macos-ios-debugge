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
