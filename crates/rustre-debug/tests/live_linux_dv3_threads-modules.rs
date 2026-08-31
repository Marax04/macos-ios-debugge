//! LIVE Linux guards for the claims `live_linux_threads_modules.rs` does NOT
//! make. Written after measuring that file's bite by corrupting each of its
//! external oracles one at a time (see `status_parts/dv3-threads-modules.md`).
//!
//! Three holes were measured there and are closed here:
//!
//! * `backtrace(tid)` is never checked to actually USE the tid. Every backtrace
//!   assertion in that file is made about the stopped main thread, or (in
//!   `every_enumerated_thread_can_be_unwound`) about the secondary thread with
//!   an oracle so weak — "at least one frame" — that returning the MAIN
//!   thread's stack for the worker passes it. A per-thread walk and a global
//!   walk are indistinguishable to it.
//! * `modules_report_the_main_executable_at_its_real_base` cross-checks ONE
//!   base against `/proc/<pid>/maps`. Shifting that single oracle by 0x1000 was
//!   measured RED, so the check bites — for the main module only. Every library
//!   base is unchecked: the whole set of paths is compared
//!   (`modules_are_exactly_the_file_backed_mappings_the_kernel_lists`) but not
//!   one of their addresses, and a module base is exactly the constant every
//!   symbolised address in that module is off by.
//! * `every_enumerated_thread_can_be_unwound` exempts itself: an
//!   `Err(DebugError::Unsupported(_))` arm passes silently, so the test stays
//!   green on a backend that walks no secondary thread at all, and nothing
//!   records that the claim was skipped.
//!
//! Nothing here is built in memory. Every oracle is either the kernel's own
//! `/proc/<pid>/maps` and `/proc/<pid>/task`, or `nm -S` over the fixture — none
//! of which the crate under test produces.
#![cfg(target_os = "linux")]

use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::{Debugger, LaunchOptions, OutputRedirect, StopReason, ThreadId};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

/// Two threads whose innermost functions are DIFFERENT and named in the source.
///
/// The worker parks in `worker_spin` and stays there; the main thread descends
/// `main → level1 → level2 → level3` and raises SIGTRAP inside `level3`. So at
/// the sync point the two threads' program counters lie in disjoint functions,
/// which is what makes "did `backtrace` read the tid?" answerable.
const FIXTURE_C: &str = r#"
#include <pthread.h>
#include <signal.h>
static volatile int ready = 0;
__attribute__((noinline)) void worker_spin(void) { ready = 1; for (;;) { } }
static void *worker(void *a) { (void)a; worker_spin(); return 0; }
__attribute__((noinline)) void level3(void) { raise(SIGTRAP); for (;;) { } }
__attribute__((noinline)) void level2(void) { level3(); }
__attribute__((noinline)) void level1(void) { level2(); }
int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    while (!ready) { }
    level1();
    return 0;
}
"#;

/// The main thread's chain as the SOURCE states it, innermost first.
const MAIN_CHAIN: [&str; 4] = ["level3", "level2", "level1", "main"];
/// The only fixture function the worker thread can be executing at the stop.
const WORKER_FRAME0: &str = "worker_spin";

/// Build the fixture `-no-pie`, so `nm` addresses are the executed addresses.
///
/// A missing `cc` is a FAILURE here, not a skip: a skip that returns green is
/// the self-exemption this file exists to remove, and it would be recorded
/// nowhere. If a machine really cannot compile C, that machine cannot run a
/// live debugger suite either.
fn build_fixture(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir();
    let src = dir.join(format!("rustre_dv3tm_{tag}_{}.c", std::process::id()));
    let bin = dir.join(format!("rustre_dv3tm_{tag}_{}", std::process::id()));
    std::fs::write(&src, FIXTURE_C).expect("the fixture source must be writable");
    let out = std::process::Command::new("cc")
        .args(["-no-pie", "-O0", "-g"])
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .arg("-lpthread")
        .output()
        .expect("`cc` must be available to build the live fixture");
    let _ = std::fs::remove_file(&src);
    assert!(
        out.status.success(),
        "the fixture must compile: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    bin
}

fn opts_for(bin: &str) -> LaunchOptions {
    LaunchOptions {
        executable: bin.to_string(),
        args: vec![],
        env: Default::default(),
        working_dir: None,
        stop_at_entry: false,
        follow_forks: false,
        redirect: OutputRedirect::default(),
    }
}

struct Target {
    dbg: LinuxDebugger,
    bin: std::path::PathBuf,
    pid: u32,
}

impl Target {
    /// Launch and resume past thread-birth stops to the fixture's own SIGTRAP.
    ///
    /// Bounded, never "resume until": an unbounded loop on a backend that stops
    /// sending events is a hang, and a hang reports nothing.
    async fn start(tag: &str) -> Self {
        let bin = build_fixture(tag);
        let dbg = LinuxDebugger::new();
        let pid = dbg
            .launch(opts_for(bin.to_str().expect("utf-8 fixture path")))
            .await
            .expect("the fixture must launch under ptrace");
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
        Self { dbg, bin, pid: pid.0 }
    }

    /// Explicit teardown: the backend reaps with `waitpid(-1, __WALL)`, which is
    /// process-global, so a session left running steals the NEXT test's stops.
    async fn shutdown(self) {
        let _ = self.dbg.kill().await;
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        let _ = std::process::Command::new("kill")
            .arg("-9")
            .arg(self.pid.to_string())
            .output();
        let _ = std::fs::remove_file(&self.bin);
    }
}

/// `(name, start, end)` for every TEXT symbol, from `nm -S --defined-only`.
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

fn name_of(ranges: &[(String, u64, u64)], pc: u64) -> Option<String> {
    ranges
        .iter()
        .find(|(_, s, e)| pc >= *s && pc < *e)
        .map(|(n, _, _)| n.clone())
}

/// The fixture's own frame names of a walk, in order, libc frames dropped.
fn fixture_names(ranges: &[(String, u64, u64)], pcs: &[u64]) -> Vec<String> {
    let known: BTreeSet<&str> = MAIN_CHAIN
        .iter()
        .copied()
        .chain(std::iter::once(WORKER_FRAME0))
        .collect();
    pcs.iter()
        .filter_map(|pc| name_of(ranges, *pc))
        .filter(|n| known.contains(n.as_str()))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────

/// `backtrace(tid)` must walk THE THREAD IT WAS ASKED ABOUT.
///
/// This is the claim the whole backtrace half of `live_linux_threads_modules.rs`
/// leaves open. There, every walk is of the stopped main thread; the one call
/// on a secondary thread
/// (`every_enumerated_thread_can_be_unwound`) is checked only for
/// `!frames.is_empty()`, which a backend that ignores its `tid` argument and
/// re-walks the main thread satisfies perfectly — and would satisfy while
/// reporting that the worker is executing `level3`, a function the worker never
/// enters.
///
/// The oracle is a TRIPLE that a single assignment of addresses to names must
/// reproduce, not a count: the main thread's fixture frames are exactly
/// `["level3","level2","level1","main"]` in that order, the worker's frame 0 is
/// `worker_spin`, and the two name sets do not intersect. `nm -S` supplies the
/// address→name mapping and the crate never touches it.
#[tokio::test]
async fn backtrace_walks_the_thread_it_was_asked_about() {
    let t = Target::start("perthread").await;
    let ranges = nm_text_ranges(&t.bin);
    for want in MAIN_CHAIN.iter().chain(std::iter::once(&WORKER_FRAME0)) {
        assert!(
            ranges.iter().any(|(n, s, e)| n == want && e > s),
            "guard: `nm -S` must give `{want}` a non-empty range or this test has no oracle"
        );
    }

    let main_tid = t
        .dbg
        .current_thread()
        .await
        .expect("current_thread() must succeed while stopped");
    let all = t.dbg.threads().await.expect("threads() must succeed");
    let workers: Vec<ThreadId> = all.iter().copied().filter(|x| *x != main_tid).collect();
    assert_eq!(
        workers.len(),
        1,
        "the fixture creates exactly one worker; threads() said {all:?} with main {main_tid:?}"
    );

    let main_pcs: Vec<u64> = t
        .dbg
        .backtrace(main_tid)
        .await
        .expect("backtrace() must walk the stopped main thread")
        .iter()
        .map(|f| f.pc.0)
        .collect();
    let worker_pcs: Vec<u64> = t
        .dbg
        .backtrace(workers[0])
        .await
        .expect("backtrace() must walk the worker thread threads() advertised")
        .iter()
        .map(|f| f.pc.0)
        .collect();
    let pid = t.pid;
    t.shutdown().await;

    let main_names = fixture_names(&ranges, &main_pcs);
    let worker_names = fixture_names(&ranges, &worker_pcs);

    assert_eq!(
        main_names,
        MAIN_CHAIN.to_vec(),
        "the main thread of pid {pid} raised SIGTRAP inside level3, so its fixture frames are \
         {MAIN_CHAIN:?}; the walk named {main_names:?} (raw pcs {main_pcs:#x?})"
    );
    assert_eq!(
        name_of(&ranges, worker_pcs[0]).as_deref(),
        Some(WORKER_FRAME0),
        "the worker spins in `{WORKER_FRAME0}`, so that is where its frame 0 must be; got \
         {:?} (raw pcs {worker_pcs:#x?})",
        name_of(&ranges, worker_pcs[0])
    );
    let a: BTreeSet<&String> = main_names.iter().collect();
    let b: BTreeSet<&String> = worker_names.iter().collect();
    assert!(
        a.is_disjoint(&b),
        "the two threads are in disjoint call chains by construction, so no fixture function may \
         appear in both walks; main {main_names:?} vs worker {worker_names:?} — an overlap means \
         one walk was handed the other thread's stack"
    );
}

/// EVERY module's base must be the first mapping of ITS OWN path.
///
/// The existing suite checks this constant for the main executable alone. A
/// library base is the same kind of constant: every address symbolised inside
/// libc is wrong by exactly the error in libc's base, and no assertion in the
/// file would move. The oracle is a MAP path→base built from
/// `/proc/<pid>/maps`, so it fails both ways — a base attached to the wrong
/// path and a base that is simply wrong.
#[tokio::test]
async fn every_module_base_is_the_first_mapping_of_its_own_path() {
    let t = Target::start("modbase").await;
    let mods = t.dbg.modules().await.expect("modules() must succeed");
    let raw = std::fs::read_to_string(format!("/proc/{}/maps", t.pid))
        .expect("/proc/<pid>/maps must be readable for our own tracee");

    // path → lowest base the kernel maps it at.
    let mut kernel: BTreeMap<String, u64> = BTreeMap::new();
    for l in raw.lines() {
        let mut it = l.split_whitespace();
        let Some(range) = it.next() else { continue };
        let Some(path) = it.nth(4) else { continue };
        if !path.starts_with('/') {
            continue;
        }
        let Some((a, _)) = range.split_once('-') else { continue };
        let Ok(base) = u64::from_str_radix(a, 16) else { continue };
        kernel
            .entry(path.to_string())
            .and_modify(|b| *b = (*b).min(base))
            .or_insert(base);
    }
    assert!(
        kernel.len() >= 2,
        "guard: the fixture links libc dynamically, so several files must be mapped; got {kernel:?}"
    );

    let got: BTreeMap<String, u64> = mods.iter().map(|m| (m.path.clone(), m.base.0)).collect();
    let pid = t.pid;
    t.shutdown().await;

    let wrong: Vec<(String, u64, u64)> = got
        .iter()
        .filter_map(|(p, b)| kernel.get(p).filter(|k| *k != b).map(|k| (p.clone(), *b, *k)))
        .collect();
    assert!(
        wrong.is_empty(),
        "modules() bases disagree with /proc/{pid}/maps for {} module(s); each triple is \
         (path, reported, kernel-first-mapping): {wrong:#x?}",
        wrong.len()
    );
    assert_eq!(
        got.keys().collect::<Vec<_>>(),
        kernel.keys().collect::<Vec<_>>(),
        "modules() must report exactly the file-backed paths the kernel lists"
    );
}

/// The secondary thread MUST be walkable — `Unsupported` is not an answer.
///
/// `every_enumerated_thread_can_be_unwound` accepts
/// `Err(DebugError::Unsupported(_))` on a silent arm, so it stays green on a
/// backend that walks no secondary thread at all and leaves no record that the
/// claim was skipped. That exemption is removed here, and the result is pinned
/// to a name rather than to a frame count: the worker's frame 0 is
/// `worker_spin` or the test fails.
#[tokio::test]
async fn a_secondary_thread_is_walkable_not_merely_unsupported() {
    let t = Target::start("nounsup").await;
    let ranges = nm_text_ranges(&t.bin);
    let main_tid = t.dbg.current_thread().await.expect("current_thread() must succeed");
    let all = t.dbg.threads().await.expect("threads() must succeed");
    let workers: Vec<ThreadId> = all.iter().copied().filter(|x| *x != main_tid).collect();
    assert_eq!(workers.len(), 1, "the fixture creates exactly one worker; got {all:?}");

    let res = t.dbg.backtrace(workers[0]).await;
    t.shutdown().await;

    let frames = res.unwrap_or_else(|e| {
        panic!(
            "threads() advertised {:?} but backtrace() refused it with {e:?}; enumerating a \
             thread the debugger cannot walk is not thread support",
            workers[0]
        )
    });
    assert!(!frames.is_empty(), "a live thread always has at least one frame");
    assert_eq!(
        name_of(&ranges, frames[0].pc.0).as_deref(),
        Some(WORKER_FRAME0),
        "the worker spins in `{WORKER_FRAME0}`; frame 0 pc {:#x} names {:?}",
        frames[0].pc.0,
        name_of(&ranges, frames[0].pc.0)
    );
}

/// No fixture of THIS file may outlive it.
///
/// `-x` matches the process name exactly; `-f` would match cargo's own
/// `live_linux_dv3_threads_modules-<hash>` test binary and report the orphan
/// check itself as an orphan.
#[tokio::test]
async fn zzz_no_dv3_fixture_survives() {
    let mut alive: Vec<String> = Vec::new();
    for tag in ["perthread", "modbase", "nounsup"] {
        let name = format!("rustre_dv3tm_{tag}_{}", std::process::id());
        let out = std::process::Command::new("pgrep")
            .arg("-x")
            .arg(&name)
            .output()
            .expect("pgrep must be available");
        if !out.stdout.is_empty() {
            alive.push(format!("{name} -> {}", String::from_utf8_lossy(&out.stdout).trim()));
        }
    }
    assert!(alive.is_empty(), "fixture processes outlived the suite: {alive:?}");
}
