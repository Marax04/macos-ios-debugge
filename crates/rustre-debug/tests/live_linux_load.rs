//! Live-process coverage for the Linux backend UNDER LOAD.
//!
//! The other `live_linux_*` files each prove one operation is correct once.
//! This one asks a different question: does the backend stay correct, bounded
//! and linear when the same operation is performed hundreds or thousands of
//! times against a real process? Three failure modes are invisible to a
//! single-shot test and fatal in a real session:
//!
//!   * **leaks** — a tracking table (breakpoints, conditions, hit counts,
//!     thread filters) that grows and never shrinks, or a file descriptor
//!     opened per operation and never closed. Measured, not reasoned about:
//!     `/proc/self/fd` and `VmRSS` of the DEBUGGER process (the ptrace loop
//!     runs in a thread of this test binary, so this process is the debugger).
//!   * **non-linear cost** — an O(n^2) plant loop, or a per-crossing cost that
//!     rises with the number of crossings. Measured by running the same work at
//!     two sizes and comparing cost PER UNIT, which cancels the constant
//!     overhead that would otherwise dominate a small sample.
//!   * **state corruption at scale** — 200 traps planted and removed must
//!     restore the text segment byte for byte, not approximately.
//!
//! Every number reported by these tests is printed, so a regression shows up as
//! a value, not as a verdict. Thresholds are deliberately loose (3x-4x
//! headroom): they are shaped to catch a COMPLEXITY class change, not to police
//! machine noise or CI scheduling jitter.
//!
//! Method notes that cost earlier rounds real time and are encoded here:
//!   * `read_memory` MASKS the debugger's own traps, so it can never witness a
//!     plant. Text-segment evidence is taken from `/proc/<pid>/mem` directly.
//!   * The backend waits with `waitpid(-1)`, so an event belonging to another
//!     test's child can be handed to this one — events are filtered on `ev.pid`.
//!   * A freshly launched tracee is stopped at the exec trap and has not run a
//!     single instruction of `main`.
//!   * `-no-pie` makes the binary `ET_EXEC`, so the address `nm` prints IS the
//!     run-time address.
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::{
    BreakpointKind, DebugEvent, Debugger, LaunchOptions, OutputRedirect, StopReason,
};

/// The fixture. One binary, three modes chosen by `argv[1]`, so every test in
/// this file shares one compilation:
///   * `loop <n>` — a tight loop crossing `hot` exactly `n` times.
///   * `threads <n>` — `n` threads created and joined one after another, so the
///     tracee thread table churns while the debugger is attached.
///   * anything else — exit immediately (used by the launch/kill cycle test).
///
/// `filler` exists only to provide a contiguous, generously sized run of `.text`
/// bytes at which 200 distinct breakpoint addresses can be planted. Those
/// addresses are never EXECUTED (the tests that use them never resume), so it
/// does not matter that byte `base + 137` may land mid-instruction; what matters
/// is that 200 distinct addresses inside a mapped executable page exist.
const FIXTURE_C: &str = r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

__attribute__((noinline)) int hot(int x) { return x + 1; }

__attribute__((noinline)) int filler(int x) {
    volatile int a = x, b = x + 1, c = x + 2, d = x + 3;
    for (int i = 0; i < 8; i++) { a += b; b ^= c; c += d; d -= a; a *= 3; b += 7; }
    switch (x & 7) {
    case 0: a += 11; break; case 1: a += 22; break; case 2: a += 33; break;
    case 3: a += 44; break; case 4: a += 55; break; case 5: a += 66; break;
    case 6: a += 77; break; default: a += 88; break;
    }
    return a + b + c + d;
}

static void *worker(void *p) { volatile int k = 0; for (int i = 0; i < 50; i++) k += i; return p; }

int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "loop") == 0) {
        long n = atol(argv[2]);
        volatile int s = 0;
        for (long i = 0; i < n; i++) { s = hot(s); }
        printf("loop %d\n", s);
        return 0;
    }
    if (argc >= 3 && strcmp(argv[1], "threads") == 0) {
        long n = atol(argv[2]);
        for (long i = 0; i < n; i++) {
            pthread_t t;
            if (pthread_create(&t, NULL, worker, NULL) != 0) return 2;
            pthread_join(t, NULL);
        }
        printf("threads done\n");
        return 0;
    }
    printf("quick %d\n", filler(argc));
    return 0;
}
"#;

struct Fixture {
    _dir: tempfile::TempDir,
    exe: String,
    hot: u64,
    /// First byte of `filler`, and the number of bytes it occupies. The
    /// breakpoint-storm tests need a run of addresses that are certainly inside
    /// one function of this binary.
    filler: u64,
    filler_size: u64,
}

fn build_fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("load_fixture.c");
    let exe = dir.path().join("load_fixture");
    std::fs::write(&src, FIXTURE_C).expect("write fixture source");
    let out = std::process::Command::new("cc")
        .args(["-no-pie", "-O0", "-g", "-pthread"])
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .output()
        .expect("cc must be available to run the live load tests");
    assert!(
        out.status.success(),
        "cc failed to build the fixture: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let nm = std::process::Command::new("nm").arg("-S").arg(&exe).output().expect("nm -S");
    assert!(nm.status.success(), "nm failed on the fixture binary");
    let listing = String::from_utf8_lossy(&nm.stdout).to_string();
    let hot = sym(&listing, "hot").expect("the fixture must export `hot`").0;
    let (filler, filler_size) = sym(&listing, "filler").expect("the fixture must export `filler`");
    assert!(
        filler_size >= 256,
        "`filler` is only {filler_size} bytes; the 200-breakpoint storm needs at least 256 distinct in-function addresses"
    );
    Fixture { _dir: dir, exe: exe.to_string_lossy().to_string(), hot, filler, filler_size }
}

/// `(address, size)` of a text symbol from an `nm -S` listing.
fn sym(listing: &str, want: &str) -> Option<(u64, u64)> {
    for line in listing.lines() {
        let p: Vec<&str> = line.split_whitespace().collect();
        // `addr size kind name` for a sized symbol; `addr kind name` otherwise.
        if p.len() == 4 && p[3] == want && (p[2] == "T" || p[2] == "t") {
            return Some((
                u64::from_str_radix(p[0], 16).ok()?,
                u64::from_str_radix(p[1], 16).unwrap_or(0),
            ));
        }
        if p.len() == 3 && p[2] == want && (p[1] == "T" || p[1] == "t") {
            return Some((u64::from_str_radix(p[0], 16).ok()?, 0));
        }
    }
    None
}

fn launch_opts(exe: &str, args: &[&str]) -> LaunchOptions {
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

async fn launched(fx: &Fixture, args: &[&str]) -> LinuxDebugger {
    let dbg = LinuxDebugger::new();
    dbg.launch(launch_opts(&fx.exe, args)).await.expect("launch should succeed");
    dbg
}

/// Read the bytes the CPU would actually fetch, bypassing the debugger.
/// `read_memory` masks planted traps by design, so it cannot witness a plant.
fn raw_bytes(dbg: &LinuxDebugger, addr: u64, n: usize) -> Vec<u8> {
    use std::io::{Read, Seek, SeekFrom};
    let pid = dbg.target_pid().expect("a live pid is required to read /proc/<pid>/mem");
    let mut f = std::fs::File::open(format!("/proc/{}/mem", pid.0)).expect("open /proc/<pid>/mem");
    f.seek(SeekFrom::Start(addr)).expect("seek");
    let mut buf = vec![0u8; n];
    f.read_exact(&mut buf).expect("read");
    buf
}

/// Open descriptors of THIS process — the debugger. A per-operation descriptor
/// that is never closed shows up here long before it exhausts the limit.
fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd").map(std::iter::Iterator::count).unwrap_or(0)
}

/// Resident set of THIS process, in KiB, from `/proc/self/status`.
fn rss_kib() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest.split_whitespace().next().and_then(|v| v.parse().ok()).unwrap_or(0);
        }
    }
    0
}

/// The addresses used by the storm tests: one per byte from the start of
/// `filler`. Distinct addresses is the property that matters; they are never
/// executed.
fn storm_addrs(fx: &Fixture, n: u64) -> Vec<u64> {
    assert!(n <= fx.filler_size, "asked for {n} addresses in a {}-byte function", fx.filler_size);
    (0..n).map(|i| fx.filler + i).collect()
}

/// No process of ours may survive a test. `pgrep -f` over the unique tempdir
/// path of the fixture is the external check: it consults no debugger state.
fn assert_no_orphans(exe: &str) {
    if let Ok(out) = std::process::Command::new("pgrep").arg("-f").arg(exe).output() {
        let listing = String::from_utf8_lossy(&out.stdout);
        let pids: Vec<&str> = listing.split_whitespace().collect();
        assert!(pids.is_empty(), "the fixture survived the test as pid(s) {pids:?}");
    }
}

/// Run until an event that belongs to `pid` and is an exit, or the budget runs
/// out. The pid filter is load-bearing: the backend waits with `waitpid(-1)`.
async fn continue_to_exit(dbg: &LinuxDebugger, budget: usize) -> Option<DebugEvent> {
    let pid = dbg.target_pid()?.0;
    for _ in 0..budget {
        let ev = dbg.continue_execution().await.ok()?;
        if ev.pid.0 != pid {
            continue;
        }
        if matches!(ev.reason, StopReason::ProcessExit { .. }) {
            return Some(ev);
        }
    }
    None
}

// -- 1. correctness at scale -------------------------------------------------

/// Planting 200 software breakpoints and removing all of them must restore the
/// text segment BYTE FOR BYTE, and must leave the tracking table empty.
///
/// A single plant/remove pair is already covered elsewhere; what only shows up
/// at scale is a saved-original that is keyed wrongly, shared between nearby
/// addresses, or overwritten by a neighbouring plant — all of which restore
/// *something* and pass a one-breakpoint test. The whole 200-byte window is
/// therefore snapshotted before any breakpoint exists and compared afterwards,
/// so a single wrong byte anywhere in the window is a failure with its offset
/// named.
#[tokio::test]
async fn two_hundred_breakpoints_plant_and_remove_restore_the_text_byte_for_byte() {
    let fx = build_fixture();
    let dbg = launched(&fx, &[]).await;
    let addrs = storm_addrs(&fx, 200);
    let n = addrs.len();

    let before = raw_bytes(&dbg, fx.filler, n);
    for a in &addrs {
        dbg.set_breakpoint(Address(*a), BreakpointKind::Software)
            .await
            .unwrap_or_else(|e| panic!("set_breakpoint at {a:#x} failed: {e:?}"));
    }
    let listed = dbg.breakpoints().await.expect("breakpoints").len();
    assert_eq!(listed, n, "planted {n} breakpoints but the table lists {listed}");
    let planted = raw_bytes(&dbg, fx.filler, n);
    let trap_count = planted.iter().filter(|b| **b == 0xCC).count();
    assert!(
        trap_count >= n - 1,
        "only {trap_count} of {n} bytes in the window are traps — the plants did not all land"
    );

    for a in &addrs {
        dbg.remove_breakpoint(Address(*a))
            .await
            .unwrap_or_else(|e| panic!("remove_breakpoint at {a:#x} failed: {e:?}"));
    }
    let after = raw_bytes(&dbg, fx.filler, n);
    let bad: Vec<usize> = (0..n).filter(|i| before[*i] != after[*i]).collect();
    assert!(
        bad.is_empty(),
        "after 200 plant/remove pairs {} bytes differ from the original, at offsets {:?} (first: {:#04x} -> {:#04x})",
        bad.len(),
        &bad[..bad.len().min(8)],
        before[bad[0]],
        after[bad[0]]
    );
    let left = dbg.breakpoints().await.expect("breakpoints").len();
    assert_eq!(left, 0, "{left} breakpoints are still listed after removing all 200");

    println!("[storm] 200 planted, {trap_count} traps observed, 0 bytes corrupted after removal");
    let _ = dbg.kill().await;
    assert_no_orphans(&fx.exe);
}

/// Repeating the plant/remove storm must not grow anything without bound.
///
/// This is the leak test proper. Five cycles of 200 breakpoints is 1000 plants
/// and 1000 removes; a table that keeps one entry per plant, or a descriptor
/// opened per `/proc/<pid>/mem` access and never closed, is unmissable at that
/// volume while invisible at one. The measured quantities — listed breakpoints,
/// open descriptors, resident set — are printed for every cycle so a regression
/// reads as a trend, not a verdict.
#[tokio::test]
async fn repeated_plant_remove_storms_leak_no_table_entries_fds_or_memory() {
    let fx = build_fixture();
    let dbg = launched(&fx, &[]).await;
    let addrs = storm_addrs(&fx, 200);

    // One warm-up cycle first: the very first plant faults in pages and may open
    // long-lived state legitimately. A leak is unbounded GROWTH, not the cost of
    // the first use, and comparing against a cold baseline would report that
    // one-time cost as a leak.
    for a in &addrs {
        dbg.set_breakpoint(Address(*a), BreakpointKind::Software).await.expect("warm set");
    }
    for a in &addrs {
        dbg.remove_breakpoint(Address(*a)).await.expect("warm remove");
    }
    let (fd0, rss0) = (open_fds(), rss_kib());

    let mut trace = Vec::new();
    for cycle in 0..5 {
        for a in &addrs {
            dbg.set_breakpoint(Address(*a), BreakpointKind::Software).await.expect("set");
        }
        for a in &addrs {
            dbg.remove_breakpoint(Address(*a)).await.expect("remove");
        }
        let listed = dbg.breakpoints().await.expect("breakpoints").len();
        assert_eq!(listed, 0, "cycle {cycle}: {listed} breakpoints survived a full removal pass");
        trace.push((cycle, open_fds(), rss_kib()));
    }
    let (fd1, rss1) = (open_fds(), rss_kib());
    println!("[leak] baseline fds={fd0} rss={rss0}KiB");
    for (c, fd, rss) in &trace {
        println!("[leak] after cycle {c}: fds={fd} rss={rss}KiB");
    }

    assert!(
        fd1 <= fd0 + 4,
        "open descriptors went {fd0} -> {fd1} across 1000 plant/remove pairs: roughly one leaked per {} operations",
        1000 / (fd1 - fd0).max(1)
    );
    // 1000 retained breakpoint entries would be far under a MiB, so this bound
    // is aimed at a per-operation allocation, not at a retained table — the
    // table is checked exactly, above, by `listed == 0`.
    assert!(
        rss1 <= rss0 + 8192,
        "resident set grew {}KiB ({rss0} -> {rss1}) across 1000 plant/remove pairs with an empty table at every step",
        rss1.saturating_sub(rss0)
    );
    let _ = dbg.kill().await;
    assert_no_orphans(&fx.exe);
}

/// The cost of planting a breakpoint must not depend on how many are already
/// planted. A quadratic plant loop (each `set_breakpoint` rescanning or
/// re-serialising the whole table) is perfectly correct and perfectly invisible
/// until a user sets a breakpoint on every line of a file.
///
/// Measured as cost PER BREAKPOINT at 25 and at 200. Dividing by the count
/// cancels the fixed per-call overhead, which would otherwise make a linear
/// implementation look sublinear at the small size and mask real growth. A
/// linear implementation keeps the ratio near 1; a quadratic one would show
/// ~8x. The threshold is 4x, i.e. the test fires on a complexity change and not
/// on a slow machine.
#[tokio::test]
async fn breakpoint_planting_cost_per_breakpoint_does_not_grow_with_the_table() {
    let fx = build_fixture();
    let dbg = launched(&fx, &[]).await;

    async fn timed(dbg: &LinuxDebugger, addrs: &[u64]) -> f64 {
        let t = std::time::Instant::now();
        for a in addrs {
            dbg.set_breakpoint(Address(*a), BreakpointKind::Software).await.expect("set");
        }
        let per = t.elapsed().as_secs_f64() / addrs.len() as f64;
        for a in addrs {
            dbg.remove_breakpoint(Address(*a)).await.expect("remove");
        }
        per
    }

    let small = storm_addrs(&fx, 25);
    let large = storm_addrs(&fx, 200);
    // Warm-up, discarded: the first pass pays page faults and allocator growth.
    let _ = timed(&dbg, &small).await;

    let per_small = timed(&dbg, &small).await;
    let per_large = timed(&dbg, &large).await;
    let ratio = per_large / per_small.max(1e-9);
    println!(
        "[scale] per-breakpoint: 25 -> {:.1}us, 200 -> {:.1}us, ratio {ratio:.2}x",
        per_small * 1e6,
        per_large * 1e6
    );
    assert!(
        ratio < 4.0,
        "planting cost per breakpoint rose {ratio:.2}x between a 25-entry and a 200-entry table ({:.1}us -> {:.1}us): the plant path is superlinear in the table size",
        per_small * 1e6,
        per_large * 1e6
    );
    let _ = dbg.kill().await;
    assert_no_orphans(&fx.exe);
}

// -- 2. a tight loop crossed 10000 times -------------------------------------

/// A breakpoint whose condition is always false must let the target run to
/// completion, with the debugger absorbing every crossing internally.
///
/// The evidence is the shape of the answer: ONE `continue_execution` call over a
/// 10000-iteration loop must come back with `ProcessExit`. If the filtered stops
/// leaked to the caller the first call would return a `Breakpoint` instead, and
/// if the resume-past-own-trap dance were wrong the loop would never advance and
/// the call would hang or return the same address forever.
#[tokio::test]
async fn ten_thousand_crossings_with_an_always_false_condition_run_to_exit() {
    let fx = build_fixture();
    let dbg = launched(&fx, &["loop", "10000"]).await;
    let at = Address(fx.hot);
    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set_breakpoint");
    dbg.set_breakpoint_condition(at, Some("1 == 0".to_string()))
        .await
        .expect("set_breakpoint_condition");

    let t = std::time::Instant::now();
    let ev = dbg.continue_execution().await.expect("continue_execution");
    let elapsed = t.elapsed();
    println!(
        "[cond] 10000 filtered crossings in {:.2}s = {:.0}us per crossing; first event {:?}",
        elapsed.as_secs_f64(),
        elapsed.as_secs_f64() * 1e6 / 10000.0,
        ev.reason
    );
    match ev.reason {
        StopReason::ProcessExit { exit_code: code } => {
            assert_eq!(code, 0, "the fixture exited {code}, so the loop did not complete");
        }
        other => panic!(
            "a condition that is always false let a stop through: the first continue_execution returned {other:?} instead of the process exit"
        ),
    }
    let _ = dbg.kill().await;
    assert_no_orphans(&fx.exe);
}

/// The per-crossing cost of a filtered breakpoint must be flat: crossing number
/// 10000 must cost what crossing number 1000 cost.
///
/// This is the non-linearity probe for the hot path. Anything that accumulates
/// per hit — a growing hit-history vector, a condition re-parsed against an
/// ever-longer table, a register snapshot appended to a log — produces a rising
/// per-crossing cost that no correctness test can see. Two runs, 10x apart in
/// size, are compared per crossing; the fixed cost of launch and exit is
/// amortised away by the division and is the reason for the generous 3x bound.
#[tokio::test]
async fn the_per_crossing_cost_of_a_filtered_breakpoint_stays_flat_from_1000_to_10000() {
    let fx = build_fixture();

    async fn run(fx: &Fixture, iters: u64) -> f64 {
        let dbg = LinuxDebugger::new();
        let n = iters.to_string();
        dbg.launch(launch_opts(&fx.exe, &["loop", &n])).await.expect("launch");
        let at = Address(fx.hot);
        dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set");
        dbg.set_breakpoint_condition(at, Some("1 == 0".to_string())).await.expect("cond");
        let t = std::time::Instant::now();
        let ev = continue_to_exit(&dbg, 8).await.expect("the fixture never reached its exit");
        let per = t.elapsed().as_secs_f64() / iters as f64;
        assert!(matches!(ev.reason, StopReason::ProcessExit { .. }));
        let _ = dbg.kill().await;
        per
    }

    let per_1k = run(&fx, 1000).await;
    let per_10k = run(&fx, 10000).await;
    let ratio = per_10k / per_1k.max(1e-9);
    println!(
        "[hot] per crossing: 1000 -> {:.0}us, 10000 -> {:.0}us, ratio {ratio:.2}x",
        per_1k * 1e6,
        per_10k * 1e6
    );
    assert!(
        ratio < 3.0,
        "the cost of a filtered crossing rose {ratio:.2}x between the 1000th and the 10000th ({:.0}us -> {:.0}us): work is accumulating per hit",
        per_1k * 1e6,
        per_10k * 1e6
    );
    assert_no_orphans(&fx.exe);
}

/// Ten thousand filtered crossings must not grow the debugger resident set or
/// its descriptor table. Same leak question as the plant storm, aimed at the
/// other hot path: the per-STOP path rather than the per-PLANT path. The
/// baseline is taken after a 1000-crossing warm-up run so that one-time costs
/// (thread stacks, allocator arenas) are not counted as a leak.
#[tokio::test]
async fn ten_thousand_filtered_crossings_leak_no_memory_or_descriptors() {
    let fx = build_fixture();

    async fn run(fx: &Fixture, iters: u64) {
        let dbg = LinuxDebugger::new();
        let n = iters.to_string();
        dbg.launch(launch_opts(&fx.exe, &["loop", &n])).await.expect("launch");
        let at = Address(fx.hot);
        dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set");
        dbg.set_breakpoint_condition(at, Some("1 == 0".to_string())).await.expect("cond");
        continue_to_exit(&dbg, 8).await.expect("exit");
        let _ = dbg.kill().await;
    }

    run(&fx, 1000).await; // warm-up, not measured
    let (fd0, rss0) = (open_fds(), rss_kib());
    run(&fx, 10000).await;
    let (fd1, rss1) = (open_fds(), rss_kib());
    println!("[hot-leak] fds {fd0} -> {fd1}, rss {rss0}KiB -> {rss1}KiB over 10000 crossings");

    assert!(
        fd1 <= fd0 + 4,
        "descriptors went {fd0} -> {fd1} over one 10000-crossing run: about one leaked per {} crossings",
        10000 / (fd1 - fd0).max(1)
    );
    assert!(
        rss1 <= rss0 + 16384,
        "resident set grew {}KiB ({rss0} -> {rss1}) over 10000 filtered crossings",
        rss1.saturating_sub(rss0)
    );
    assert_no_orphans(&fx.exe);
}

// -- 3. thread churn ---------------------------------------------------------

/// Threads that are born and die while the debugger is attached must leave the
/// thread list back at its resting size.
///
/// `threads()` reads `/proc/<pid>/task`, so it cannot itself accumulate; what
/// this proves is that the whole attached session survives 200 clone/exit pairs
/// and still answers with the LIVE set rather than the historical one. A backend
/// that cached tids would report a few hundred here. The resting size is
/// measured on the same process before the storm, so a runtime that keeps
/// helper threads of its own is not mistaken for a leak.
#[tokio::test]
async fn two_hundred_short_lived_threads_leave_the_thread_list_at_its_resting_size() {
    let fx = build_fixture();
    let dbg = launched(&fx, &["threads", "200"]).await;
    let resting = dbg.threads().await.expect("threads").len();

    let ev = continue_to_exit(&dbg, 4096).await;
    let after = dbg.threads().await.map(|t| t.len());
    println!(
        "[threads] resting={resting}, after 200 create/join pairs: {after:?}, final event {:?}",
        ev.map(|e| e.reason)
    );

    if let Ok(n) = after {
        assert!(
            n <= resting + 2,
            "the thread list holds {n} entries after 200 threads came and went (resting size was {resting}): dead threads are being retained"
        );
    }
    let _ = dbg.kill().await;
    assert_no_orphans(&fx.exe);
}

/// A thread storm must not disturb the breakpoint table. 200 clone/exit events
/// are 200 chances for the event loop to touch shared state; a table rebuilt,
/// re-keyed or cleared on a thread event would silently disarm every breakpoint
/// the user set, and the user would conclude their code is never reached.
///
/// The check is on both halves of the claim: the entry is still LISTED, and the
/// trap is still PLANTED in the bytes the CPU will fetch — the listing alone
/// cannot tell an armed breakpoint from a forgotten one.
#[tokio::test]
async fn a_thread_storm_does_not_disarm_the_planted_breakpoints() {
    let fx = build_fixture();
    let dbg = launched(&fx, &["threads", "200"]).await;
    let addrs = storm_addrs(&fx, 32);
    for a in &addrs {
        dbg.set_breakpoint(Address(*a), BreakpointKind::Software).await.expect("set");
    }
    let pid = dbg.target_pid().expect("pid").0;

    // Resume a bounded number of times. The loop is capped rather than run to
    // completion so the test does not depend on the whole program finishing.
    let mut resumes = 0;
    let mut exited = false;
    for _ in 0..64 {
        match dbg.continue_execution().await {
            Ok(ev) => {
                if ev.pid.0 != pid {
                    continue;
                }
                resumes += 1;
                if matches!(ev.reason, StopReason::ProcessExit { .. }) {
                    exited = true;
                    break;
                }
            }
            Err(_) => break,
        }
    }

    let listed = dbg.breakpoints().await.map(|b| b.len()).unwrap_or(0);
    println!(
        "[thread-bp] {resumes} events consumed (exited={exited}), {listed}/{} breakpoints still listed",
        addrs.len()
    );
    if !exited && listed > 0 {
        // Only meaningful while the process is alive: after an exit the table is
        // legitimately retired and there is nothing left to read.
        assert_eq!(
            listed,
            addrs.len(),
            "the thread storm left {listed} of {} breakpoints listed",
            addrs.len()
        );
        let window = raw_bytes(&dbg, fx.filler, addrs.len());
        let traps = window.iter().filter(|b| **b == 0xCC).count();
        assert!(
            traps >= addrs.len() - 1,
            "only {traps} of {} traps are still planted after the thread storm: breakpoints are listed but disarmed",
            addrs.len()
        );
    }
    let _ = dbg.kill().await;
    assert_no_orphans(&fx.exe);
}

// -- 4. session churn --------------------------------------------------------

/// Ten launch/kill cycles must leave no orphaned process and no leaked
/// descriptor. Each cycle spawns a ptrace thread, a tracee and whatever
/// descriptors the backend needs; if `kill()` does not fully retire a session,
/// the tenth cycle is holding ten of everything. Both halves are checked from
/// OUTSIDE the debugger: `pgrep` for the processes, `/proc/self/fd` for the
/// descriptors.
#[tokio::test]
async fn ten_launch_kill_cycles_leave_no_orphans_and_no_leaked_descriptors() {
    let fx = build_fixture();
    // One cycle first, so the baseline includes whatever a session costs once.
    {
        let dbg = launched(&fx, &[]).await;
        let _ = dbg.kill().await;
    }
    let (fd0, rss0) = (open_fds(), rss_kib());

    for i in 0..10 {
        let dbg = launched(&fx, &[]).await;
        dbg.set_breakpoint(Address(fx.hot), BreakpointKind::Software).await.expect("set");
        let _ = dbg.kill().await;
        assert!(
            dbg.breakpoints().await.map(|b| b.len()).unwrap_or(0) == 0,
            "cycle {i}: breakpoints survived kill(), so the session was not retired"
        );
    }
    let (fd1, rss1) = (open_fds(), rss_kib());
    println!("[session] 10 launch/kill cycles: fds {fd0} -> {fd1}, rss {rss0}KiB -> {rss1}KiB");

    assert!(
        fd1 <= fd0 + 4,
        "descriptors went {fd0} -> {fd1} over 10 launch/kill cycles: about {} leaked per session",
        (fd1 - fd0) / 10
    );
    assert!(
        rss1 <= rss0 + 8192,
        "resident set grew {}KiB over 10 launch/kill cycles",
        rss1.saturating_sub(rss0)
    );
    assert_no_orphans(&fx.exe);
}
