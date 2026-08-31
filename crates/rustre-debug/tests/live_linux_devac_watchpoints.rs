//! De-vacuation guards for the hardware-watchpoint and thread/module surfaces.
//!
//! The workflow-5 falsification campaign measured that `live_linux_watchpoints.rs`
//! had 1 biting test out of 11 and `live_linux_threads_modules.rs` 1 out of 9:
//! shifting the single external oracle each file used left almost every
//! assertion green. The cause is the same in both, and it is the one this repo
//! keeps re-discovering — **the expectation is built out of the very data being
//! checked**. A watchpoint test that reads `sp` out of the backend, arms a
//! watchpoint there and then asserts that DR0 holds that address is a round
//! trip through the kernel that no wrong address can fail. A thread test that
//! asserts `threads()` is non-empty is satisfied by any list at all.
//!
//! Every guard below is anchored to an oracle the debugger DOES NOT PRODUCE:
//!
//! * the tracee's **own written declaration** — each fixture opens the file
//!   named by `argv[1]` and writes, BEFORE doing any of the work, the addresses
//!   of its globals (`%p`), how many times it is about to write each one, and
//!   the `gettid()` of every thread it creates. That is this file's cheapest
//!   and strongest oracle: the debugger has no way to influence it.
//! * `nm`, used as a SECOND, disagreeing-capable oracle for the same addresses.
//!   Two oracles that must agree catch the failure mode a single one cannot: a
//!   PIE relocation that moves every global by a constant.
//! * `/proc/<pid>/task` and `/proc/<pid>/maps`, read by the test directly.
//!
//! ## Falsifying these guards
//!
//! Rule 5 of the de-vacuation protocol: falsify the ORACLE too. The mutations
//! are wired in permanently rather than applied by editing, so anyone can
//! re-measure them:
//!
//! ```text
//! RUSTRE_DEVAC_MUT=addr_shift   arm 8 bytes past the address the program declared
//! RUSTRE_DEVAC_MUT=swap         arm w_beta's address while claiming w_alpha's counts
//! RUSTRE_DEVAC_MUT=nm_shift     shift the nm oracle by 0x40
//! RUSTRE_DEVAC_MUT=tid_drop     drop one tid from the program's declaration
//! RUSTRE_DEVAC_MUT=tid_add      add a tid the program never reported
//! RUSTRE_DEVAC_MUT=map_drop     drop one file-backed mapping from /proc/<pid>/maps
//! RUSTRE_DEVAC_MUT=cross        cross w_alpha and w_beta in the two comparison guards
//! ```
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::{BreakpointKind, Debugger, LaunchOptions, OutputRedirect, StopReason, ThreadId};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

// -- falsification switch ---------------------------------------------------

fn mutation() -> String {
    std::env::var("RUSTRE_DEVAC_MUT").unwrap_or_default()
}

fn mutating(which: &str) -> bool {
    mutation() == which
}

// -- shared fixture machinery -----------------------------------------------

fn compile(dir: &std::path::Path, name: &str, source: &str) -> Option<std::path::PathBuf> {
    let src = dir.join(format!("{name}.c"));
    std::fs::write(&src, source).ok()?;
    let exe = dir.join(name);
    let out = std::process::Command::new("cc")
        .args(["-no-pie", "-O0", "-g", "-pthread"])
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .output()
        .ok()?;
    out.status.success().then_some(exe)
}

fn launch_opts(exe: &std::path::Path, report: &std::path::Path) -> LaunchOptions {
    LaunchOptions {
        executable: exe.to_string_lossy().into_owned(),
        args: vec![report.to_string_lossy().into_owned()],
        env: std::collections::HashMap::new(),
        working_dir: None,
        stop_at_entry: false,
        follow_forks: false,
        redirect: OutputRedirect::default(),
    }
}

/// Everything the tracee said about itself, keyed by the tag it printed.
///
/// The parse is deliberately strict: a report line that does not have exactly
/// three fields is dropped, so a fixture that half-wrote its declaration
/// produces an EMPTY oracle and every guard below fails loudly, rather than a
/// short one that silently agrees with a short answer from the debugger.
#[derive(Default, Debug)]
struct Declared {
    addrs: BTreeMap<String, u64>,
    writes: BTreeMap<String, usize>,
    tids: BTreeSet<u32>,
}

fn parse_report(text: &str) -> Declared {
    let mut d = Declared::default();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() != 3 {
            continue;
        }
        match f[0] {
            "ADDR" => {
                let hex = f[2].trim_start_matches("0x");
                if let Ok(v) = u64::from_str_radix(hex, 16) {
                    d.addrs.insert(f[1].to_string(), v);
                }
            }
            "WRITES" => {
                if let Ok(v) = f[2].parse() {
                    d.writes.insert(f[1].to_string(), v);
                }
            }
            "TID" => {
                if let Ok(v) = f[2].parse() {
                    d.tids.insert(v);
                }
            }
            _ => {}
        }
    }
    d
}

/// The address `nm` prints for a symbol in a non-PIE executable.
fn nm_addr(exe: &std::path::Path, symbol: &str) -> Option<u64> {
    let out = std::process::Command::new("nm").arg(exe).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let found = text.lines().find_map(|line| {
        let mut it = line.split_whitespace();
        let addr = it.next()?;
        let _kind = it.next()?;
        if it.next()? != symbol {
            return None;
        }
        u64::from_str_radix(addr, 16).ok()
    })?;
    Some(if mutating("nm_shift") { found + 0x40 } else { found })
}

// -- the watchpoint fixture -------------------------------------------------

/// Declares, then does. The counts (7, 4, 2, 0) are all different, so the
/// vector of counts is a FINGERPRINT of the address->name assignment: swapping
/// two watchpoints swaps two numbers. A single count would not separate them —
/// measured twice in the previous de-vacuation round, on two different objects.
const WP_FIXTURE_C: &str = r#"
#include <stdio.h>
volatile long w_alpha = 0;
volatile long w_beta = 0;
volatile long w_gamma = 0;
volatile long w_quiet = 0;
#define N_ALPHA 7
#define N_BETA  4
#define N_GAMMA 2
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    FILE *f = fopen(argv[1], "w");
    if (!f) return 3;
    fprintf(f, "ADDR w_alpha %p\n", (void *)&w_alpha);
    fprintf(f, "ADDR w_beta %p\n",  (void *)&w_beta);
    fprintf(f, "ADDR w_gamma %p\n", (void *)&w_gamma);
    fprintf(f, "ADDR w_quiet %p\n", (void *)&w_quiet);
    fprintf(f, "WRITES w_alpha %d\n", N_ALPHA);
    fprintf(f, "WRITES w_beta %d\n",  N_BETA);
    fprintf(f, "WRITES w_gamma %d\n", N_GAMMA);
    fprintf(f, "WRITES w_quiet 0\n");
    fclose(f);
    for (long i = 0; i < N_ALPHA; i++) w_alpha = i + 1;
    for (long i = 0; i < N_BETA;  i++) w_beta  = i + 1;
    for (long i = 0; i < N_GAMMA; i++) w_gamma = i + 1;
    return 0;
}
"#;

struct WpFixture {
    _dir: tempfile::TempDir,
    exe: std::path::PathBuf,
    report: std::path::PathBuf,
}

impl WpFixture {
    fn build() -> Option<Self> {
        let dir = tempfile::tempdir().ok()?;
        let exe = compile(dir.path(), "devacwp", WP_FIXTURE_C)?;
        let report = dir.path().join("wp_report.txt");
        Some(Self {
            _dir: dir,
            exe,
            report,
        })
    }
}

macro_rules! wp_fixture {
    () => {
        match WpFixture::build() {
            Some(f) => f,
            None => {
                eprintln!("skipping: `cc -no-pie -pthread` is not usable here");
                return;
            }
        }
    };
}

/// Run the fixture to completion with `watched` armed, and return BOTH the
/// declaration the program wrote and a histogram of the stop addresses the
/// debugger reported.
///
/// The stop stream is NOT filtered on any address. Filtering is what made the
/// campaign's 143 vacuous tests vacuous: `assert_eq!(address, expected)` after
/// `if address != expected { continue }` is an identity written in two lines.
async fn run_watching(fx: &WpFixture, watched: &[(u64, u8)]) -> (Declared, BTreeMap<u64, usize>) {
    let _ = std::fs::remove_file(&fx.report);
    let dbg = LinuxDebugger::new();
    dbg.launch(launch_opts(&fx.exe, &fx.report))
        .await
        .expect("the watchpoint fixture must launch under ptrace");
    for (addr, size) in watched {
        if let Err(e) = dbg
            .set_watchpoint_sized(Address(*addr), BreakpointKind::DataWrite, *size)
            .await
        {
            let _ = dbg.kill().await;
            panic!("arming a {size}-byte write watchpoint at {addr:#x} must succeed: {e}");
        }
    }
    let mut hist = BTreeMap::new();
    for _ in 0..128 {
        match tokio::time::timeout(Duration::from_secs(30), dbg.continue_execution()).await {
            Ok(Ok(ev)) => match ev.reason {
                StopReason::Breakpoint { address, .. } => {
                    *hist.entry(address.as_u64()).or_insert(0usize) += 1;
                }
                StopReason::ProcessExit { .. } => break,
                _ => {}
            },
            _ => break,
        }
    }
    let _ = dbg.kill().await;
    let text = std::fs::read_to_string(&fx.report).unwrap_or_default();
    (parse_report(&text), hist)
}

/// Read DR0-DR3/DR7 back out of the tracee and answer which slot, if any, holds
/// `addr` with its local-enable bit set.
fn armed_slot(regs: &rustre_debug::RegisterSet, addr: u64) -> Option<u8> {
    let dr7 = regs.get("dr7")?;
    (0u8..4).find(|s| {
        let name = ["dr0", "dr1", "dr2", "dr3"][*s as usize];
        dr7 & (1u64 << (2 * u32::from(*s))) != 0 && regs.get(name) == Some(addr)
    })
}

// -- watchpoint guards ------------------------------------------------------

/// The two independent oracles must AGREE on where the globals live.
///
/// This is the guard on the oracle itself, and it earns its place: `nm` reads a
/// file on disk while `%p` is printed by the running process, so the only way
/// they can agree is if the address really is the one the program uses. If a
/// build ever becomes PIE, `nm` keeps answering link-time addresses, every
/// watchpoint below would be armed on unmapped memory, and without this guard
/// they would fail with a confusing message about counts instead of naming the
/// cause. `nm_shift` proves it can go red.
#[tokio::test]
async fn the_program_and_nm_agree_on_every_global_address() {
    let fx = wp_fixture!();
    let (decl, _) = run_watching(&fx, &[]).await;
    assert_eq!(
        decl.addrs.len(),
        4,
        "the fixture must declare all four globals, got {:?}",
        decl.addrs
    );
    for (name, declared) in &decl.addrs {
        let from_nm =
            nm_addr(&fx.exe, name).unwrap_or_else(|| panic!("`nm` must know the global `{name}`"));
        assert_eq!(
            *declared, from_nm,
            "the running process printed {declared:#x} for `{name}` while `nm` says \
             {from_nm:#x}; the two oracles disagree, so neither can be trusted to say what \
             a watchpoint is watching"
        );
    }
}

/// A watchpoint must fire exactly as often as the PROGRAM SAYS it writes that
/// global — the number coming from the tracee's own declaration, never from the
/// debugger.
///
/// `arming_a_watchpoint_programs_the_real_debug_registers` in the sibling file
/// checks that DR0 holds the address the test just asked for; that assertion
/// cannot separate a correct watchpoint from one armed on any other mapped,
/// aligned address. The write count can: (7, 4, 2, 0) is reproduced by exactly
/// one assignment of addresses to names.
#[tokio::test]
async fn each_watchpoint_fires_as_often_as_the_program_declares() {
    let fx = wp_fixture!();
    let mut got: Vec<(String, usize)> = Vec::new();
    let mut want: Vec<(String, usize)> = Vec::new();
    for name in ["w_alpha", "w_beta", "w_gamma", "w_quiet"] {
        let (decl, _) = run_watching(&fx, &[]).await;
        let mut addr = *decl
            .addrs
            .get(name)
            .unwrap_or_else(|| panic!("the fixture must declare the address of `{name}`"));
        if mutating("addr_shift") {
            addr += 8;
        }
        if mutating("swap") && name == "w_alpha" {
            addr = decl.addrs["w_beta"];
        }
        let (decl2, hist) = run_watching(&fx, &[(addr, 8)]).await;
        let fired: usize = hist.values().sum();
        got.push((name.to_string(), fired));
        want.push((
            name.to_string(),
            *decl2
                .writes
                .get(name)
                .unwrap_or_else(|| panic!("the fixture must declare the write count of `{name}`")),
        ));
    }
    assert_eq!(
        got, want,
        "an 8-byte write watchpoint fired {got:?} times, but the tracee itself declared \
         {want:?}; a count that does not match what the program says it did means the \
         hardware is watching something other than the named global"
    );
}

/// The counting oracle must be a FUNCTION OF THE ADDRESS, or nothing built on
/// it means anything.
///
/// Three separations, because one is not enough: a written global against a
/// never-written one, a written global against 0x40 past it, and two written
/// globals against each other. The last is the one that matters — `w_alpha` and
/// `w_beta` are both written, so a debugger that fires on "some global" rather
/// than "this global" passes the first two and fails this one.
#[tokio::test]
async fn the_declared_count_separates_the_globals_from_each_other() {
    let fx = wp_fixture!();
    let (decl, _) = run_watching(&fx, &[]).await;
    let (mut a, mut b) = (decl.addrs["w_alpha"], decl.addrs["w_beta"]);
    if mutating("cross") {
        std::mem::swap(&mut a, &mut b);
    }
    let q = decl.addrs["w_quiet"];

    let n = |h: BTreeMap<u64, usize>| -> usize { h.values().sum() };
    let alpha = n(run_watching(&fx, &[(a, 8)]).await.1);
    let beta = n(run_watching(&fx, &[(b, 8)]).await.1);
    let quiet = n(run_watching(&fx, &[(q, 8)]).await.1);
    let past = n(run_watching(&fx, &[(a + 0x40, 8)]).await.1);

    assert_eq!(
        quiet, 0,
        "`w_quiet` is never written, so it cannot fire {quiet} times"
    );
    assert_eq!(past, 0, "an address 0x40 past `w_alpha` fired {past} times");
    assert_ne!(
        alpha, beta,
        "watching `w_alpha` and watching `w_beta` both produced {alpha} stops; the count does \
         not depend on WHICH global is watched, so it cannot pin a watchpoint to an address"
    );
    assert_eq!(
        (alpha, beta),
        (decl.writes["w_alpha"], decl.writes["w_beta"]),
        "the pair of counts must be the pair the program declared"
    );
}

/// Four watchpoints at once: the HISTOGRAM keyed by reported address must match
/// the declaration, not just the total.
///
/// A total is lax in the exact way the previous round measured: cross two slots
/// and the sum is unchanged. Here crossing two slots swaps two entries of the
/// map and the assertion fails.
#[tokio::test]
async fn four_live_watchpoints_report_each_their_own_declared_writes() {
    let fx = wp_fixture!();
    let (decl, _) = run_watching(&fx, &[]).await;
    let names = ["w_alpha", "w_beta", "w_gamma", "w_quiet"];
    let mut watched: Vec<(u64, u8)> = names.iter().map(|n| (decl.addrs[*n], 8u8)).collect();
    if mutating("cross") {
        // `swap(0, 1)` would only reorder the arming and change nothing — the
        // SET of watched addresses would be identical, which is itself worth
        // knowing: order is not the observable here. To make the slot
        // assignment wrong, slot 0 is given slot 1's address, so `w_alpha`
        // vanishes from the histogram and `w_beta` is watched twice.
        watched[0].0 = decl.addrs["w_beta"];
    }
    let (decl2, hist) = run_watching(&fx, &watched).await;
    let want: BTreeMap<u64, usize> = names
        .iter()
        .filter(|n| decl2.writes[**n] > 0)
        .map(|n| (decl2.addrs[*n], decl2.writes[*n]))
        .collect();
    let named = |a: u64| {
        names
            .iter()
            .find(|n| decl2.addrs[**n] == a)
            .map(|n| (*n).to_string())
            .unwrap_or_else(|| format!("{a:#x} (declared by nobody)"))
    };
    assert_eq!(
        hist,
        want,
        "with all four globals watched at once the debugger reported {:?}, the program \
         declared {:?}",
        hist.iter().map(|(a, c)| (named(*a), *c)).collect::<Vec<_>>(),
        names
            .iter()
            .filter(|n| decl2.writes[**n] > 0)
            .map(|n| (*n, decl2.writes[*n]))
            .collect::<Vec<_>>()
    );
}

/// The debug registers read back out of the tracee must hold the address the
/// PROGRAM declared — closing the loop the sibling file leaves open.
///
/// The sibling's version obtains the address from `get_registers().sp`, arms
/// there and reads it back: backend to backend. Here the address comes from the
/// tracee's own `printf`, so a slot programmed with anything else is visible.
#[tokio::test]
async fn the_debug_registers_hold_the_address_the_program_printed() {
    let fx = wp_fixture!();
    let (decl, _) = run_watching(&fx, &[]).await;
    let mut addr = decl.addrs["w_alpha"];
    if mutating("addr_shift") {
        addr += 8;
    }
    if mutating("swap") {
        addr = decl.addrs["w_beta"];
    }

    let _ = std::fs::remove_file(&fx.report);
    let dbg = LinuxDebugger::new();
    let pid = dbg
        .launch(launch_opts(&fx.exe, &fx.report))
        .await
        .expect("launch");
    dbg.set_watchpoint_sized(Address(addr), BreakpointKind::DataWrite, 8)
        .await
        .expect("arming on the declared address must succeed");
    let regs = dbg
        .get_registers(ThreadId(pid.0))
        .await
        .expect("get_registers on the stopped tracee");
    let dr7 = regs.get("dr7").unwrap_or(0);
    let slot = armed_slot(&regs, addr);
    // Run it out so the declaration exists even on the failing path.
    let mut fired = 0usize;
    for _ in 0..128 {
        match tokio::time::timeout(Duration::from_secs(30), dbg.continue_execution()).await {
            Ok(Ok(ev)) => match ev.reason {
                StopReason::Breakpoint { .. } => fired += 1,
                StopReason::ProcessExit { .. } => break,
                _ => {}
            },
            _ => break,
        }
    }
    let _ = dbg.kill().await;
    let declared = parse_report(&std::fs::read_to_string(&fx.report).unwrap_or_default());

    assert!(
        slot.is_some(),
        "no enabled debug register holds {addr:#x}, the address the tracee printed for a \
         global; DR7={dr7:#x}, DR0-DR3={:?}",
        ["dr0", "dr1", "dr2", "dr3"].map(|n| regs.get(n))
    );
    assert_eq!(
        fired, declared.writes["w_alpha"],
        "the slot held the right address but fired {fired} times against the {} writes the \
         program declared",
        declared.writes["w_alpha"]
    );
}

// -- the thread/module fixture ----------------------------------------------

/// Each thread declares its own `gettid()` before signalling readiness, so the
/// SET of tids is known to the test without asking the debugger anything.
const THR_FIXTURE_C: &str = r#"
#include <stdio.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <sys/syscall.h>
#define NWORKERS 3
static FILE *g_rep;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_ready = 0;
static void announce(void) {
    pthread_mutex_lock(&g_lock);
    fprintf(g_rep, "TID x %ld\n", (long)syscall(SYS_gettid));
    fflush(g_rep);
    pthread_mutex_unlock(&g_lock);
}
static void *worker(void *arg) {
    (void)arg;
    announce();
    __sync_fetch_and_add(&g_ready, 1);
    for (;;) { }
    return 0;
}
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    g_rep = fopen(argv[1], "w");
    if (!g_rep) return 3;
    announce();
    pthread_t t[NWORKERS];
    for (int i = 0; i < NWORKERS; i++) pthread_create(&t[i], 0, worker, 0);
    while (g_ready < NWORKERS) { }
    fprintf(g_rep, "WRITES threads %d\n", NWORKERS + 1);
    fflush(g_rep);
    raise(SIGTRAP);
    for (;;) { }
    return 0;
}
"#;

struct ThrFixture {
    _dir: tempfile::TempDir,
    report: std::path::PathBuf,
    dbg: LinuxDebugger,
    pid: u32,
}

impl ThrFixture {
    /// Launch and resume until the fixture's own `raise(SIGTRAP)` — the point
    /// at which the program has declared every tid.
    ///
    /// The resume loop consumes only `ThreadCreate` stops and breaks on the
    /// first stop that is something else: resuming *until* a condition holds
    /// would hang forever on a kernel that never sends another stop, and a hang
    /// is not a failure anybody can read.
    async fn start() -> Option<Self> {
        let dir = tempfile::tempdir().ok()?;
        let exe = compile(dir.path(), "devacthr", THR_FIXTURE_C)?;
        let report = dir.path().join("thr_report.txt");
        // A previous test that panicked leaves its `LinuxDebugger` event loop
        // running, and that loop reaps with `waitpid(-1, __WALL)` — process
        // global. MEASURED: under `RUSTRE_DEVAC_MUT=tid_add`, the two thread
        // guards panicked and the next `start()` then hung for 18 minutes in
        // `futex_do_wait` with its fixture spinning. The timeout turns that
        // hang into a readable failure, and the sweep removes the spinner.
        let _ = std::process::Command::new("pkill")
            .args(["-9", "-x", "devacthr"])
            .output();
        let dbg = LinuxDebugger::new();
        let pid = tokio::time::timeout(Duration::from_secs(30), dbg.launch(launch_opts(&exe, &report)))
            .await
            .expect(
                "launch hung: a previous test's debugger event loop is still reaping with                  waitpid(-1, __WALL) and swallowed this child's stops",
            )
            .expect("the pthread fixture must launch under ptrace");
        for _ in 0..64 {
            match tokio::time::timeout(Duration::from_secs(30), dbg.continue_execution()).await {
                Ok(Ok(ev)) => match ev.reason {
                    StopReason::ThreadCreate { .. } => continue,
                    _ => break,
                },
                _ => break,
            }
        }
        Some(Self {
            _dir: dir,
            report,
            dbg,
            pid: pid.0,
        })
    }

    /// What the program itself said, possibly mutated to prove the guards bite.
    fn declared_tids(&self) -> BTreeSet<u32> {
        let text = std::fs::read_to_string(&self.report).unwrap_or_default();
        let mut tids = parse_report(&text).tids;
        if mutating("tid_drop") {
            if let Some(first) = tids.iter().next().copied() {
                tids.remove(&first);
            }
        }
        if mutating("tid_add") {
            tids.insert(999_999);
        }
        tids
    }

    async fn shutdown(self) {
        let _ = self.dbg.kill().await;
    }
}

impl Drop for ThrFixture {
    fn drop(&mut self) {
        // The fixture spins forever, so leaking it costs a core for the rest of
        // the run. `output()` rather than `status()` so "No such process" does
        // not pollute the log when `shutdown` already did the work.
        let _ = std::process::Command::new("kill")
            .arg("-9")
            .arg(self.pid.to_string())
            .output();
    }
}

macro_rules! thr_fixture {
    () => {
        match ThrFixture::start().await {
            Some(f) => f,
            None => {
                eprintln!("skipping: `cc -no-pie -pthread` is not usable here");
                return;
            }
        }
    };
}

/// The tids the kernel lists, read by the test with no help from the crate.
fn proc_task_tids(pid: u32) -> BTreeSet<u32> {
    std::fs::read_dir(format!("/proc/{pid}/task"))
        .expect("/proc/<pid>/task must exist for a live process")
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect()
}

/// The file-backed mappings `/proc/<pid>/maps` lists, as path -> lowest address.
fn proc_file_backed(pid: u32) -> BTreeMap<String, u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap_or_default();
    let mut out: BTreeMap<String, u64> = BTreeMap::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let range = it.next().unwrap_or("");
        let (_perms, _off, _dev, _ino) = (it.next(), it.next(), it.next(), it.next());
        let Some(path) = it.next() else { continue };
        if !path.starts_with('/') {
            continue;
        }
        let Some(start) = range
            .split('-')
            .next()
            .and_then(|s| u64::from_str_radix(s, 16).ok())
        else {
            continue;
        };
        out.entry(path.to_string())
            .and_modify(|v| *v = (*v).min(start))
            .or_insert(start);
    }
    if mutating("map_drop") {
        if let Some(k) = out.keys().next().cloned() {
            out.remove(&k);
        }
    }
    out
}

// -- thread / module guards -------------------------------------------------

/// `threads()` must answer the EXACT SET of tids, checked against two oracles
/// produced independently of each other and of the debugger.
///
/// The campaign's finding for `live_linux_threads_modules.rs` was that its
/// thread assertions survive any mutation because they are about the SIZE of
/// the list. A size is lax; a set is not — and the two oracles here are a
/// stronger pair than either alone, because the program's own `gettid()` list
/// cannot include a thread the C runtime created behind its back while
/// `/proc/<pid>/task` can. Requiring `threads() == /proc` AND
/// `declared` a subset of `threads()` fails both a missing thread and an
/// invented one.
#[tokio::test]
async fn threads_are_exactly_the_tids_the_kernel_and_the_program_both_know() {
    let fx = thr_fixture!();
    let declared = fx.declared_tids();
    let from_proc = proc_task_tids(fx.pid);
    let from_dbg: BTreeSet<u32> = fx
        .dbg
        .threads()
        .await
        .expect("threads() on a live, stopped process")
        .into_iter()
        .map(|t| t.0)
        .collect();

    // Guards against a VACUOUS oracle: the empty set is a subset of every set,
    // so an unwritten report would satisfy both subset assertions below. The
    // discriminating work is done by the set comparisons, not by this count.
    assert!(
        declared.len() >= 4,
        "the fixture must have declared main + 3 workers before raising SIGTRAP, got {declared:?}"
    );
    assert!(
        declared.is_subset(&from_proc),
        "the program printed tids {declared:?} that /proc/{}/task does not list ({from_proc:?}); \
         the two external oracles disagree",
        fx.pid
    );
    assert_eq!(
        from_dbg, from_proc,
        "threads() answered {from_dbg:?} while /proc/{}/task lists {from_proc:?}",
        fx.pid
    );
    assert!(
        declared.is_subset(&from_dbg),
        "threads() answered {from_dbg:?}, which omits tids the program itself printed: {:?}",
        declared.difference(&from_dbg).collect::<Vec<_>>()
    );
    fx.shutdown().await;
}

/// Every tid the program declared must be usable as a tid — a list of ids no
/// operation accepts is a list of numbers.
///
/// `get_registers` is the cheapest such operation and the process is stopped,
/// so it must succeed for each. The point is not the register values but that
/// the enumeration and the per-thread path agree about which threads exist:
/// they are different code, and only one of them is exercised by a size
/// assertion.
#[tokio::test]
async fn every_tid_the_program_declared_answers_as_a_thread() {
    let fx = thr_fixture!();
    let declared = fx.declared_tids();
    assert!(
        declared.len() >= 4,
        "precondition: the program must have declared main + 3 workers, got {declared:?}"
    );
    let from_proc = proc_task_tids(fx.pid);
    assert!(
        declared.is_subset(&from_proc),
        "the program printed tids {declared:?} the kernel does not list in          /proc/{}/task ({from_proc:?})",
        fx.pid
    );
    let mut refused = Vec::new();
    for tid in &declared {
        if fx.dbg.get_registers(ThreadId(*tid)).await.is_err() {
            refused.push(*tid);
        }
    }
    assert!(
        refused.is_empty(),
        "the program printed tids {declared:?} and /proc lists {:?}, but get_registers refused \
         {refused:?} of them on a stopped process",
        proc_task_tids(fx.pid)
    );
    fx.shutdown().await;
}

/// `modules()` must be the file-backed mappings the kernel lists, at the bases
/// the kernel lists them at.
///
/// Checked as a SET of paths plus a per-path base, not a count: a module list
/// of the right length naming the wrong files, or naming the right files at
/// invented bases, is exactly the failure a count cannot see. `map_drop`
/// proves the comparison bites.
#[tokio::test]
async fn modules_are_the_file_backed_mappings_at_the_kernels_bases() {
    let fx = thr_fixture!();
    let kernel = proc_file_backed(fx.pid);
    let mods = fx.dbg.modules().await.expect("modules() on a live process");

    assert!(
        !kernel.is_empty(),
        "/proc/{}/maps listed no file-backed mapping; the oracle is empty and would agree \
         with anything",
        fx.pid
    );
    let dbg_paths: BTreeSet<String> = mods.iter().map(|m| m.path.clone()).collect();
    let kernel_paths: BTreeSet<String> = kernel.keys().cloned().collect();
    assert_eq!(
        dbg_paths, kernel_paths,
        "modules() named {dbg_paths:?}, /proc/{}/maps names {kernel_paths:?}",
        fx.pid
    );
    for m in &mods {
        assert_eq!(
            m.base.as_u64(),
            kernel[&m.path],
            "modules() put `{}` at {:#x}; the kernel maps it from {:#x}",
            m.path,
            m.base.as_u64(),
            kernel[&m.path]
        );
    }
    let exe = std::fs::read_link(format!("/proc/{}/exe", fx.pid))
        .expect("/proc/<pid>/exe must resolve")
        .to_string_lossy()
        .into_owned();
    let main: Vec<&str> = mods
        .iter()
        .filter(|m| m.is_main)
        .map(|m| m.path.as_str())
        .collect();
    assert_eq!(
        main,
        vec![exe.as_str()],
        "exactly one module must be flagged main, and it must be the binary \
         /proc/<pid>/exe points at"
    );
    fx.shutdown().await;
}

/// No fixture may outlive this suite.
///
/// `pgrep -x` matches the process NAME exactly. `-f` was measured in
/// `live_linux_falsification.rs` to match cargo's own
/// `live_linux_devac_watchpoints-<hash>` binary, so the orphan check written
/// that way reports the checker as the orphan.
#[tokio::test]
async fn zz_no_orphan_devac_fixture_survives() {
    for name in ["devacwp", "devacthr"] {
        let Ok(out) = std::process::Command::new("pgrep").args(["-x", name]).output() else {
            eprintln!("[test] pgrep is unavailable; the orphan check cannot run");
            return;
        };
        // A tracee killed on a panicking path stays visible to `pgrep` until
        // its tracer reaps it, and the tracer is a thread of THIS binary, so it
        // cannot reap after the test that owned it died. That is a zombie: it
        // holds a pid slot and nothing else, and it disappears when this
        // process exits. A LIVE leftover is the thing that costs a core and
        // corrupts the next test's stop stream, so the two are reported apart
        // rather than merged into one lax count.
        let mut alive = Vec::new();
        let mut zombies = Vec::new();
        for pid in String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
        {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            let state = stat.rsplit(") ").next().and_then(|s| s.chars().next());
            if state == Some('Z') {
                zombies.push(pid);
            } else {
                alive.push(format!("{pid} (state {:?})", state));
            }
        }
        if !zombies.is_empty() {
            eprintln!("[test] {} unreaped `{name}` zombie(s): {zombies:?}", zombies.len());
        }
        assert!(
            alive.is_empty(),
            "the suite left {} RUNNING `{name}` process(es) behind: {alive:?}",
            alive.len()
        );
    }
}
