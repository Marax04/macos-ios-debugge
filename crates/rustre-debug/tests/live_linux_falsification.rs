//! Guard tests born out of a FALSIFICATION campaign against the existing
//! `live_linux_*` suites.
//!
//! ## What the campaign did
//!
//! For each of the twenty `live_linux_*.rs` files present before this one, ONE
//! datum of the external ground truth was changed — the address `nm` prints,
//! the symbol count `nm` reports, the permission bits `/proc/<pid>/maps` shows,
//! the tid list the kernel exposes — and the suite was re-run. A test that stays
//! green after the truth underneath it moved does not bite on that truth.
//!
//! Measured: 230 tests, 211 active, 19 ignored — **68 bite, 143 do not**.
//!
//! Three files bit on NOTHING, even under the strongest mutation available:
//!
//! * `live_linux_breakpoints.rs` and `live_linux_load.rs` — every symbol was
//!   made to resolve to `main` instead of the requested function. 18 of 20 and
//!   8 of 8 stayed green. Cause, read rather than guessed: the helper
//!   `run_until_breakpoint(dbg, addr, ..)` FILTERS the stop stream on the very
//!   address the test then asserts on, so the loop closes on itself. Any mapped,
//!   executable, actually-crossed address satisfies it.
//! * `live_linux_elf_symbols.rs` — `nm_count`, the only independent oracle in
//!   the file, was made to return `0`. 9 of 9 stayed green, because the value it
//!   feeds (`Gap::expected`) occurs only inside `format!` arguments and in no
//!   assertion at all. The gap table it produces is decorative.
//!
//! ## What this file adds
//!
//! Guards anchored on a truth that MOVES when the symbol table moves:
//!
//! * [`the_crossing_count_pins_each_symbol_to_its_own_address`] counts stops
//!   WITHOUT filtering on the address, so the count is an observable of the
//!   program rather than of the bookkeeping. `main` calls `hot` five times,
//!   `warm` once and `cold` never; the triple `(5, 1, 0)` is reproduced by
//!   exactly one assignment of addresses to names.
//! * [`the_crossing_count_guard_is_itself_falsifiable`] performs the mutation on
//!   the guard itself and REQUIRES the number to change. Without it the guard
//!   above would be one more assertion nobody had ever seen go red.
//! * [`parse_elf_resolves_every_name_nm_defines`] makes `nm` load-bearing
//!   instead of decorative.
//! * [`every_reported_region_appears_verbatim_in_proc_maps`] checks the backend
//!   against the kernel's text file rather than against its own restatement of
//!   it.
//!
//! ## These guards were falsified too
//!
//! Five mutations of the ground truth under THIS file, each run against the
//! whole suite (8 tests, green at rest):
//!
//! | mutation of the external truth | tests that went red |
//! |---|---|
//! | `nm_address` shifted by `0x40` | 4 |
//! | `CROSSINGS` says `hot` is called 4 times, not 5 | 1 |
//! | `nm_defined_names` prefixes every name with `zz_` | 1 |
//! | reported region bases shifted by one page | 1 |
//! | the fixture renames `cold` to `coldx` | 3 |
//!
//! Seven of the eight bite under at least one. The eighth,
//! [`zz_no_orphan_falsification_fixture_survives`], needs no synthetic mutation:
//! it went red on its first real run, catching a defect in itself rather than in
//! the backend — `pgrep -f falsif` matched cargo's own
//! `live_linux_falsification-<hash>` binary. That is recorded at the test.
//!
//! One weak assertion was found this way and replaced. The first version of
//! [`parse_elf_resolves_every_name_nm_defines`] compared COUNTS
//! (`obtained >= nm_count`); forcing the oracle from 28 to 31 left it green,
//! because `parse_elf` returns comfortably more entries than either. A count is
//! slack; the set of NAMES is not.
//!
//! Everything here drives a real process: a C fixture compiled with `cc` into a
//! tempdir and run under `ptrace`. Nothing asserts on a structure built in
//! memory.
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::{BreakpointKind, Debugger, LaunchOptions, OutputRedirect, StopReason, ThreadId};
use rustre_symbols::SymbolProvider;
use rustre_symbols::elf_provider::ElfSymbolProvider;

/// The fixture. The call counts are the point: three DIFFERENT observables
/// attached to three addresses, so no single wrong address reproduces all three.
const FIXTURE_C: &str = r#"
#include <stdio.h>
__attribute__((noinline)) int hot(int x)  { return x + 1; }
__attribute__((noinline)) int warm(int x) { return x + 2; }
__attribute__((noinline)) int cold(int x) { return x + 3; }
int main(void) {
    volatile int s = 0;
    for (int i = 0; i < 5; i++) { s = hot(s); }
    s = warm(s);
    printf("%d\n", s);
    return 0;
}
"#;

/// How often `main` really crosses each function. Ground truth read off the
/// source above, not off the debugger.
const CROSSINGS: [(&str, usize); 3] = [("hot", 5), ("warm", 1), ("cold", 0)];

struct Fixture {
    _dir: tempfile::TempDir,
    exe: String,
    bytes: Vec<u8>,
}

impl Fixture {
    /// The address `nm` prints. The binary is `-no-pie`, so this IS the address
    /// the CPU executes.
    fn addr(&self, name: &str) -> u64 {
        nm_address(&self.exe, name).unwrap_or_else(|| panic!("the fixture must export `{name}`"))
    }
}

fn build_fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("falsifwf5.c");
    let exe = dir.path().join("falsifwf5");
    std::fs::write(&src, FIXTURE_C).expect("write fixture source");
    let out = std::process::Command::new("cc")
        .args(["-no-pie", "-O0", "-g"])
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .output()
        .expect("cc must be available to run the live falsification guards");
    assert!(
        out.status.success(),
        "cc failed to build the fixture: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bytes = std::fs::read(&exe).expect("read the fixture back");
    Fixture { exe: exe.to_string_lossy().into_owned(), bytes, _dir: dir }
}

/// The address of a TEXT symbol, straight out of `nm`. Independent of the crate.
fn nm_address(exe: &str, want: &str) -> Option<u64> {
    let out = std::process::Command::new("nm").arg(exe).output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).lines().find_map(|line| {
        let mut it = line.split_whitespace();
        let addr = it.next()?;
        let kind = it.next()?;
        if it.next()? == want && (kind == "T" || kind == "t") {
            u64::from_str_radix(addr, 16).ok()
        } else {
            None
        }
    })
}

/// Every DEFINED symbol `nm` lists — the lower bound a symbol reader must reach.
fn nm_defined_names(exe: &str) -> Vec<String> {
    let out = std::process::Command::new("nm")
        .args(["--defined-only", exe])
        .output()
        .expect("nm --defined-only");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() == 3).then(|| f[2].to_string())
        })
        .collect()
}

fn launch_opts(exe: &str) -> LaunchOptions {
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

async fn launched(fx: &Fixture) -> LinuxDebugger {
    let dbg = LinuxDebugger::new();
    dbg.launch(launch_opts(&fx.exe)).await.expect("launch should succeed");
    dbg
}

/// Resume to process exit and count EVERY breakpoint stop seen on the way.
///
/// The address is deliberately NOT consulted. That is the whole point: the
/// existing suites resume with a helper that filters the stop stream on the
/// address they then assert on, which makes any crossed address pass. Counting
/// blind turns the crossing count into an observable a wrong address cannot fake.
async fn count_stops_to_exit(dbg: &LinuxDebugger, budget: usize) -> usize {
    let mut stops = 0usize;
    for _ in 0..budget {
        match dbg.continue_execution().await {
            Ok(ev) => match ev.reason {
                StopReason::Breakpoint { .. } => stops += 1,
                StopReason::ProcessExit { .. } => return stops,
                _ => {}
            },
            Err(_) => return stops,
        }
    }
    stops
}

/// Plant one software breakpoint at `at`, run the program to completion, and
/// return how many times it was crossed. The tracee is always killed, including
/// on the error paths, so no fixture process can outlive the test.
async fn crossings_at(fx: &Fixture, at: u64) -> usize {
    let dbg = launched(fx).await;
    if dbg.set_breakpoint(Address(at), BreakpointKind::Software).await.is_err() {
        let _ = dbg.kill().await;
        panic!("set_breakpoint refused the address {at:#x}, so nothing can be counted");
    }
    let n = count_stops_to_exit(&dbg, 64).await;
    let _ = dbg.kill().await;
    n
}

// ─────────────────────────────────────────────────────────────────────────────
// Guard 1 — an address must be the address of THAT function
// ─────────────────────────────────────────────────────────────────────────────

/// Each symbol's address must produce the number of crossings its NAME implies.
///
/// This is the guard against the vacuity measured in `live_linux_breakpoints.rs`
/// and `live_linux_load.rs`: making every symbol resolve to `main` left 26 of
/// their 28 tests green, because each test resumes with a helper that filters
/// stops on the address it is about to assert on, and then compares that address
/// to itself.
///
/// Here the count is taken blind — every breakpoint stop is counted, whatever
/// its address — so the number describes the PROGRAM. `main` calls `hot` five
/// times, `warm` once and `cold` never, so the triple `(5, 1, 0)` is reproduced
/// by exactly one assignment of addresses to names. Point `hot` at `main` and
/// its count falls to 1; point it at `cold` and it falls to 0.
#[tokio::test]
async fn the_crossing_count_pins_each_symbol_to_its_own_address() {
    let fx = build_fixture();
    let mut got = Vec::new();
    for (name, _) in CROSSINGS {
        got.push((name, crossings_at(&fx, fx.addr(name)).await));
    }
    let want: Vec<(&str, usize)> = CROSSINGS.to_vec();
    assert_eq!(
        got, want,
        "crossings per function were {got:?} but the source says {want:?}; a count that does \
         not match the call structure means the breakpoint was planted somewhere other than \
         the named function"
    );
}

/// The guard above must FAIL when the address underneath it moves.
///
/// `cold` is never called, so any breakpoint on it is crossed zero times; `hot`
/// is crossed five. If feeding one address where the other belongs does not
/// change the number, the counting is not measuring the program and every test
/// built on it is worthless.
#[tokio::test]
async fn the_crossing_count_guard_is_itself_falsifiable() {
    let fx = build_fixture();
    let hot = crossings_at(&fx, fx.addr("hot")).await;
    let cold = crossings_at(&fx, fx.addr("cold")).await;
    assert_ne!(
        hot, cold,
        "planting on `hot` (called five times) and on `cold` (never called) produced the same \
         count {hot}; the crossing count does not depend on the address"
    );
    assert_eq!(cold, 0, "`cold` is never called, so it cannot be crossed {cold} times");
}

/// The stop must be reported at the address `nm` prints, and the CPU must agree.
///
/// `live_linux_breakpoints.rs` asserts `address == fx.hot` after resuming with a
/// helper that already discarded every stop whose address was not `fx.hot`, so
/// the assertion is a tautology. Here the first stop is taken UNFILTERED and
/// checked against two independent witnesses: `nm`, and the program counter read
/// out of the live thread.
#[tokio::test]
async fn the_first_unfiltered_stop_is_at_the_nm_address_and_the_cpu_agrees() {
    let fx = build_fixture();
    let hot = fx.addr("hot");
    let dbg = launched(&fx).await;
    dbg.set_breakpoint(Address(hot), BreakpointKind::Software)
        .await
        .expect("set_breakpoint at `hot`");

    let mut reported = None;
    for _ in 0..32 {
        match dbg.continue_execution().await {
            Ok(ev) => match ev.reason {
                StopReason::Breakpoint { address, .. } => {
                    reported = Some(address.as_u64());
                    break;
                }
                StopReason::ProcessExit { .. } => break,
                _ => {}
            },
            Err(_) => break,
        }
    }
    let Some(reported) = reported else {
        let _ = dbg.kill().await;
        panic!("the process never stopped, though `hot` is called five times");
    };
    let pid = dbg.target_pid().expect("a live pid");
    let pc = dbg.get_registers(ThreadId(pid.0)).await.map(|r| r.pc);
    let _ = dbg.kill().await;
    let pc = pc.expect("get_registers at the stop");

    assert_eq!(
        reported, hot,
        "the first breakpoint stop was reported at {reported:#x}; `nm` puts `hot` at {hot:#x}"
    );
    assert_eq!(
        pc, hot,
        "the thread's program counter at the stop is {pc:#x}, not the {hot:#x} the stop event \
         claims; the event and the hardware describe different places"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Guard 2 — `nm` must be load-bearing for the symbol reader
// ─────────────────────────────────────────────────────────────────────────────

/// `parse_elf` must resolve every NAME `nm --defined-only` lists.
///
/// This is the guard against the vacuity measured in `live_linux_elf_symbols.rs`:
/// `nm_count` there was forced to return `0` and all nine tests stayed green,
/// because the value only ever reaches a `format!` argument. `nm` was that
/// file's one independent oracle and it constrained nothing. Here it is an
/// assertion.
///
/// The fixture is proved to be a real, runnable program first — launched under
/// `ptrace` and killed — so this is a statement about a binary the kernel
/// accepts, not about a byte array.
#[tokio::test]
async fn parse_elf_resolves_every_name_nm_defines() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let runnable = dbg
        .target_pid()
        .map(|p| std::path::Path::new(&format!("/proc/{}", p.0)).exists())
        .unwrap_or(false);
    let _ = dbg.kill().await;
    assert!(runnable, "the fixture must be a program the kernel really runs");

    let expected = nm_defined_names(&fx.exe);
    assert!(expected.len() > 10, "guard: `nm` must list a real symbol table, got {expected:?}");
    let provider =
        ElfSymbolProvider::parse_elf("subject", &fx.bytes).expect("parse_elf must accept an ELF");

    // A COUNT is the weak form of this assertion, and it was MEASURED to be
    // slack: `nm --defined-only` lists 28 names for this fixture while
    // `parse_elf` returns more entries than that, so `obtained >= 28` passes
    // with room to spare and stops constraining anything — forcing the oracle
    // to report 31 instead of 28 left this test green. Every NAME must be
    // present instead: a set containment cannot be satisfied by returning the
    // right number of wrong entries.
    let missing: Vec<&String> =
        expected.iter().filter(|n| provider.lookup_name(n).is_none()).collect();
    assert!(
        missing.is_empty(),
        "parse_elf reports {} symbols but cannot resolve {} of the {} names `nm --defined-only`          lists, e.g. {:?}; the external oracle must constrain the reader, not merely decorate          its error message",
        provider.symbol_count(),
        missing.len(),
        expected.len(),
        &missing[..missing.len().min(5)]
    );
}

/// The three functions the fixture defines must be findable BY NAME.
///
/// A count can be reached by any set of entries; a name cannot. This is the
/// assertion that survives a symbol reader returning the right number of wrong
/// things.
#[tokio::test]
async fn parse_elf_finds_the_fixture_functions_by_name() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let alive = dbg.target_pid().is_some();
    let _ = dbg.kill().await;
    assert!(alive, "the fixture must be a program the kernel really runs");

    let provider = ElfSymbolProvider::parse_elf("subject", &fx.bytes).expect("parse_elf");
    let missing: Vec<&str> =
        ["hot", "warm", "cold"].into_iter().filter(|n| provider.lookup_name(n).is_none()).collect();
    assert!(
        missing.is_empty(),
        "parse_elf cannot resolve {missing:?}, which `nm` lists in this very binary"
    );
}

/// A symbol resolved by the crate must land where `nm` puts it AND where the
/// program's own control flow says it is.
///
/// The three-way agreement is the point. `live_linux_symbols.rs` compares the
/// resolved address with `nm`'s — and both shift together when the oracle is
/// shifted, which is why that comparison survived the mutation. The crossing
/// count is a third witness that comes from the program's control flow and
/// cannot be shifted by any change to the symbol table.
#[tokio::test]
async fn a_resolved_address_agrees_with_nm_and_with_the_programs_control_flow() {
    let fx = build_fixture();
    let provider = ElfSymbolProvider::parse_elf("subject", &fx.bytes).expect("parse_elf");
    let sym = provider
        .lookup_name("warm")
        .expect("parse_elf cannot resolve `warm`, so there is nothing to cross-check");
    let resolved = sym.address;
    let from_nm = fx.addr("warm");
    assert_eq!(
        resolved, from_nm,
        "the crate resolves `warm` to {resolved:#x} and `nm` to {from_nm:#x}"
    );
    let crossed = crossings_at(&fx, resolved).await;
    assert_eq!(
        crossed, 1,
        "a breakpoint at the resolved address of `warm` was crossed {crossed} times; `main` \
         calls it exactly once, so the address is not `warm`"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Guard 3 — the kernel's own map, not the backend's restatement of it
// ─────────────────────────────────────────────────────────────────────────────

/// Every region the backend reports must exist, byte for byte, in
/// `/proc/<pid>/maps`.
///
/// `live_linux_memory_limits.rs` derives its boundaries from the backend's own
/// `MemoryMap` list, so shifting every end by a page left 6 of its 9 tests
/// green: it was checking the backend against itself. The kernel's text file is
/// the only external witness for a mapping, and this makes it one.
#[tokio::test]
async fn every_reported_region_appears_verbatim_in_proc_maps() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let pid = dbg.target_pid().expect("a live pid").0;
    let raw = std::fs::read_to_string(format!("/proc/{pid}/maps")).expect("read /proc/<pid>/maps");
    let maps = dbg.memory_maps().await;
    let _ = dbg.kill().await;
    let maps = maps.expect("memory_maps on a live tracee");

    let kernel: std::collections::HashSet<(u64, u64)> = raw
        .lines()
        .filter_map(|l| {
            let range = l.split_whitespace().next()?;
            let (a, b) = range.split_once('-')?;
            Some((u64::from_str_radix(a, 16).ok()?, u64::from_str_radix(b, 16).ok()?))
        })
        .collect();
    assert!(!kernel.is_empty(), "the kernel listed no mappings for a live process");

    let strays: Vec<(u64, u64)> = maps
        .iter()
        .map(|m| (m.base.as_u64(), m.base.as_u64() + m.size))
        .filter(|r| !kernel.contains(r))
        .collect();
    assert!(
        strays.is_empty(),
        "{} of {} reported regions have no counterpart in /proc/{pid}/maps: {:x?}",
        strays.len(),
        maps.len(),
        &strays[..strays.len().min(4)]
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Hygiene
// ─────────────────────────────────────────────────────────────────────────────

/// No fixture process may outlive this suite.
///
/// Named `zz_` so it runs last under `--test-threads=1`. Every helper above
/// kills its tracee on the error paths too, and this is the check that says so
/// out loud rather than on trust.
#[tokio::test]
async fn zz_no_orphan_falsification_fixture_survives() {
    // `-x` matches the process NAME exactly, never the command line. `-f` was
    // tried first and failed: it matched this suite's own binary, which cargo
    // names `live_linux_falsification-<hash>`. The check has to be able to tell
    // the fixture from the thing looking for it.
    let Ok(out) = std::process::Command::new("pgrep").args(["-x", "falsifwf5"]).output() else {
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
        "the suite left {} `falsifwf5` process(es) behind: {listed:?}",
        listed.len()
    );
}
