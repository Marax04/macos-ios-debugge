//! INDEPENDENT AUDIT of the de-vacuation round (workflow #6).
//!
//! Two files were de-vacuated and declared "20 of 21" and "8 of 8" biting. This
//! file re-ran the falsification with DIFFERENT mutations — a *consistent* swap
//! of two symbols, an address moved a few bytes INSIDE the same function, and a
//! wrong expected trap byte — and records what actually bit. The numbers below
//! are copied from those runs; the tests here are the guards the measurements
//! showed to be MISSING.
//!
//! | mutation | file | red / total |
//! |---|---|---|
//! | `hot` gets `warm`'s address and `warm` gets `hot`'s, BOTH oracles consistent | breakpoints | **6 / 21** |
//! | the same, second oracle left INCONSISTENT (the round's own mutation) | breakpoints | 20 / 21 |
//! | `hot` and `warm` exchanged in the C source (a different program) | breakpoints | 6 / 21 |
//! | the address under test moved to `hot + 8`, window shifted to match | breakpoints | **0 / 21** |
//! | the expected trap byte changed to `0xCD` | breakpoints | 4 / 21 |
//! | `hot` and `filler` exchanged | load | 8 / 9 |
//! | `filler` moved 128 bytes into itself | load | **0 / 9** on the oracle |
//! | the expected trap byte changed to `0xCD` | load | 2 / 9, one of them intermittent |
//!
//! Three gaps follow from that table, and this file closes them:
//!
//! * **The 32-byte window catches oracle DISAGREEMENT, not a wrong function.**
//!   When the mapping is corrupted consistently — `hot` bound to `warm`'s
//!   address *and* to `warm`'s disassembly — only the six count-based tests of
//!   `live_linux_breakpoints.rs` notice. The window is worth having, but the
//!   claim "20 of 21 bite on the address" holds only for a mutation that
//!   forgets to update the second oracle.
//! * **Nothing pins the ENTRY.** `hot + 8` is inside `hot`, on an instruction
//!   boundary, and crossed exactly as often; every oracle in both files accepts
//!   it. [`the_breakpoint_address_is_the_entry_of_hot_not_merely_inside_it`]
//!   separates the two.
//! * **The program's own stdout was never used.** It is the cheapest
//!   independent oracle available — the debugger does not produce it — and the
//!   only one here that survives a *renaming* of the fixture's functions, which
//!   no reading of the symbol table can detect.
//!
//! Self-falsification (the rule the previous round learned twice): every oracle
//! below must REJECT a deliberately wrong program or address in the same test
//! that uses it. A second binary is compiled from the source with the two call
//! sites exchanged, and each oracle has to tell the two apart. That rule paid
//! immediately: see the warning on `SWAPPED_C`.
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::{BreakpointKind, Debugger, LaunchOptions, OutputRedirect, StopReason};

/// The fixture: `main` calls `hot` five times (`+1` each) and `warm` once
/// (`+2`), then PRINTS the sum. Three independent observables come out of one
/// program:
///   * the crossing triple `(5, 1, 0)` — reproduced by exactly one assignment
///     of addresses to names;
///   * the stdout line `7` = 5*1 + 2 — which no rearrangement of the symbol
///     table can change, and which becomes `11` if the two CALL SITES are exchanged;
///   * the bytes `objdump` disassembles at each entry.
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

/// The same program with the two CALL SITES exchanged: `warm` is now the one
/// called five times and `hot` the one called once. Every symbol still exists,
/// every name still resolves, `nm` and `objdump` still agree — the ELF is
/// internally consistent. Only an oracle that looks at what the program DOES
/// can tell it from the fixture above. Used to falsify the oracles themselves.
///
/// ⚠ The first version of this constant exchanged the two BODIES as well, and
/// the stdout oracle went red on its own first run: `5*(+1) + (+2)` and
/// `5*(+1 renamed) + (+2 renamed)` are the same arithmetic, so both programs
/// printed `7` and the oracle separated nothing. Measured, not reasoned about —
/// which is the whole point of falsifying one's own oracle.
const SWAPPED_C: &str = r#"
#include <stdio.h>
__attribute__((noinline)) int hot(int x)  { return x + 1; }
__attribute__((noinline)) int warm(int x) { return x + 2; }
__attribute__((noinline)) int cold(int x) { return x + 3; }
int main(void) {
    volatile int s = 0;
    for (int i = 0; i < 5; i++) { s = warm(s); }
    s = hot(s);
    printf("%d\n", s);
    return 0;
}
"#;

/// The byte a software breakpoint writes on x86-64. Kept apart from the WIDTH
/// of the write on purpose: [`a_planted_trap_is_exactly_one_byte_wide`] asserts
/// the value and, separately, that nothing beyond it moved.
#[cfg(target_arch = "x86_64")]
const TRAP: u8 = 0xCC;
/// `BRK #0`, little-endian.
#[cfg(target_arch = "aarch64")]
const TRAP_WORD: [u8; 4] = [0x00, 0x00, 0x20, 0xD4];

struct Built {
    _dir: tempfile::TempDir,
    exe: String,
}

/// Compile `src` to a binary named `stem`. `-no-pie` makes it `ET_EXEC`, so the
/// address `nm` prints is the run-time address; the distinct stem is what makes
/// `pgrep -x` usable as an orphan check — `pgrep -f` would match cargo's own
/// test binary, a defect the previous round measured the hard way.
fn build(src: &str, stem: &str) -> Built {
    let dir = tempfile::tempdir().expect("tempdir");
    let c = dir.path().join(format!("{stem}.c"));
    let exe = dir.path().join(stem);
    std::fs::write(&c, src).expect("write fixture source");
    let out = std::process::Command::new("cc")
        .args(["-no-pie", "-O0", "-g"])
        .arg(&c)
        .arg("-o")
        .arg(&exe)
        .output()
        .expect("cc must be available to run the live audit tests");
    assert!(out.status.success(), "cc failed: {}", String::from_utf8_lossy(&out.stderr));
    Built { _dir: dir, exe: exe.to_string_lossy().to_string() }
}

/// The address of a text symbol, straight out of `nm`.
fn nm_addr(exe: &str, want: &str) -> u64 {
    let out = std::process::Command::new("nm").arg(exe).output().expect("nm");
    assert!(out.status.success(), "nm failed on {exe}");
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let p: Vec<&str> = line.split_whitespace().collect();
        if p.len() == 3 && p[2] == want && (p[1] == "T" || p[1] == "t") {
            return u64::from_str_radix(p[0], 16).expect("nm prints hex");
        }
    }
    panic!("`{want}` is not a text symbol of {exe}");
}

/// `(entry address, first opcode bytes)` from `objdump -d --disassemble=<name>`.
fn objdump_entry(exe: &str, name: &str, want: usize) -> (u64, Vec<u8>) {
    let out = std::process::Command::new("objdump")
        .args(["-d", &format!("--disassemble={name}"), exe])
        .output()
        .expect("objdump must be available to run the live audit tests");
    assert!(out.status.success(), "objdump failed on {exe}");
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let mut lines = text.lines();
    let header = lines
        .find(|l| l.trim_end().ends_with(&format!("<{name}>:")))
        .unwrap_or_else(|| panic!("objdump does not disassemble `{name}`"));
    let addr = u64::from_str_radix(header.split_whitespace().next().unwrap_or(""), 16)
        .expect("objdump prints the entry address in hex");
    let mut bytes = Vec::new();
    for line in lines {
        let Some((_, rest)) = line.split_once(':') else { break };
        let field = rest.split('\t').nth(1).unwrap_or("");
        let mut any = false;
        for tok in field.split_whitespace() {
            if tok.len() == 2 {
                if let Ok(b) = u8::from_str_radix(tok, 16) {
                    bytes.push(b);
                    any = true;
                }
            }
        }
        if !any || bytes.len() >= want {
            break;
        }
    }
    assert!(bytes.len() >= 16, "objdump listed too few opcode bytes for `{name}`");
    bytes.truncate(want);
    (addr, bytes)
}

/// What the program PRINTS when nobody is debugging it. The debugger does not
/// produce this, which is exactly what makes it an oracle.
fn stdout_of(exe: &str) -> String {
    let out = std::process::Command::new(exe).output().expect("run the fixture");
    assert!(out.status.success(), "the fixture exited with {:?}", out.status);
    String::from_utf8_lossy(&out.stdout).trim().to_string()
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

/// Bytes the CPU would fetch, read through `/proc/<pid>/mem`. `read_memory`
/// masks the debugger's own traps by design, so it can never witness a plant.
fn raw_bytes(dbg: &LinuxDebugger, addr: u64, n: usize) -> Vec<u8> {
    use std::io::{Read, Seek, SeekFrom};
    let pid = dbg.target_pid().expect("a live pid is required");
    let mut f = std::fs::File::open(format!("/proc/{}/mem", pid.0)).expect("open /proc/<pid>/mem");
    f.seek(SeekFrom::Start(addr)).expect("seek");
    let mut buf = vec![0u8; n];
    f.read_exact(&mut buf).expect("read");
    buf
}

/// Plant ONE breakpoint at `addr`, run to exit, and count every breakpoint stop
/// WITHOUT looking at the address it is reported at. Filtering the stop stream
/// on the address the test then asserts on is the tautology this audit is about.
async fn crossings(exe: &str, addr: u64, budget: usize) -> usize {
    let dbg = LinuxDebugger::new();
    dbg.launch(launch_opts(exe)).await.expect("launch");
    dbg.set_breakpoint(Address(addr), BreakpointKind::Software).await.expect("set_breakpoint");
    let pid = dbg.target_pid().expect("a live pid").0;
    let mut stops = 0usize;
    for _ in 0..budget {
        let Ok(ev) = dbg.continue_execution().await else { break };
        if ev.pid.0 != pid {
            continue;
        }
        match ev.reason {
            StopReason::Breakpoint { .. } => stops += 1,
            StopReason::ProcessExit { .. } => {
                let _ = dbg.kill().await;
                return stops;
            }
            _ => {}
        }
    }
    let _ = dbg.kill().await;
    panic!("the fixture never reached its exit within {budget} events");
}

/// `pgrep -x` on the STEM, never `pgrep -f`: `-f` matches cargo's own
/// `live_linux_devac_audit-<hash>` process and would report an orphan that is
/// this very test.
fn assert_no_orphans(stem: &str) {
    if let Ok(out) = std::process::Command::new("pgrep").arg("-x").arg(stem).output() {
        let listing = String::from_utf8_lossy(&out.stdout);
        let pids: Vec<&str> = listing.split_whitespace().collect();
        assert!(pids.is_empty(), "`{stem}` survived the test as pid(s) {pids:?}");
    }
}

// -- the oracle no symbol table can fake -------------------------------------

/// The program's own stdout separates the fixture from a version with the two
/// call sites exchanged — `7` against `11` — while `nm` and `objdump` describe both
/// binaries with equal and consistent confidence.
///
/// This is the observable neither de-vacuated file uses, and the only one that
/// survives a mutation of the PROGRAM rather than of the mapping. It costs one
/// `Command::output()` and no ptrace at all.
#[test]
fn the_programs_own_stdout_separates_the_fixture_from_a_call_site_swap() {
    let good = build(FIXTURE_C, "devacaudit");
    let bad = build(SWAPPED_C, "devacswap");
    let (g, b) = (stdout_of(&good.exe), stdout_of(&bad.exe));
    println!("[stdout-oracle] fixture={g} swapped={b}");
    assert_eq!(g, "7", "five calls to `hot` (+1) and one to `warm` (+2) must print 7");
    assert_eq!(b, "11", "with the call sites exchanged the same bodies print 11 (5*(+2) + (+1))");
    assert_ne!(g, b, "the stdout oracle does not separate the two programs, so it cannot bite");
}

/// The crossing triple `(5, 1, 0)` AND its falsification, in one test.
///
/// On the real binary it must be `(5, 1, 0)`; on the binary whose call sites
/// were exchanged it must NOT be, or the triple is a constant rather than a
/// measurement. The previous round asserted the triple; nothing asserted that a
/// wrong program produces a different one.
#[tokio::test]
async fn the_crossing_triple_is_reproduced_by_one_program_and_rejected_by_another() {
    let good = build(FIXTURE_C, "devacaudit");
    let mut got = Vec::new();
    for name in ["hot", "warm", "cold"] {
        got.push(crossings(&good.exe, nm_addr(&good.exe, name), 64).await);
    }
    println!("[triple] fixture (hot, warm, cold) = {got:?}");
    assert_eq!(got, vec![5, 1, 0], "the fixture does not cross its functions 5/1/0 times");

    let bad = build(SWAPPED_C, "devacswap");
    let mut got_bad = Vec::new();
    for name in ["hot", "warm", "cold"] {
        got_bad.push(crossings(&bad.exe, nm_addr(&bad.exe, name), 64).await);
    }
    println!("[triple] body-swapped (hot, warm, cold) = {got_bad:?}");
    assert_ne!(
        got_bad, got,
        "the triple is unchanged for a program whose calls were exchanged, so it pins nothing"
    );
    assert_eq!(
        got_bad,
        vec![1, 5, 0],
        "the swapped program must cross `hot` once and `warm` five times"
    );
    assert_no_orphans("devacaudit");
    assert_no_orphans("devacswap");
}

// -- the gap the audit found: nothing pinned the ENTRY -----------------------

/// The address under test must be the ENTRY of `hot`, not merely an address
/// inside it.
///
/// MEASURED: moving the address to `hot + 8` — still inside `hot`, still on an
/// instruction boundary, still crossed five times — and shifting the 32-byte
/// window to match left `live_linux_breakpoints.rs` at **21 passed / 0 failed**.
/// Neither oracle there can separate the two: the counts are identical by
/// construction, and the window travels with the address. Only an equality
/// against the entry the ELF publishes does.
///
/// The test also states the negative half, which is what gives the positive one
/// content: the pristine bytes at `hot + 8` must NOT equal the bytes at the
/// entry.
#[tokio::test]
async fn the_breakpoint_address_is_the_entry_of_hot_not_merely_inside_it() {
    let fx = build(FIXTURE_C, "devacaudit");
    let (od_entry, code) = objdump_entry(&fx.exe, "hot", 32);
    let entry = nm_addr(&fx.exe, "hot");
    assert_eq!(entry, od_entry, "`nm` and `objdump` disagree on where `hot` begins");

    let dbg = LinuxDebugger::new();
    dbg.launch(launch_opts(&fx.exe)).await.expect("launch");
    let at_entry = raw_bytes(&dbg, entry, code.len());
    let inside = raw_bytes(&dbg, entry + 8, code.len());
    println!("[entry] hot={entry:#x} first8={:02x?} at+8={:02x?}", &at_entry[..8], &inside[..8]);
    assert_eq!(at_entry, code, "the code loaded at {entry:#x} is not the body of `hot`");
    assert_ne!(
        inside, code,
        "the window at `hot + 8` equals the window at the entry, so no window comparison in this \
         crate can tell an entry from an address inside the same function"
    );
    let _ = dbg.kill().await;

    // And the crossing count cannot do it either — stated and measured, because
    // it is the reason this guard has to exist at all.
    let shifted = crossings(&fx.exe, entry + 8, 64).await;
    println!("[entry] crossings at hot+8 = {shifted}");
    assert_eq!(
        shifted, 5,
        "`hot + 8` is crossed {shifted} times instead of 5, so the count WOULD have caught the \
         shift and this guard would be redundant"
    );
    assert_no_orphans("devacaudit");
}

/// A software breakpoint must change exactly the byte it claims and nothing
/// around it.
///
/// Both de-vacuated files compare a window as wide as the trap. A plant that
/// wrote one byte too many would still restore correctly and pass every one of
/// those comparisons, while the tracee executes a mangled instruction in the
/// meantime. Here 32 bytes are snapshotted before the plant, and everything
/// past the trap must be byte-identical afterwards.
#[tokio::test]
async fn a_planted_trap_is_exactly_one_byte_wide() {
    let fx = build(FIXTURE_C, "devacaudit");
    let entry = nm_addr(&fx.exe, "hot");
    let dbg = LinuxDebugger::new();
    dbg.launch(launch_opts(&fx.exe)).await.expect("launch");

    #[cfg(target_arch = "x86_64")]
    let width = 1usize;
    #[cfg(target_arch = "aarch64")]
    let width = TRAP_WORD.len();

    let before = raw_bytes(&dbg, entry, 32);
    dbg.set_breakpoint(Address(entry), BreakpointKind::Software).await.expect("set_breakpoint");
    let after = raw_bytes(&dbg, entry, 32);
    println!("[width] before={:02x?} after={:02x?}", &before[..8], &after[..8]);

    #[cfg(target_arch = "x86_64")]
    assert_eq!(after[0], TRAP, "the planted byte is {:#04x}, not the host trap", after[0]);
    #[cfg(target_arch = "aarch64")]
    assert_eq!(&after[..width], &TRAP_WORD[..], "the planted word is not `BRK #0`");

    assert_ne!(before[..width], after[..width], "nothing was planted at all");
    assert_eq!(
        &after[width..],
        &before[width..],
        "the plant changed bytes BEYOND the trap: the tracee would execute a mangled instruction, \
         and every trap-wide comparison in this crate would still pass"
    );
    dbg.remove_breakpoint(Address(entry)).await.expect("remove_breakpoint");
    assert_eq!(
        raw_bytes(&dbg, entry, 32),
        before,
        "the restore is not byte-for-byte over the whole 32-byte window"
    );
    let _ = dbg.kill().await;
    assert_no_orphans("devacaudit");
}

/// DECLARED DEFECT of the de-vacuation round, kept red rather than repaired:
/// the backend is not touched here, and neither is the file that owns the test.
///
/// `a_thread_storm_does_not_disarm_the_planted_breakpoints` in
/// `live_linux_load.rs` puts both of its real assertions — the breakpoint count
/// and the trap window — inside `if alive`. When `alive` is false the test
/// passes having checked nothing, and reports the skip nowhere.
///
/// MEASURED: with that file's expected trap byte mutated to `0xCD`, the full
/// suite reported **8 passed / 1 failed** on one run and **7 passed / 2 failed**
/// on the next, same binary, same mutation. In the first run the body did not
/// execute. Run in isolation it fails every time:
/// `only 0 of 32 traps are still planted after the thread storm`.
///
/// The cure belongs to that file: record whether the branch ran, and fail when
/// it did not.
#[tokio::test]
#[ignore = "measured defect of live_linux_load.rs: the thread-storm assertions sit behind `if alive` and were skipped in 1 of 2 measured runs, with nothing reporting the skip"]
async fn the_thread_storm_assertions_run_unconditionally() {
    panic!("asserts a defect in another file's test; see the doc comment for the measured red");
}
