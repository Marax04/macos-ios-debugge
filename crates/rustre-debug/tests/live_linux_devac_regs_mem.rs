//! De-vacuation of `live_linux_regs_mem.rs` and `live_linux_expressions.rs`:
//! the same capabilities, re-asserted against an oracle the debugger does not
//! produce.
//!
//! ## Why the originals needed this
//!
//! The falsification campaign (STATUS.md, «LA FALSIFICAZIONE») measured 68 of
//! 211 live tests as biting. `live_linux_regs_mem.rs` scores 9 of 14 and
//! `live_linux_expressions.rs` 6 of 9 — the best two files of the survey — but
//! the tests that do bite mostly bite on the crate's *self-consistency*, not on
//! anything outside it. Three shapes recur:
//!
//! * **read-back of one's own write.** `write_memory` then `read_memory` at the
//!   same address proves the two agree; both could be reading a cache, a stale
//!   image, or the wrong process, and the pair would still match.
//! * **a partial read compared with a wider read of the same address.**
//!   `read_memory_returns_exactly_the_requested_length_for_partial_sizes`
//!   asserts `part == full[..size]` where `full` came from the same backend, the
//!   same call path, moments earlier. The content is never claimed to be
//!   anything in particular.
//! * **a register round trip.** `set_register` then `get_register` proves the
//!   backend remembers; it does not prove the value reached the thread, because
//!   nothing but the backend is ever asked.
//!
//! ## The oracle used here
//!
//! **The program says what it holds, and the debugger must read exactly that.**
//! The fixture fills its globals, a 32-byte blob and a stack local, then writes
//! its own addresses and values into a report file handed to it in `argv[1]`,
//! flushes and closes it, and only then calls `checkpoint()`, where the
//! breakpoint waits. Every number the tests below compare against was produced
//! by the tracee itself, before the debugger looked at anything.
//!
//! (The report goes to a file rather than to stdout only because
//! `OutputRedirect::stdout` is documented in `lib.rs` as a no-op on both
//! concrete backends — the child is spawned with inherited stdio. It is the
//! program's own output either way: nothing in this crate writes a byte of it.)
//!
//! And the loop is closed in the other direction too, which is the part a
//! read-back cannot do: [`a_write_to_a_global_is_observed_by_the_program_itself`]
//! and [`a_register_write_is_observed_by_the_program_itself`] change the tracee
//! while it is stopped, resume it to exit, and then read what the PROGRAM
//! reported afterwards. A write that never reached the process cannot forge
//! that line.
//!
//! ## These guards were falsified — including the oracle itself
//!
//! ⚠ The report and the memory are written by the SAME program, so mutating a
//! constant moves both sides at once and proves nothing — that is the trap this
//! oracle carries, and the reason the mutations below break the LINK between
//! what the program says and what it holds instead. Seven mutations, each run
//! against the whole file (11 tests, green at rest):
//!
//! | mutation | reds |
//! |---|---|
//! | the blob is FILLED with `i*7+3` and REPORTED as `i*7+4` | **3 / 11** |
//! | `g_a_addr` reports `&g_slot` instead of `&g_a` | 1 |
//! | `checkpoint` is CALLED with `arg1+1` while `arg1` is reported | 1 |
//! | every reported address is read at `+ 8` (test side) | **6 / 11** |
//! | `checkpoint` stores a constant instead of its first argument | 1 |
//! | `main` restores `g_slot` after the resume, before reporting it | 1 |
//! | the test writes into the local it calls untouched | 1 |
//!
//! Nine of the eleven bite under at least one. The two that do not are
//! declared rather than hidden: [`the_programs_report_is_regenerated_by_each_run`]
//! is a guard ON the oracle — it goes red when the report stops being rewritten,
//! which no mutation of the report's CONTENT can produce — and
//! [`zz_no_orphan_devac_fixture_survives`] is hygiene, and must not depend on
//! any value the fixture holds.
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::memory_search::{MemorySearch, SearchOptions, SearchPattern, search_target};
use rustre_debug::{BreakpointKind, Debugger, LaunchOptions, OutputRedirect, StopReason, ThreadId};
use std::collections::HashMap;

/// The fixture.
///
/// Everything it reports is written BEFORE `checkpoint()` is called, so the
/// file is complete and closed by the time the breakpoint fires. The three
/// `*_after` lines are appended after the resume: they are how the program
/// reports back what the debugger did to it while it was stopped.
const FIXTURE_C: &str = r#"
#include <stdio.h>

long g_a = 0x1122334455667788L;
unsigned char g_blob[32];
long g_slot = 0x1111111111111111L;
long g_seen = 0;

__attribute__((noinline)) void checkpoint(long a, long b) { g_seen = a ^ (b & 0); }

int main(int argc, char **argv) {
    volatile long loc = 0x0badc0de12345678L;
    FILE *f;
    int i;
    if (argc < 2) return 2;
    for (i = 0; i < 32; i++) g_blob[i] = (unsigned char)(i * 7 + 3);
    f = fopen(argv[1], "w");
    if (!f) return 3;
    fprintf(f, "g_a_addr %lx\n", (unsigned long)&g_a);
    fprintf(f, "g_a_val %lx\n", (unsigned long)g_a);
    fprintf(f, "blob_addr %lx\n", (unsigned long)&g_blob[0]);
    fprintf(f, "blob");
    for (i = 0; i < 32; i++) fprintf(f, " %02x", g_blob[i]);
    fprintf(f, "\n");
    fprintf(f, "slot_addr %lx\n", (unsigned long)&g_slot);
    fprintf(f, "slot_val %lx\n", (unsigned long)g_slot);
    fprintf(f, "loc_addr %lx\n", (unsigned long)&loc);
    fprintf(f, "loc_val %lx\n", (unsigned long)loc);
    fprintf(f, "arg1 %lx\n", 0x4142434445464748L);
    fprintf(f, "arg2 %lx\n", 0x0102030405060708L);
    fclose(f);

    checkpoint(0x4142434445464748L, 0x0102030405060708L);

    f = fopen(argv[1], "a");
    if (!f) return 4;
    fprintf(f, "seen_after %lx\n", (unsigned long)g_seen);
    fprintf(f, "slot_after %lx\n", (unsigned long)g_slot);
    fprintf(f, "loc_after %lx\n", (unsigned long)loc);
    fclose(f);
    return 0;
}
"#;

struct Fixture {
    _dir: tempfile::TempDir,
    exe: String,
    report: String,
}

fn build_fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("devacwf7.c");
    let exe = dir.path().join("devacwf7");
    let report = dir.path().join("report.txt");
    std::fs::write(&src, FIXTURE_C).expect("write fixture source");
    let out = std::process::Command::new("cc")
        .args(["-no-pie", "-O0", "-g"])
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .output()
        .expect("cc must be available to run the live de-vacuation guards");
    assert!(
        out.status.success(),
        "cc failed to build the fixture: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Fixture {
        exe: exe.to_string_lossy().into_owned(),
        report: report.to_string_lossy().into_owned(),
        _dir: dir,
    }
}

/// The address `nm` prints. `-no-pie`, so this IS the run-time address.
fn nm_address(exe: &str, want: &str) -> u64 {
    let out = std::process::Command::new("nm").arg(exe).output().expect("nm");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|line| {
            let mut it = line.split_whitespace();
            let addr = it.next()?;
            let _kind = it.next()?;
            if it.next()? == want { u64::from_str_radix(addr, 16).ok() } else { None }
        })
        .unwrap_or_else(|| panic!("the fixture must define `{want}`"))
}

/// What the PROGRAM said about itself. Nothing in this crate writes it.
#[derive(Debug, Default)]
struct Report(HashMap<String, String>);

impl Report {
    fn read(path: &str) -> Report {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("the fixture must have written {path}: {e}"));
        let mut m = HashMap::new();
        for line in text.lines() {
            if let Some((k, v)) = line.split_once(' ') {
                m.insert(k.to_string(), v.trim().to_string());
            }
        }
        Report(m)
    }
    fn hex(&self, key: &str) -> u64 {
        let raw = self
            .0
            .get(key)
            .unwrap_or_else(|| panic!("the program's report has no `{key}` line: {:?}", self.0));
        u64::from_str_radix(raw, 16).unwrap_or_else(|e| panic!("`{key}` = {raw:?} is not hex: {e}"))
    }
    /// The 32 bytes the program itself dumped.
    fn blob(&self) -> Vec<u8> {
        let raw = self.0.get("blob").expect("the report must carry the blob dump");
        let bytes: Vec<u8> = raw
            .split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).expect("hex byte"))
            .collect();
        assert_eq!(bytes.len(), 32, "the program dumped {} bytes, not 32", bytes.len());
        bytes
    }
}

fn launch_opts(fx: &Fixture) -> LaunchOptions {
    LaunchOptions {
        executable: fx.exe.clone(),
        args: vec![fx.report.clone()],
        env: std::collections::HashMap::new(),
        working_dir: None,
        stop_at_entry: false,
        follow_forks: false,
        redirect: OutputRedirect::default(),
    }
}

/// Launch the fixture, stop it at `checkpoint`, and hand back what the program
/// had already written about itself.
///
/// The stop is taken UNFILTERED — every breakpoint stop is accepted, whatever
/// its address — so nothing here closes a loop on the address it later asserts.
async fn stopped_at_checkpoint(fx: &Fixture) -> (LinuxDebugger, ThreadId, Report) {
    let dbg = LinuxDebugger::new();
    dbg.launch(launch_opts(fx)).await.expect("launch should succeed");
    let at = nm_address(&fx.exe, "checkpoint");
    dbg.set_breakpoint(Address(at), BreakpointKind::Software)
        .await
        .expect("set_breakpoint at `checkpoint`");
    let mut hit = false;
    for _ in 0..32 {
        match dbg.continue_execution().await {
            Ok(ev) => match ev.reason {
                StopReason::Breakpoint { .. } => {
                    hit = true;
                    break;
                }
                StopReason::ProcessExit { .. } => break,
                _ => {}
            },
            Err(_) => break,
        }
    }
    if !hit {
        let _ = dbg.kill().await;
        panic!("the fixture never reached `checkpoint`, so there is nothing to observe");
    }
    let tid = ThreadId(dbg.target_pid().expect("a live pid").0);
    let rep = Report::read(&fx.report);
    (dbg, tid, rep)
}

/// Resume to exit, then read everything the program had to say — including the
/// lines it appends AFTER the resume.
async fn resume_to_exit_and_reread(dbg: &LinuxDebugger, fx: &Fixture) -> Report {
    for _ in 0..32 {
        match dbg.continue_execution().await {
            Ok(ev) => {
                if matches!(ev.reason, StopReason::ProcessExit { .. }) {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = dbg.kill().await;
    // The `*_after` lines are appended by the tracee on its way out; give the
    // writer a moment on a loaded runner rather than racing it.
    for _ in 0..50 {
        let r = Report::read(&fx.report);
        if r.0.contains_key("slot_after") {
            return r;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Report::read(&fx.report)
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory reads — against what the program says it holds
// ─────────────────────────────────────────────────────────────────────────────

/// `read_memory` at the address the PROGRAM printed must return the value the
/// PROGRAM printed.
///
/// This is what `write_memory_is_visible_to_a_subsequent_read_memory` cannot
/// say: there, the debugger writes the bytes and then reads them back, so the
/// two halves agree by construction even if both are talking to the wrong
/// place. Here neither the address nor the value came from this crate.
#[tokio::test]
async fn a_global_reads_back_the_value_the_program_reported() {
    let fx = build_fixture();
    let (dbg, _tid, rep) = stopped_at_checkpoint(&fx).await;
    let addr = rep.hex("g_a_addr");
    let want = rep.hex("g_a_val");

    let bytes = dbg.read_memory(Address(addr), 8).await;
    let _ = dbg.kill().await;
    let bytes = bytes.expect("read_memory at the program's own `&g_a`");
    let got = u64::from_le_bytes(bytes[..8].try_into().unwrap());

    assert_eq!(
        got, want,
        "the program says `g_a` at {addr:#x} holds {want:#x}; the debugger read {got:#x}"
    );
    // And the address itself must be the one `nm` names, which is the second,
    // independent witness that `g_a_addr` really is `g_a`.
    let from_nm = nm_address(&fx.exe, "g_a");
    assert_eq!(
        addr, from_nm,
        "the program printed {addr:#x} for `&g_a` and `nm` puts it at {from_nm:#x}"
    );
}

/// The 32 bytes the program dumped must be the 32 bytes the debugger reads.
///
/// Thirty-two, not eight, and a per-index pattern rather than a constant: eight
/// shared bytes are what made the breakpoint round's first oracle vacuous
/// (STATUS.md, «DE-VACUAZIONE»), and a constant fill would be reproduced by any
/// zeroed or repeated page.
#[tokio::test]
async fn the_blob_reads_back_byte_for_byte_as_the_program_dumped_it() {
    let fx = build_fixture();
    let (dbg, _tid, rep) = stopped_at_checkpoint(&fx).await;
    let addr = rep.hex("blob_addr");
    let want = rep.blob();

    let got = dbg.read_memory(Address(addr), 32).await;
    let _ = dbg.kill().await;
    let got = got.expect("read_memory of the 32-byte blob");

    assert_eq!(got, want, "the program dumped {want:02x?} at {addr:#x}; the debugger read {got:02x?}");
    // Guard on the oracle: a constant or zeroed window would satisfy an
    // equality between two things that are both wrong in the same way.
    assert!(
        want.windows(2).any(|w| w[0] != w[1]),
        "the blob must not be uniform, or matching it proves nothing"
    );
}

/// Partial reads must be prefixes of what the PROGRAM dumped.
///
/// `read_memory_returns_exactly_the_requested_length_for_partial_sizes` asserts
/// `part == full[..size]` where `full` is another read by the same backend of
/// the same address — a self-comparison that holds for any content whatsoever,
/// zeroes included. The content is pinned here.
#[tokio::test]
async fn partial_reads_are_prefixes_of_the_programs_own_dump() {
    let fx = build_fixture();
    let (dbg, _tid, rep) = stopped_at_checkpoint(&fx).await;
    let addr = rep.hex("blob_addr");
    let want = rep.blob();

    let mut fail = None;
    for size in [1usize, 3, 5, 7, 8, 9, 15, 17, 32] {
        match dbg.read_memory(Address(addr), size).await {
            Ok(part) => {
                if part.len() != size {
                    fail = Some(format!("a {size}-byte read returned {} bytes", part.len()));
                    break;
                }
                if part[..] != want[..size] {
                    fail = Some(format!(
                        "a {size}-byte read returned {part:02x?}, the program dumped {:02x?}",
                        &want[..size]
                    ));
                    break;
                }
            }
            Err(e) => {
                fail = Some(format!("a {size}-byte read failed: {e}"));
                break;
            }
        }
    }
    let _ = dbg.kill().await;
    assert!(fail.is_none(), "{}", fail.unwrap_or_default());
}

/// A STACK local, at the address the program printed for it.
///
/// The existing suite pokes the stack at `sp - 512` — mapped, but nothing in
/// particular. Here the address is the one the program took of its own
/// variable, and the value is the one it says it put there.
#[tokio::test]
async fn a_stack_local_reads_back_the_value_the_program_reported() {
    let fx = build_fixture();
    let (dbg, tid, rep) = stopped_at_checkpoint(&fx).await;
    let addr = rep.hex("loc_addr");
    let want = rep.hex("loc_val");
    let sp = dbg.get_registers(tid).await.map(|r| r.sp);

    let bytes = dbg.read_memory(Address(addr), 8).await;
    let _ = dbg.kill().await;
    let got = u64::from_le_bytes(bytes.expect("read the local")[..8].try_into().unwrap());

    assert_eq!(
        got, want,
        "the program says its local at {addr:#x} holds {want:#x}; the debugger read {got:#x}"
    );
    // The local must really be on the stack of the stopped thread: an address
    // that happened to hold the right pattern elsewhere would not be.
    let sp = sp.expect("get_registers at the stop");
    assert!(
        addr > sp && addr < sp + 0x10000,
        "the reported local {addr:#x} is not in the stopped thread's frame (sp = {sp:#x})"
    );
}

/// `memory_search` must find the blob at the address the program printed.
///
/// `memory_search_finds_a_needle_just_written_into_the_live_target` plants the
/// needle with `write_memory` and then searches for it, so the search is
/// confirming this crate's own write. The needle here is the program's, and so
/// is the address the hit is checked against.
#[tokio::test]
async fn memory_search_finds_the_programs_blob_at_the_address_it_reported() {
    let fx = build_fixture();
    let (dbg, _tid, rep) = stopped_at_checkpoint(&fx).await;
    let addr = rep.hex("blob_addr");
    let needle = rep.blob();

    let engine = MemorySearch::new(SearchOptions::default().with_max_results(64));
    let pattern = SearchPattern::bytes(needle.clone()).expect("pattern");
    let report = search_target(&engine, &dbg, &pattern).await;
    let _ = dbg.kill().await;
    let report = report.expect("search_target over the live target");

    assert!(
        report.results.iter().any(|r| r.address == addr),
        "the scan must report the program's own blob at {addr:#x}; got {} hits at {:x?}, \
         regions_searched={}, unreadable={}",
        report.results.len(),
        report.results.iter().map(|r| r.address).collect::<Vec<_>>(),
        report.regions_searched,
        report.regions_unreadable
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Registers — against what the program says it passed
// ─────────────────────────────────────────────────────────────────────────────

/// The argument registers at `checkpoint`'s entry must hold the values the
/// program says it passed.
///
/// `get_registers_returns_a_coherent_live_register_file` asserts only that `pc`
/// and `sp` are non-zero and that two views of the crate's own structure agree.
/// Neither statement is about the program being debugged. `rdi`/`rsi` here are
/// two 64-bit patterns the program named in writing.
#[tokio::test]
async fn the_argument_registers_hold_what_the_program_says_it_passed() {
    let fx = build_fixture();
    let (dbg, tid, rep) = stopped_at_checkpoint(&fx).await;
    let regs = dbg.get_registers(tid).await;
    let rdi_one = dbg.get_register(tid, "rdi").await;
    let pc = regs.as_ref().ok().map(|r| r.pc);
    let _ = dbg.kill().await;

    let regs = regs.expect("get_registers at the stop");
    assert_eq!(
        regs.get("rdi"),
        Some(rep.hex("arg1")),
        "the program passed {:#x} in the first argument register; the debugger reads {:x?}",
        rep.hex("arg1"),
        regs.get("rdi")
    );
    assert_eq!(
        regs.get("rsi"),
        Some(rep.hex("arg2")),
        "the program passed {:#x} in the second argument register; the debugger reads {:x?}",
        rep.hex("arg2"),
        regs.get("rsi")
    );
    // The single-register path must answer the same as the whole-file path —
    // and both are now anchored outside the crate, not merely to each other.
    assert_eq!(
        rdi_one.ok(),
        Some(rep.hex("arg1")),
        "`get_register(\"rdi\")` disagrees with the value the program passed"
    );
    // And the stop really is at `checkpoint`, per `nm`.
    let want_pc = nm_address(&fx.exe, "checkpoint");
    assert_eq!(pc, Some(want_pc), "the stop is not at `checkpoint` ({want_pc:#x})");
}

// ─────────────────────────────────────────────────────────────────────────────
// Writes — closed through the program's own output
// ─────────────────────────────────────────────────────────────────────────────

/// A `write_memory` into a global must be observed BY THE PROGRAM.
///
/// This is the direction a read-back cannot cover. The debugger overwrites
/// `g_slot` while the tracee is stopped, the tracee is resumed, and the tracee
/// then prints `g_slot` itself. Only a write that actually reached the process
/// can put that number in the file, and the debugger writes no part of the file.
#[tokio::test]
async fn a_write_to_a_global_is_observed_by_the_program_itself() {
    let fx = build_fixture();
    let (dbg, _tid, rep) = stopped_at_checkpoint(&fx).await;
    let slot = rep.hex("slot_addr");
    let before = rep.hex("slot_val");
    let planted: u64 = 0xfeed_face_dead_beef;
    assert_ne!(planted, before, "the plant must differ from what the program already held");

    dbg.write_memory(Address(slot), &planted.to_le_bytes()).await.expect("write_memory to g_slot");
    let after = resume_to_exit_and_reread(&dbg, &fx).await;

    assert_eq!(
        after.hex("slot_after"),
        planted,
        "the program reports `g_slot` = {:#x} after the resume; the debugger wrote {planted:#x} \
         into {slot:#x}, so the write never reached the process",
        after.hex("slot_after")
    );
}

/// A `set_register` must be observed BY THE PROGRAM.
///
/// `set_register_then_get_register_round_trips_a_scratch_register` asks the
/// backend what it just told the backend. Here the debugger changes `rdi` at
/// `checkpoint`'s entry — before the `-O0` prologue spills it — and the program
/// stores that argument into `g_seen` and prints it on its way out. The number
/// in the file is the program's own, and it can only be the planted one if the
/// write landed on the thread.
#[tokio::test]
async fn a_register_write_is_observed_by_the_program_itself() {
    let fx = build_fixture();
    let (dbg, tid, rep) = stopped_at_checkpoint(&fx).await;
    let passed = rep.hex("arg1");
    let planted: u64 = 0x0f1e_2d3c_4b5a_6978;
    assert_ne!(planted, passed, "the plant must differ from the argument the program passed");

    dbg.set_register(tid, "rdi", planted).await.expect("set_register(rdi)");
    let after = resume_to_exit_and_reread(&dbg, &fx).await;

    assert_eq!(
        after.hex("seen_after"),
        planted,
        "the program stored {:#x} from its first argument; the debugger had set rdi to \
         {planted:#x} (it was {passed:#x}), so the register write never reached the thread",
        after.hex("seen_after")
    );
}

/// The debugger must not disturb what it did NOT write.
///
/// The two tests above prove a write lands; this one proves the rest of the
/// process is intact afterwards, judged by the program rather than by a second
/// read. `loc` is never touched, and the program prints it again after the
/// resume: it must still be the value it reported before the stop.
#[tokio::test]
async fn stopping_and_resuming_leaves_untouched_state_as_the_program_left_it() {
    let fx = build_fixture();
    let (dbg, _tid, rep) = stopped_at_checkpoint(&fx).await;
    let before = rep.hex("loc_val");
    let after = resume_to_exit_and_reread(&dbg, &fx).await;

    assert_eq!(
        after.hex("loc_after"),
        before,
        "the program's untouched local read {before:#x} before the stop and {:#x} after it",
        after.hex("loc_after")
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// The oracle, guarded
// ─────────────────────────────────────────────────────────────────────────────

/// The report must describe THIS run, not a stale file or a constant.
///
/// The stack local's address is randomised by ASLR, so two runs of the same
/// binary print different `loc_addr` values. If they do not, the report is not
/// being regenerated and every test above is comparing against a fossil.
#[tokio::test]
async fn the_programs_report_is_regenerated_by_each_run() {
    let fx = build_fixture();
    let (dbg1, _t1, r1) = stopped_at_checkpoint(&fx).await;
    let _ = dbg1.kill().await;
    let (dbg2, _t2, r2) = stopped_at_checkpoint(&fx).await;
    let _ = dbg2.kill().await;

    assert_eq!(r1.hex("g_a_addr"), r2.hex("g_a_addr"), "a -no-pie global must not move");
    assert_ne!(
        r1.hex("loc_addr"),
        r2.hex("loc_addr"),
        "two runs reported the same stack address {:#x}; either ASLR is off on this runner or \
         the report file is not being rewritten — in the second case every comparison in this \
         file is against a fossil",
        r1.hex("loc_addr")
    );
}

/// No fixture process may outlive this suite.
///
/// `-x` matches the process NAME exactly. `-f` was measured to be wrong for
/// this job in the falsification round: it matches cargo's own
/// `live_linux_devac_regs_mem-<hash>` binary, so the check would report an
/// orphan that is the very process looking for one.
#[tokio::test]
async fn zz_no_orphan_devac_fixture_survives() {
    let Ok(out) = std::process::Command::new("pgrep").args(["-x", "devacwf7"]).output() else {
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
        "the suite left {} `devacwf7` process(es) behind: {listed:?}",
        listed.len()
    );
}
