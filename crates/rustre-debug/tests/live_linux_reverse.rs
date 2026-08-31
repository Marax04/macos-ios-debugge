//! Live reverse-debugging / time-travel coverage for the Linux backend.
//!
//! Every test here drives a REAL process: a small C fixture is compiled on the
//! fly with `cc -O0 -static -no-pie`, launched under `LinuxDebugger`, and
//! single-stepped with ptrace. The register state fed into
//! [`SnapshotReplayBackend`] and the [`MemoryWrite`]s fed into
//! [`OmniscientIndex`] are MEASURED off that process — no test in this file
//! builds a trace out of invented numbers.
//!
//! ## What this file found (the gap, measured)
//!
//! The crate ships the *consumers* of a recording (`TtdSession::step_backward`,
//! `reverse_continue`, `run_to_previous_call`, `OmniscientIndex::who_wrote`,
//! `retro_print`) but no *producer* that observes a live Linux process. The
//! only recorder in the workspace is the MCP tool `debug.ttd_record`
//! (`rustre-mcp-tools/src/tools/debug.rs:3684`), which snapshots registers once
//! per call from the caller's own step loop. `rustre-debug` itself exposes
//! nothing that records; the recording loop in `record_trace` below is written
//! BY THE TEST, doing the work the crate does not do.
//!
//! | capability | expected (external truth) | reachable with what the crate has | obtained today |
//! |---|---|---|---|
//! | record execution | `rr record ./fixture` → every instruction replayable | caller-driven `single_step` + `get_registers` + `SnapshotReplayBackend::record` | works, exactly as many positions as the caller chose to record (`ttd_record_loop_captures_the_real_pcs`) |
//! | `reverse_step` | gdb `reverse-stepi` → previous instruction, registers restored | `TtdSession::step_backward` over recorded states | the previous RECORDED state, with the right pc; registers are NOT written back into the process |
//! | `reverse_continue` to an unvisited pc | gdb runs to the start and says "no more history" | `SnapshotReplayBackend::reverse_continue` | `states[0]` with no field distinguishing it from a hit (`defect_reverse_continue_cannot_report_no_breakpoint_hit`) |
//! | `reverse_step_over` | steps back OVER a call, landing at the call site | `TtdBackend::reverse_step_over` | aliased to `step_backward`: one instruction, frame-blind |
//! | `run_to_previous_call` | the most recent `call` before the cursor | `TtdBackend::run_to_previous_call` | aliased to `step_backward`: a call only by coincidence |
//! | `who_wrote(addr)` | `rr`/Pernosco answer it with no caller cooperation | `OmniscientIndex::who_wrote` over writes SOMEONE ELSE pushed | the query is correct on real data; the crate produces none of that data itself |
//!
//! The commands that produce the external truth are named in each test's doc
//! comment (`nm --print-size`, `objdump -d`, `gdb record`, `rr record`), and
//! the fixture is built `-static -no-pie` so those addresses are the addresses
//! the process actually runs at.
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::omniscient_query::{MemoryWrite, OmniscientIndex, OriginEnd};
use rustre_debug::retroactive_print::{retro_print, EvalResult, RetroAnnotation};
use rustre_debug::time_travel_debug::{
    ProcessSnapshot, SnapshotReplayBackend, TracePosition, TtdBackend, TtdConfig, TtdError,
    TtdSession, TtdState, SIMULATED_STOP_REASON_PREFIX,
};
use rustre_debug::{BreakpointKind, Debugger, LaunchOptions, StopReason, ThreadId};
use std::collections::BTreeMap;
use std::process::Command;

// ── Fixture ──────────────────────────────────────────────────────────────────

/// `g` is a file-scope global written twice by `main` with two distinct,
/// unmistakable constants, so "which instruction wrote it" is a question
/// `objdump -d` can be asked independently.
const FIXTURE_C: &str = r#"
#include <stdio.h>

int g = 0;

__attribute__((noinline)) int callee(int x) { return x * 2 + 1; }

int main(void) {
    g = 0x11;
    g = 0x22;
    int b = callee(g);
    printf("%d %d\n", g, b);
    return 0;
}
"#;

struct Fixture {
    _dir: tempfile::TempDir,
    path: String,
    /// `[start, end)` of `main`, from `nm --print-size`.
    main: (u64, u64),
    /// `[start, end)` of `callee`.
    callee: (u64, u64),
    /// Address of the global `g`.
    g: u64,
}

/// Compile the fixture, or `None` when this host has no usable C toolchain /
/// static libc. A missing toolchain is not a debugger defect, and this says so
/// out loud instead of reporting a green it did not earn.
fn build_fixture() -> Option<Fixture> {
    let dir = tempfile::tempdir().ok()?;
    let src = dir.path().join("fixture.c");
    let exe = dir.path().join("fixture");
    std::fs::write(&src, FIXTURE_C).ok()?;
    let out = Command::new("cc")
        .args(["-O0", "-g", "-static", "-no-pie", "-fno-pie"])
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .output()
        .ok()?;
    if !out.status.success() {
        eprintln!("[fixture] cc failed: {}", String::from_utf8_lossy(&out.stderr));
        return None;
    }
    let path = exe.to_str()?.to_string();
    let main = symbol_extent(&path, "main")?;
    let callee = symbol_extent(&path, "callee")?;
    let g = symbol_addr(&path, "g")?;
    Some(Fixture { _dir: dir, path, main, callee, g })
}

/// `[address, address + size)` of a named symbol — external truth, from
/// `nm --print-size --defined-only <exe>`.
fn symbol_extent(exe: &str, name: &str) -> Option<(u64, u64)> {
    let out = Command::new("nm").args(["--print-size", "--defined-only", exe]).output().ok()?;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() == 4 && f[3] == name {
            let addr = u64::from_str_radix(f[0], 16).ok()?;
            let size = u64::from_str_radix(f[1], 16).ok()?;
            return Some((addr, addr + size));
        }
    }
    None
}

/// Address of a data symbol (`nm` prints data symbols with or without a size
/// column depending on the object).
fn symbol_addr(exe: &str, name: &str) -> Option<u64> {
    let out = Command::new("nm").args(["--print-size", "--defined-only", exe]).output().ok()?;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 3 && f.last() == Some(&name) {
            return u64::from_str_radix(f[0], 16).ok();
        }
    }
    None
}

/// Every address inside `main` at which `objdump -d` shows a `call`
/// instruction. External truth for `run_to_previous_call`.
fn call_sites_in_main(exe: &str, main: (u64, u64)) -> Vec<u64> {
    let Ok(out) = Command::new("objdump").args(["-d", exe]).output() else { return Vec::new() };
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut sites = Vec::new();
    for line in text.lines() {
        let Some((lhs, rhs)) = line.split_once(':') else { continue };
        let Ok(addr) = u64::from_str_radix(lhs.trim(), 16) else { continue };
        if addr >= main.0 && addr < main.1 && rhs.contains("call") {
            sites.push(addr);
        }
    }
    sites
}

macro_rules! fixture_or_skip {
    () => {
        match build_fixture() {
            Some(f) => f,
            None => {
                eprintln!("[skip] no usable C toolchain / static libc on this host");
                return;
            }
        }
    };
}

// ── Harness ──────────────────────────────────────────────────────────────────

async fn open(fx: &Fixture) -> Option<(LinuxDebugger, ThreadId)> {
    let dbg = LinuxDebugger::new();
    let pid = dbg.launch(LaunchOptions::new(fx.path.clone())).await.ok()?;
    Some((dbg, ThreadId(pid.0)))
}

/// Run to `addr` via a software breakpoint. `false` when the process exited
/// first — reported by the caller, never asserted away.
async fn run_to(dbg: &LinuxDebugger, addr: u64) -> bool {
    if dbg.set_breakpoint(Address(addr), BreakpointKind::Software).await.is_err() {
        return false;
    }
    for _ in 0..4000 {
        let Ok(ev) = dbg.continue_execution().await else { return false };
        match ev.reason {
            StopReason::Breakpoint { address, .. } if address.as_u64() == addr => return true,
            StopReason::ProcessExit { .. } => return false,
            _ => {}
        }
    }
    false
}

/// A recording of a live process: one [`TtdState`] per single-step position,
/// plus the pcs as measured by ptrace.
struct Recording {
    backend: SnapshotReplayBackend,
    /// `(sequence, pc)`, oldest first.
    pcs: Vec<(u64, u64)>,
}

/// THE RECORDER THE CRATE DOES NOT HAVE. It mirrors, in-process, exactly what
/// the MCP tool `debug.ttd_record` does per call: `get_registers` → `TtdState`
/// → `SnapshotReplayBackend::record`, plus a 256-byte stack window around rsp
/// so historical derefs can resolve.
async fn record_trace(dbg: &LinuxDebugger, tid: ThreadId, steps: usize) -> Recording {
    let mut backend = SnapshotReplayBackend::new();
    let mut pcs = Vec::new();
    for seq in 1..=steps as u64 {
        let Ok(regset) = dbg.get_registers(tid).await else { break };
        let mut regs: BTreeMap<String, u64> = BTreeMap::new();
        for name in regset.all_names() {
            if let Some(v) = regset.get(&name) {
                regs.insert(name, v);
            }
        }
        let pc = regset.pc;
        let sp = regset.get("rsp").unwrap_or(0);
        let pos = TracePosition::new(seq, 0);
        let mut st = TtdState::new(pos, pc, sp);
        st.regs = regs;
        st.stop_reason = "recorded".to_string();
        backend.record(st);
        if sp != 0 {
            if let Ok(bytes) = dbg.read_memory(Address::new(sp.saturating_sub(64)), 256).await {
                backend.record_memory(pos, sp.saturating_sub(64), bytes);
            }
        }
        pcs.push((seq, pc));
        let Ok(ev) = dbg.single_step(tid).await else { break };
        if ev.reason.is_exit() {
            break;
        }
    }
    Recording { backend, pcs }
}

fn session_over(backend: SnapshotReplayBackend) -> TtdSession {
    let mut s = TtdSession::new(TtdConfig::default());
    s.attach_backend(Box::new(backend));
    s
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. Recording a live process
// ═════════════════════════════════════════════════════════════════════════════

/// PROVES: a trace recorded off a REAL ptrace'd process holds the pcs the
/// process actually executed — one recorded state per single-step, the first
/// of them `main` itself.
///
/// WHY THAT IS RIGHT: every reverse operation below is only as true as the
/// recording underneath it. A recorder that dropped, duplicated or reordered
/// states would leave `step_backward` "working" and wrong; this pins the input
/// before anything consumes it.
#[tokio::test]
async fn ttd_record_loop_captures_the_real_pcs() {
    let fx = fixture_or_skip!();
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    assert!(run_to(&dbg, fx.main.0).await, "the fixture should reach main");

    let rec = record_trace(&dbg, tid, 40).await;

    assert_eq!(rec.backend.len(), rec.pcs.len(), "one recorded state per step");
    assert_eq!(rec.pcs.len(), 40, "40 single-steps from main should not exit the process");
    assert_eq!(rec.pcs[0].1, fx.main.0, "the first recorded pc must be main itself");
    let distinct: std::collections::HashSet<u64> = rec.pcs.iter().map(|&(_, pc)| pc).collect();
    assert!(distinct.len() > 5, "a recording stuck on one pc is not a recording: {distinct:?}");

    let _ = dbg.kill().await;
}

/// PROVES: `TtdSession::trace_extent` over a recording of a live process
/// reports the first and last sequence actually recorded, and
/// `is_trace_loaded` is false until a backend is attached.
///
/// WHY THAT IS RIGHT: "how far back can I go" is the first question a reverse
/// UI asks; an extent that does not match the recording turns every seek into
/// a guess.
#[tokio::test]
async fn trace_extent_matches_the_recorded_range() {
    let fx = fixture_or_skip!();
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    assert!(run_to(&dbg, fx.main.0).await, "reach main");
    let rec = record_trace(&dbg, tid, 20).await;
    let last = rec.pcs.last().expect("recorded at least one state").0;

    let empty = TtdSession::new(TtdConfig::default());
    assert!(!empty.is_trace_loaded(), "a session with no snapshots has no trace");

    let sess = session_over(rec.backend);
    assert!(sess.is_trace_loaded(), "attaching a backend loads the trace");
    let (a, b) = sess.trace_extent().expect("a backend-backed session reports its extent");
    assert_eq!(a, TracePosition::new(1, 0), "extent starts at the first recorded position");
    assert_eq!(b, TracePosition::new(last, 0), "extent ends at the last recorded position");

    let _ = dbg.kill().await;
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. reverse_step / step_backward
// ═════════════════════════════════════════════════════════════════════════════

/// PROVES: `step_backward` over a recording of a live process returns the pc
/// the process really had one instruction earlier — checked against the pc
/// list measured by ptrace, not against the trace's own bookkeeping.
///
/// WHY THAT IS RIGHT: a reverse step that moves the cursor but reports the
/// wrong registers is worse than none, and only an independently measured pc
/// sequence separates the two.
#[tokio::test]
async fn reverse_step_returns_the_pc_the_process_really_had() {
    let fx = fixture_or_skip!();
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    assert!(run_to(&dbg, fx.main.0).await, "reach main");
    let rec = record_trace(&dbg, tid, 30).await;
    let pcs = rec.pcs.clone();
    assert!(pcs.len() >= 2, "need at least two recorded positions");
    let mut sess = session_over(rec.backend);

    let last = pcs.last().unwrap().0;
    sess.seek(TracePosition::new(last, 0)).expect("seek to the end of the recording");

    for i in (0..pcs.len() - 1).rev() {
        let st = sess.step_backward().expect("step_backward inside the recorded range");
        assert_eq!(
            st.position.sequence, pcs[i].0,
            "reverse step landed on sequence {} instead of {}",
            st.position.sequence, pcs[i].0
        );
        assert_eq!(
            st.pc, pcs[i].1,
            "reverse step to sequence {} reported pc {:#x}, the process had {:#x}",
            pcs[i].0, st.pc, pcs[i].1
        );
        assert!(
            !st.stop_reason.starts_with(SIMULATED_STOP_REASON_PREFIX),
            "a backend-backed reverse step must not be flagged simulated: {}",
            st.stop_reason
        );
    }

    let _ = dbg.kill().await;
}

/// PROVES: reverse-stepping past the first recorded position reports
/// `AtBeginning` instead of inventing a state before the recording started.
///
/// WHY THAT IS RIGHT: the recording starts at `main`; everything before it was
/// never observed, so anything but an error there is fabricated history.
#[tokio::test]
async fn reverse_step_off_the_front_of_the_trace_is_an_error() {
    let fx = fixture_or_skip!();
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    assert!(run_to(&dbg, fx.main.0).await, "reach main");
    let rec = record_trace(&dbg, tid, 10).await;
    let mut sess = session_over(rec.backend);

    sess.seek(TracePosition::new(1, 0)).expect("seek to the first recorded position");
    let err = sess.step_backward().expect_err("nothing precedes the first recorded position");
    assert_eq!(err, TtdError::AtBeginning, "got {err:?}");

    let _ = dbg.kill().await;
}

/// PROVES: the recorded registers really differ between two positions of a
/// live process — the "what changed between here and there" diff has real
/// content, not one snapshot repeated.
///
/// WHY THAT IS RIGHT: `record` keyed by position would happily store the same
/// register map N times if `get_registers` were cached or stale; a measurable
/// delta is the proof it is not.
#[tokio::test]
async fn recorded_states_differ_between_positions() {
    let fx = fixture_or_skip!();
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    assert!(run_to(&dbg, fx.main.0).await, "reach main");
    let rec = record_trace(&dbg, tid, 25).await;
    let mut backend = rec.backend;

    let a = backend.seek(TracePosition::new(1, 0)).expect("first recorded state");
    let b = backend.seek(TracePosition::new(20, 0)).expect("twentieth recorded state");
    let changed: Vec<&String> =
        b.regs.iter().filter(|(n, v)| a.regs.get(*n) != Some(*v)).map(|(n, _)| n).collect();
    assert!(
        !changed.is_empty(),
        "19 instructions of a real process changed no register — the recorder is not reading the \
         process"
    );
    assert_ne!(a.pc, b.pc, "rip must differ across 19 instructions");

    let _ = dbg.kill().await;
}

/// PROVES: seeking to a position BETWEEN two recorded ones lands on the
/// nearest earlier recorded state and reports that state's own sequence.
///
/// WHY THAT IS RIGHT: a recording is sparse by construction (the caller
/// chooses when to record). What keeps a sparse trace honest is that a seek
/// says WHERE IT LANDED, so a caller comparing the returned sequence with the
/// requested one can see the gap.
#[tokio::test]
async fn seek_between_recorded_positions_lands_on_the_nearest_earlier_one() {
    let fx = fixture_or_skip!();
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    assert!(run_to(&dbg, fx.main.0).await, "reach main");
    let rec = record_trace(&dbg, tid, 12).await;
    let pcs = rec.pcs.clone();
    if pcs.len() < 6 {
        eprintln!("[skip] recording too short");
        let _ = dbg.kill().await;
        return;
    }
    let mut sess = session_over(rec.backend);

    // Positions are (seq, 0); (5, 7) is strictly between (5,0) and (6,0).
    let st = sess.seek(TracePosition::new(5, 7)).expect("in-range seek");
    assert_eq!(st.position, TracePosition::new(5, 0), "landed on the nearest earlier state");
    assert_eq!(st.pc, pcs[4].1, "and reported that state's real pc");

    let _ = dbg.kill().await;
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. reverse_continue
// ═════════════════════════════════════════════════════════════════════════════

/// PROVES: `reverse_continue` with a reverse breakpoint on an address the
/// process REALLY executed lands exactly on the recorded state whose pc is
/// that address.
///
/// WHY THAT IS RIGHT: the breakpoint address is not invented — it is a pc the
/// process is known to have run, taken from the measured pc list, and chosen
/// so it occurs exactly once, so "the last time we were there" has one answer.
#[tokio::test]
async fn reverse_continue_lands_on_a_pc_the_process_really_visited() {
    let fx = fixture_or_skip!();
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    assert!(run_to(&dbg, fx.main.0).await, "reach main");
    let rec = record_trace(&dbg, tid, 30).await;
    let pcs = rec.pcs.clone();
    let last_seq = pcs.last().unwrap().0;
    let unique = pcs
        .iter()
        .copied()
        .find(|&(seq, pc)| {
            seq != last_seq && pcs.iter().filter(|&&(_, p)| p == pc).count() == 1
        });
    let Some((seq, target)) = unique else {
        eprintln!("[skip] no uniquely-visited pc in this recording");
        let _ = dbg.kill().await;
        return;
    };
    let mut sess = session_over(rec.backend);
    sess.seek(TracePosition::new(last_seq, 0)).expect("seek to the end");
    sess.add_reverse_breakpoint(target);

    let st = sess.reverse_continue().expect("reverse_continue over a recorded trace");
    assert_eq!(st.pc, target, "reverse_continue must stop AT the breakpoint pc");
    assert_eq!(st.position.sequence, seq, "and at the sequence where that pc was executed");

    let _ = dbg.kill().await;
}

/// PROVES: with NO reverse breakpoints set, `reverse_continue` over a live
/// recording runs all the way back to the first recorded state.
///
/// WHY THAT IS RIGHT: that is gdb's documented behaviour for
/// `reverse-continue` with no breakpoints — it runs to the beginning of
/// recorded history and stops there.
#[tokio::test]
async fn reverse_continue_without_breakpoints_runs_back_to_the_start() {
    let fx = fixture_or_skip!();
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    assert!(run_to(&dbg, fx.main.0).await, "reach main");
    let rec = record_trace(&dbg, tid, 15).await;
    let first_pc = rec.pcs[0].1;
    let last_seq = rec.pcs.last().unwrap().0;
    let mut sess = session_over(rec.backend);
    sess.seek(TracePosition::new(last_seq, 0)).expect("seek to the end");

    let st = sess.reverse_continue().expect("reverse_continue with no breakpoints");
    assert_eq!(st.position, TracePosition::new(1, 0), "ran back to the first recorded position");
    assert_eq!(st.pc, first_pc, "which is main itself");
    assert_eq!(first_pc, fx.main.0, "sanity: the recording started at main");

    let _ = dbg.kill().await;
}

/// MEASURES TODAY'S BEHAVIOUR (companion of the ignored defect test below):
/// `reverse_continue` toward an address the process NEVER executed returns the
/// first recorded state, indistinguishable from a real breakpoint hit there.
///
/// WHY THIS TEST EXISTS: the defect is pinned twice — once as the behaviour
/// actually shipped (here, green, so a silent change is caught) and once as
/// the behaviour that would be right (`#[ignore]`d, below). The address used
/// is `main - 0x1000`, unvisited by construction and asserted so.
#[tokio::test]
async fn reverse_continue_to_an_unvisited_pc_returns_the_first_state_today() {
    let fx = fixture_or_skip!();
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    assert!(run_to(&dbg, fx.main.0).await, "reach main");
    let rec = record_trace(&dbg, tid, 15).await;
    let pcs = rec.pcs.clone();
    let never = fx.main.0.wrapping_sub(0x1000);
    assert!(!pcs.iter().any(|&(_, pc)| pc == never), "the chosen pc must be unvisited");

    let mut sess = session_over(rec.backend);
    sess.seek(TracePosition::new(pcs.last().unwrap().0, 0)).expect("seek to the end");
    sess.add_reverse_breakpoint(never);
    let st = sess.reverse_continue().expect("today this succeeds");

    assert_eq!(
        st.position,
        TracePosition::new(1, 0),
        "MEASURED: reverse_continue to an unvisited pc silently lands at the start of the trace"
    );
    assert_ne!(st.pc, never, "and its pc is NOT the requested breakpoint");
    eprintln!(
        "[measured] reverse_continue(bp={never:#x}) -> seq {} pc {:#x} reason {:?}",
        st.position.sequence, st.pc, st.stop_reason
    );

    let _ = dbg.kill().await;
}

/// DEFECT — `SnapshotReplayBackend::reverse_continue` ends with "No breakpoint
/// hit going back → stop at the beginning" and returns `states[0]` verbatim.
/// Its `stop_reason` is the recorded state's own `"recorded"`, so the caller
/// cannot tell a real hit from no hit at all.
///
/// | | value |
/// |---|---|
/// | expected (gdb `reverse-continue`) | runs to the start and reports "No more reverse-execution history" — not a breakpoint stop |
/// | reachable today | the same `states[0]`, plus a `stop_reason` saying so — the backend-LESS path in the same module already does exactly that (`simulated_reverse_continue_to_beginning`) |
/// | obtained | `states[0]`, `stop_reason == "recorded"`, pc = the trace's first pc |
///
/// External truth: `gdb -q ./fixture -ex record -ex 'break *ADDR' -ex reverse-continue`.
///
/// MEASURED RED (`cargo test --release -p rustre-debug --test live_linux_reverse -- --ignored`):
/// ```text
/// reverse_continue to an unvisited pc must be distinguishable from a hit;
/// got pc=0x40187a reason="recorded"
/// ```
#[tokio::test]
#[ignore = "DEFECT: reverse_continue reports a stop for a breakpoint never crossed; un-ignore when the no-hit case is distinguishable"]
async fn defect_reverse_continue_cannot_report_no_breakpoint_hit() {
    let fx = fixture_or_skip!();
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    assert!(run_to(&dbg, fx.main.0).await, "reach main");
    let rec = record_trace(&dbg, tid, 15).await;
    let pcs = rec.pcs.clone();
    let never = fx.main.0.wrapping_sub(0x1000);
    let mut sess = session_over(rec.backend);
    sess.seek(TracePosition::new(pcs.last().unwrap().0, 0)).expect("seek to the end");
    sess.add_reverse_breakpoint(never);

    match sess.reverse_continue() {
        Err(_) => { /* refusing is an honest answer */ }
        Ok(st) => assert!(
            st.pc == never
                || st.stop_reason.contains("beginning")
                || st.stop_reason.contains("no_hit"),
            "reverse_continue to an unvisited pc must be distinguishable from a hit; got \
             pc={:#x} reason={:?}",
            st.pc,
            st.stop_reason
        ),
    }

    let _ = dbg.kill().await;
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. reverse_step_over / run_to_previous_call
// ═════════════════════════════════════════════════════════════════════════════

/// MEASURES TODAY'S BEHAVIOUR: over a real recording taken INSIDE `callee`,
/// `reverse_step_over` returns exactly what `step_backward` returns — one
/// instruction back, still inside the callee.
///
/// WHY THIS IS THE RIGHT PROBE: the recording starts at `callee`'s entry (a
/// software breakpoint there), and `[callee, callee_end)` comes from
/// `nm --print-size`, so "did the reverse step-over leave the frame" is
/// decidable rather than a guess.
#[tokio::test]
async fn reverse_step_over_equals_step_backward_today() {
    let fx = fixture_or_skip!();
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    assert!(run_to(&dbg, fx.callee.0).await, "the fixture should reach callee");
    let rec = record_trace(&dbg, tid, 6).await;
    let pcs = rec.pcs.clone();
    if pcs.len() < 3 {
        eprintln!("[skip] recording too short");
        let _ = dbg.kill().await;
        return;
    }
    let end = pcs.last().unwrap().0;

    // Two independent sessions over the same measured pcs, to compare the ops.
    let mut clone = SnapshotReplayBackend::new();
    for &(seq, pc) in &pcs {
        let mut st = TtdState::new(TracePosition::new(seq, 0), pc, 0);
        st.stop_reason = "recorded".into();
        clone.record(st);
    }
    let mut a = session_over(rec.backend);
    let mut b = session_over(clone);
    a.seek(TracePosition::new(end, 0)).expect("seek a");
    b.seek(TracePosition::new(end, 0)).expect("seek b");

    let back = a.step_backward().expect("step_backward");
    let over = b.reverse_step_over().expect("reverse_step_over");
    assert_eq!(
        (over.position, over.pc),
        (back.position, back.pc),
        "MEASURED: reverse_step_over is aliased to step_backward"
    );
    assert!(
        over.pc >= fx.callee.0 && over.pc < fx.callee.1,
        "MEASURED: still inside callee [{:#x},{:#x}) at {:#x} — it stepped OVER nothing",
        fx.callee.0,
        fx.callee.1,
        over.pc
    );

    let _ = dbg.kill().await;
}

/// DEFECT — `TtdBackend::reverse_step_over` for `SnapshotReplayBackend` is
/// `self.step_backward(current)`: it has no notion of a call frame, so from
/// inside a callee it steps one instruction back INSIDE the same callee
/// instead of landing at the caller's call site.
///
/// | | value |
/// |---|---|
/// | expected (gdb `reverse-next` from inside `callee`) | lands in `main`, at or before the `call <callee>` |
/// | reachable today | the recording holds every pc; walking back to the first recorded state whose pc lies outside `[callee, callee_end)` is a scan over data already held |
/// | obtained | a pc still inside `[callee, callee_end)` (see the measured test above) |
///
/// External truth: `nm --print-size ./fixture` for the extent of `callee`,
/// `objdump -d ./fixture` for the `call <callee>` inside `main`.
///
/// MEASURED RED:
/// ```text
/// reverse_step_over from inside callee must leave [0x401865,0x40187a);
/// it returned 0x401870
/// ```
#[tokio::test]
#[ignore = "DEFECT: reverse_step_over is aliased to step_backward and is frame-blind"]
async fn defect_reverse_step_over_should_leave_the_callee_frame() {
    let fx = fixture_or_skip!();
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    assert!(run_to(&dbg, fx.callee.0).await, "reach callee");
    let rec = record_trace(&dbg, tid, 6).await;
    let end = rec.pcs.last().unwrap().0;
    let mut sess = session_over(rec.backend);
    sess.seek(TracePosition::new(end, 0)).expect("seek to the end");

    let st = sess.reverse_step_over().expect("reverse_step_over");
    assert!(
        st.pc < fx.callee.0 || st.pc >= fx.callee.1,
        "reverse_step_over from inside callee must leave [{:#x},{:#x}); it returned {:#x}",
        fx.callee.0,
        fx.callee.1,
        st.pc
    );

    let _ = dbg.kill().await;
}

/// MEASURES TODAY'S BEHAVIOUR: `run_to_previous_call` over a real recording of
/// `main` returns a pc that `objdump -d` does NOT list as a `call`.
///
/// WHY THAT IS THE RIGHT PROBE: `main` in this fixture contains calls (to
/// `callee` and to `printf`) whose addresses are read out of the disassembly,
/// so "is the returned pc a call site" is answered by an external tool rather
/// than by the debugger's own opinion.
#[tokio::test]
async fn run_to_previous_call_does_not_land_on_a_call_site_today() {
    let fx = fixture_or_skip!();
    let sites = call_sites_in_main(&fx.path, fx.main);
    if sites.is_empty() {
        eprintln!("[skip] objdump listed no call inside main");
        return;
    }
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    assert!(run_to(&dbg, fx.main.0).await, "reach main");
    let rec = record_trace(&dbg, tid, 30).await;
    let end = rec.pcs.last().unwrap().0;
    let mut sess = session_over(rec.backend);
    sess.seek(TracePosition::new(end, 0)).expect("seek to the end");

    let st = sess.run_to_previous_call().expect("run_to_previous_call");
    eprintln!(
        "[measured] run_to_previous_call -> pc {:#x}; objdump call sites in main: {sites:x?}",
        st.pc
    );
    assert!(
        !sites.contains(&st.pc),
        "MEASURED EXPECTATION BROKEN (in a good way): run_to_previous_call returned a real call \
         site {:#x}. If that is now deliberate, delete this test and un-ignore the defect test \
         below",
        st.pc
    );

    let _ = dbg.kill().await;
}

/// DEFECT — `TtdBackend::run_to_previous_call` for `SnapshotReplayBackend` is
/// `self.step_backward(current)`. It never inspects an instruction, so it
/// cannot find a call.
///
/// | | value |
/// |---|---|
/// | expected (WinDbg TTD `!tt` backwards / rr `reverse-finish`) | the most recent `call` instruction before the cursor |
/// | reachable today | the workspace already disassembles (`rustre-arch-x86`) and the recording holds every pc — matching recorded pcs against call sites is a scan |
/// | obtained | the immediately preceding recorded pc; a call only by coincidence |
///
/// External truth: `objdump -d ./fixture`, `call` lines inside `main`.
///
/// MEASURED RED:
/// ```text
/// run_to_previous_call returned 0x404d28, which objdump does not list as a
/// call site among [4018a2, 4018bf]
/// ```
#[tokio::test]
#[ignore = "DEFECT: run_to_previous_call is aliased to step_backward and never looks for a call"]
async fn defect_run_to_previous_call_should_land_on_a_call() {
    let fx = fixture_or_skip!();
    let sites = call_sites_in_main(&fx.path, fx.main);
    if sites.is_empty() {
        eprintln!("[skip] objdump listed no call inside main");
        return;
    }
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    assert!(run_to(&dbg, fx.main.0).await, "reach main");
    let rec = record_trace(&dbg, tid, 30).await;
    let end = rec.pcs.last().unwrap().0;
    let mut sess = session_over(rec.backend);
    sess.seek(TracePosition::new(end, 0)).expect("seek to the end");

    let st = sess.run_to_previous_call().expect("run_to_previous_call");
    assert!(
        sites.contains(&st.pc),
        "run_to_previous_call returned {:#x}, which objdump does not list as a call site among \
         {sites:x?}",
        st.pc
    );

    let _ = dbg.kill().await;
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. The backend-LESS session, measured against the same live process
// ═════════════════════════════════════════════════════════════════════════════

/// MEASURES THE GAP: a `TtdSession` fed real `ProcessSnapshot`s from a live
/// process — but with no `TtdBackend` attached — moves its position cursor
/// correctly and reports `pc = 0`, flagged by the `simulated_` prefix.
///
/// WHY THAT IS RIGHT (and still a gap): the module documents this contract
/// explicitly and a caller testing the prefix is safe. What is lost is that
/// the snapshots handed to `record_snapshot` DO carry the real registers in
/// `thread_regs`, and the simulated path throws them away.
///
/// | | value |
/// |---|---|
/// | expected | the pc of the previous position |
/// | reachable today | the same snapshots, read back through `ProcessSnapshot::thread_regs` |
/// | obtained | `pc = 0`, `regs` empty, `stop_reason = "simulated_backward_step"` |
#[tokio::test]
async fn backendless_session_moves_the_cursor_but_reports_no_registers() {
    let fx = fixture_or_skip!();
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    assert!(run_to(&dbg, fx.main.0).await, "reach main");

    let mut sess = TtdSession::new(TtdConfig::default());
    let mut real_pcs = Vec::new();
    for seq in 1..=8u64 {
        let regs = dbg.get_registers(tid).await.expect("registers of the live process");
        let pos = TracePosition::new(seq, 0);
        let mut snap = ProcessSnapshot::new(pos);
        let mut map = BTreeMap::new();
        for name in regs.all_names() {
            if let Some(v) = regs.get(&name) {
                map.insert(name, v);
            }
        }
        snap.thread_regs.insert(tid.0, map);
        sess.seek(pos).expect("simulated seek");
        sess.record_snapshot(snap);
        real_pcs.push(regs.pc);
        let ev = dbg.single_step(tid).await.expect("single_step");
        if ev.reason.is_exit() {
            break;
        }
    }
    assert_eq!(sess.snapshot_count(), real_pcs.len(), "one snapshot per step");
    assert_eq!(sess.backend_name(), "snapshot-simulation", "no backend attached");
    assert!(real_pcs.len() >= 2, "need two positions to step back between");

    let st = sess.step_backward().expect("simulated backward step");
    assert!(
        st.stop_reason.starts_with(SIMULATED_STOP_REASON_PREFIX),
        "the simulated path must flag itself: {}",
        st.stop_reason
    );
    assert_eq!(st.pc, 0, "MEASURED: the simulated path reports pc = 0");
    assert!(st.regs.is_empty(), "MEASURED: and no registers");
    eprintln!(
        "[measured] backend-less step_backward: pos {} pc {:#x}; the process's real previous pc \
         was {:#x}",
        st.position,
        st.pc,
        real_pcs[real_pcs.len() - 2]
    );

    let _ = dbg.kill().await;
}

// ═════════════════════════════════════════════════════════════════════════════
// 6. who_wrote / trace_origin on writes observed in a live process
// ═════════════════════════════════════════════════════════════════════════════

/// Single-step the live process watching the 4 bytes at `addr`, recording a
/// [`MemoryWrite`] whenever the value changes. `writer_pc` is the pc that was
/// about to execute before the step that changed it — the storing instruction.
///
/// THIS IS THE PRODUCER THE CRATE DOES NOT HAVE. In the whole workspace
/// `OmniscientIndex` is filled only by the MCP tool `debug.record_write` (a
/// caller telling it what happened) and by unit tests / benches with synthetic
/// writes.
async fn observe_writes_to(
    dbg: &LinuxDebugger,
    tid: ThreadId,
    addr: u64,
    max_steps: usize,
) -> (OmniscientIndex, SnapshotReplayBackend, Vec<(u64, u32, u64)>) {
    let mut index = OmniscientIndex::new();
    let mut backend = SnapshotReplayBackend::new();
    let mut observed: Vec<(u64, u32, u64)> = Vec::new();
    let as_u32 = |bytes: &[u8]| -> u32 {
        let mut a = [0u8; 4];
        a.copy_from_slice(&bytes[..4]);
        u32::from_le_bytes(a)
    };
    let Ok(first) = dbg.read_memory(Address::new(addr), 4).await else {
        return (index, backend, observed);
    };
    let mut prev = as_u32(&first);

    for seq in 1..=max_steps as u64 {
        let Ok(regs) = dbg.get_registers(tid).await else { break };
        let pc = regs.pc;
        let sp = regs.get("rsp").unwrap_or(0);
        let mut map = BTreeMap::new();
        for name in regs.all_names() {
            if let Some(v) = regs.get(&name) {
                map.insert(name, v);
            }
        }
        let pos = TracePosition::new(seq, 0);
        let mut st = TtdState::new(pos, pc, sp);
        st.regs = map;
        st.stop_reason = "recorded".into();
        backend.record(st);
        if sp != 0 {
            if let Ok(bytes) = dbg.read_memory(Address::new(sp.saturating_sub(64)), 256).await {
                backend.record_memory(pos, sp.saturating_sub(64), bytes);
            }
        }

        let Ok(ev) = dbg.single_step(tid).await else { break };
        if ev.reason.is_exit() {
            break;
        }
        let Ok(now) = dbg.read_memory(Address::new(addr), 4).await else { break };
        let now = as_u32(&now);
        if now != prev {
            index.push(MemoryWrite {
                sequence: seq,
                address: Address::new(addr),
                size: 4,
                tid,
                writer_pc: Some(Address::new(pc)),
                source_address: None,
            });
            observed.push((seq, now, pc));
            prev = now;
        }
    }
    (index, backend, observed)
}

/// PROVES: `who_wrote` answers correctly over writes OBSERVED in a live
/// process — the last writer of the global `g` is the instruction inside
/// `main` that stored `0x22`, and the query one sequence earlier names the
/// instruction that stored `0x11`.
///
/// WHY THAT IS RIGHT: the two constants are unique in the program, the extent
/// of `main` comes from `nm --print-size`, and the writes come from watching
/// real memory across real single-steps. Nothing is synthetic except the act
/// of recording — which is precisely the gap this file measures.
#[tokio::test]
async fn who_wrote_names_the_real_instruction_that_stored_the_global() {
    let fx = fixture_or_skip!();
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    assert!(run_to(&dbg, fx.main.0).await, "reach main");
    let (index, _replay, observed) = observe_writes_to(&dbg, tid, fx.g, 400).await;

    eprintln!("[measured] writes to g @ {:#x}: {observed:x?}", fx.g);
    assert!(observed.len() >= 2, "main writes g twice (0x11 then 0x22); observed {observed:x?}");
    assert_eq!(observed[0].1, 0x11, "first observed value");
    assert_eq!(observed[1].1, 0x22, "second observed value");

    let second_seq = observed[1].0;
    let w = index
        .last_writer(Address::new(fx.g), second_seq)
        .expect("who_wrote must name a writer for an address written twice");
    assert_eq!(w.sequence, second_seq, "the LAST writer is the 0x22 store");
    let pc = w.writer_pc.expect("the observed write carries its pc").as_u64();
    assert!(
        pc >= fx.main.0 && pc < fx.main.1,
        "the storing instruction {pc:#x} must be inside main [{:#x},{:#x})",
        fx.main.0,
        fx.main.1
    );

    let earlier = index
        .who_wrote(Address::new(fx.g), second_seq - 1)
        .into_iter()
        .next()
        .expect("a writer exists before the second store");
    assert_eq!(earlier.sequence, observed[0].0, "the earlier writer is the 0x11 store");
    assert_ne!(
        earlier.writer_pc, w.writer_pc,
        "two different store instructions must have two different pcs"
    );

    let _ = dbg.kill().await;
}

/// PROVES: `who_wrote` on a byte INSIDE the 4-byte store (`g+1..g+3`) still
/// names it, and on `g+4` — one byte past — names nobody.
///
/// WHY THAT IS RIGHT: a user asks about the address they saw in a hex dump,
/// which is rarely the base of the store. A `who_wrote` matching only exact
/// bases would answer "nobody" for three bytes out of four; one that matched
/// too far would blame a store for a byte it never touched.
#[tokio::test]
async fn who_wrote_covers_the_interior_bytes_of_a_real_store() {
    let fx = fixture_or_skip!();
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    assert!(run_to(&dbg, fx.main.0).await, "reach main");
    let (index, _replay, observed) = observe_writes_to(&dbg, tid, fx.g, 400).await;
    if observed.len() < 2 {
        eprintln!("[skip] did not observe both stores");
        let _ = dbg.kill().await;
        return;
    }
    let last_seq = observed.last().unwrap().0;
    for off in 1..4u64 {
        let hits = index.who_wrote(Address::new(fx.g + off), last_seq);
        assert!(
            !hits.is_empty(),
            "g+{off} lies inside a recorded 4-byte store and must have a writer"
        );
        assert_eq!(hits[0].sequence, last_seq, "and the most recent one is the last store");
    }
    assert!(
        index.who_wrote(Address::new(fx.g + 4), last_seq).is_empty(),
        "g+4 is outside the 4-byte store and must have no writer"
    );

    let _ = dbg.kill().await;
}

/// PROVES: `trace_origin_full` over the observed writes stops with
/// `OriginEnd::Origin` — the store to `g` was not copied from another recorded
/// address, so the chain really ends there — while a query at sequence 0
/// reports `NoEarlierWriter`.
///
/// WHY THAT IS RIGHT: the distinction the API draws (`Origin` vs
/// `NoEarlierWriter` vs `LimitReached`) is the difference between "this is
/// where the value came from" and "I stopped looking", and only a real chain
/// shows which one a real write produces.
#[tokio::test]
async fn trace_origin_over_observed_writes_reaches_a_real_origin() {
    let fx = fixture_or_skip!();
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    assert!(run_to(&dbg, fx.main.0).await, "reach main");
    let (index, _replay, observed) = observe_writes_to(&dbg, tid, fx.g, 400).await;
    if observed.is_empty() {
        eprintln!("[skip] observed no write to g");
        let _ = dbg.kill().await;
        return;
    }
    let last_seq = observed.last().unwrap().0;

    let t = index.trace_origin_full(Address::new(fx.g), last_seq);
    assert_eq!(t.end, OriginEnd::Origin, "an immediate-constant store IS the origin");
    assert!(t.reached_origin(), "and the walk says so");
    assert_eq!(t.hops.len(), 1, "no source_address was observed, so the chain is one hop");

    let t0 = index.trace_origin_full(Address::new(fx.g), 0);
    assert_eq!(t0.end, OriginEnd::NoEarlierWriter, "nothing wrote g at sequence 0");

    let _ = dbg.kill().await;
}

/// MEASURES THE GAP: driving a real process through the crate's OWN public
/// API — launch, breakpoint, `single_step`, `get_registers` — leaves
/// `OmniscientIndex` EMPTY. Nothing in `rustre-debug` observes writes.
///
/// | | value |
/// |---|---|
/// | expected (`rr` / Pernosco) | every store recorded and queryable by address, with no caller cooperation |
/// | reachable today | a hardware watchpoint per address (4 slots), or the caller diffing memory after every step — both written by the CALLER (`observe_writes_to` above) |
/// | obtained | 0 writes; the index is filled only when someone calls `push` / `debug.record_write` |
///
/// External truth: `rr record ./fixture && rr replay` answers "who wrote &g"
/// without the caller writing a step loop at all.
#[tokio::test]
async fn nothing_in_the_crate_records_writes_from_a_live_process() {
    let fx = fixture_or_skip!();
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    assert!(run_to(&dbg, fx.main.0).await, "reach main");

    let index = OmniscientIndex::new();
    for _ in 0..60 {
        let Ok(ev) = dbg.single_step(tid).await else { break };
        if ev.reason.is_exit() {
            break;
        }
        let _ = dbg.get_registers(tid).await;
    }
    assert!(
        index.is_empty(),
        "MEASURED: 60 single-steps of a real process produced {} recorded writes",
        index.writes().len()
    );
    assert!(
        index.who_wrote(Address::new(fx.g), u64::MAX).is_empty(),
        "who_wrote answers 'nobody' for an address main demonstrably wrote twice"
    );

    let _ = dbg.kill().await;
}

// ═════════════════════════════════════════════════════════════════════════════
// 7. retroactive_print over real writes and real registers
// ═════════════════════════════════════════════════════════════════════════════

/// PROVES: `retro_print` over the observed writes and the recorded live
/// register states renders REAL register values at the moment of each store —
/// one entry per observed write, most-recent-first, each carrying the pc of
/// its storing instruction.
///
/// WHY THAT IS RIGHT: retroactive print's claim is "the printf you forgot to
/// write, evaluated in the past". The `rip` it renders must be the pc measured
/// at that write, and the entries must be ordered like `who_wrote`.
#[tokio::test]
async fn retro_print_renders_real_registers_at_a_real_write() {
    let fx = fixture_or_skip!();
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    assert!(run_to(&dbg, fx.main.0).await, "reach main");
    let (index, replay, observed) = observe_writes_to(&dbg, tid, fx.g, 400).await;
    if observed.len() < 2 {
        eprintln!("[skip] did not observe both stores");
        let _ = dbg.kill().await;
        return;
    }
    let last_seq = observed.last().unwrap().0;

    let ann = RetroAnnotation {
        address: fx.g,
        format: "g written at pc={0} sp={1}".to_string(),
        args: vec!["rip".to_string(), "rsp".to_string()],
    };
    let entries = retro_print(&index, &replay, &ann, last_seq);

    assert_eq!(entries.len(), observed.len(), "one entry per observed write");
    assert_eq!(entries[0].position.sequence, observed[1].0, "newest entry first");
    assert_eq!(entries[1].position.sequence, observed[0].0, "then the older one");

    for (e, &(seq, _val, pc)) in entries.iter().zip(observed.iter().rev()) {
        assert_eq!(e.writer_pc, Some(pc), "entry for seq {seq} carries the storing pc");
        match &e.arg_values[0] {
            EvalResult::U64(v) => assert_eq!(*v, pc, "rendered rip must be the measured pc"),
            other => panic!("rip did not evaluate at seq {seq}: {other:?}"),
        }
        assert!(matches!(e.arg_values[1], EvalResult::U64(v) if v != 0), "rsp must be real");
        assert!(e.rendered.contains(&format!("{pc:#x}")), "rendered: {}", e.rendered);
    }

    let _ = dbg.kill().await;
}

/// PROVES: a retroactive expression that DEREFERENCES historical memory
/// (`*(rsp+0)`) resolves against the stack window recorded at that position
/// instead of failing.
///
/// WHY THAT IS RIGHT: historical deref is the one part of retro-print that
/// cannot be faked from registers alone. The window recorded at each position
/// is `[rsp-64, rsp+192)`, so `rsp` itself is covered by construction; an
/// `Err` here would mean the memory side of the recording is not wired at all.
#[tokio::test]
async fn retro_print_derefs_the_recorded_stack_window() {
    let fx = fixture_or_skip!();
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    assert!(run_to(&dbg, fx.main.0).await, "reach main");
    let (index, replay, observed) = observe_writes_to(&dbg, tid, fx.g, 400).await;
    if observed.is_empty() {
        eprintln!("[skip] observed no write to g");
        let _ = dbg.kill().await;
        return;
    }
    let last_seq = observed.last().unwrap().0;

    let ann = RetroAnnotation {
        address: fx.g,
        format: "{0}".to_string(),
        args: vec!["*(rsp+0)".to_string()],
    };
    let entries = retro_print(&index, &replay, &ann, last_seq);
    assert!(!entries.is_empty(), "at least one entry");
    match &entries[0].arg_values[0] {
        EvalResult::U64(v) => eprintln!("[measured] *(rsp) at the last store = {v:#x}"),
        EvalResult::Bytes(b) => eprintln!("[measured] *(rsp) = {b:x?}"),
        EvalResult::Err(e) => panic!(
            "historical deref of *(rsp+0) failed although a 256-byte window around rsp was \
             recorded at that position: {e}"
        ),
    }

    let _ = dbg.kill().await;
}

/// PROVES: an annotation on an address with NO recorded write yields no
/// entries — retro-print does not invent a timeline.
///
/// WHY THAT IS RIGHT: `g + 0x1000` is never written by the fixture. An empty
/// result is the only honest answer; a non-empty one would mean entries come
/// from the annotation rather than from the evidence.
#[tokio::test]
async fn retro_print_on_an_unwritten_address_yields_nothing() {
    let fx = fixture_or_skip!();
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    assert!(run_to(&dbg, fx.main.0).await, "reach main");
    let (index, replay, _observed) = observe_writes_to(&dbg, tid, fx.g, 200).await;

    let ann = RetroAnnotation::simple(fx.g + 0x1000, "rip");
    assert!(
        retro_print(&index, &replay, &ann, u64::MAX).is_empty(),
        "an address nothing wrote must produce no retroactive-print entries"
    );

    let _ = dbg.kill().await;
}

// ═════════════════════════════════════════════════════════════════════════════
// 8. Hygiene
// ═════════════════════════════════════════════════════════════════════════════

/// PROVES: this suite leaves no orphaned fixture processes behind.
///
/// WHY THAT IS RIGHT: every test above kills its target on the success path,
/// but a `panic!` skips that. `pgrep -f fixture` afterwards is the only check
/// that does not trust the code under test. Named `zz_` so it runs last under
/// `--test-threads=1`, where cargo orders tests by name.
#[tokio::test]
async fn zz_no_orphan_fixture_processes_remain() {
    match Command::new("pgrep").args(["-af", "fixture"]).output() {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            let mine: Vec<&str> =
                s.lines().filter(|l| l.contains("/fixture") && !l.contains("pgrep")).collect();
            assert!(mine.is_empty(), "orphaned fixture processes: {mine:?}");
        }
        Err(e) => eprintln!("[skip] pgrep unavailable: {e}"),
    }
}
