//! DE-VACUATION of `live_linux_reverse.rs`: the backward path is required to
//! reproduce a pc sequence measured on a DIFFERENT process.
//!
//! ## The vacuity this file answers
//!
//! The falsification campaign measured 2 biting tests out of 20 active ones in
//! `live_linux_reverse.rs`. The cause is structural: every reverse test there
//! records a trace with `record_trace`, then asserts that the replay agrees
//! with `rec.pcs` — the pc list produced by the SAME `get_registers` calls that
//! filled the trace. That is an identity, not a measurement: a recorder that
//! reported every pc four bytes off would satisfy it exactly.
//!
//! ## The oracle
//!
//! The independent truth for reverse debugging is the pc sequence ptrace
//! measures stepping FORWARD — measured here in a **second, separate process**
//! (`forward_pc_sequence`), never in the process whose recording is replayed.
//! The backward walk must reproduce that sequence *element by element*, in
//! reverse. A count of steps would be lax; the sequence is not.
//!
//! ## The oracle is itself falsified, three ways
//!
//! 1. two independent runs of the fixture must give the SAME sequence (a
//!    non-deterministic oracle constrains nothing);
//! 2. every pc in it must be an instruction boundary `objdump -d` lists — a
//!    different tool, which no debugger bug can move;
//! 3. it must reproduce a PAIR read out of the fixture's own **stdout**, which
//!    the debugger does not produce: the program prints its loop count `3`, so
//!    `hot`'s entry must occur exactly 3 times in the sequence and `cold`'s
//!    exactly 0. One cell would not separate the two functions; the pair does.

#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::time_travel_debug::{
    SnapshotReplayBackend, TracePosition, TtdConfig, TtdError, TtdSession, TtdState,
};
use rustre_debug::{BreakpointKind, Debugger, LaunchOptions, StopReason, ThreadId};
use std::collections::BTreeMap;
use std::process::Command;

/// `hot` is called exactly three times and `cold` never; the program PRINTS
/// both the accumulated result and the loop count, so the trace's shape is
/// checkable against something the debugger never produces.
const FIXTURE_C: &str = r#"
#include <stdio.h>
int g = 0;
__attribute__((noinline)) int hot(int x)  { g += x; return g; }
__attribute__((noinline)) int cold(int x) { g -= x; return g; }
int main(void) {
    int n = 0;
    for (int i = 0; i < 3; i++) n = hot(2);
    printf("%d %d\n", n, 3);
    return 0;
}
"#;

/// How many forward single-steps every recording in this file takes. Chosen so
/// all three `hot` calls are inside the window — asserted, not assumed.
const STEPS: usize = 160;

struct Fixture {
    _dir: tempfile::TempDir,
    path: String,
    main: u64,
    hot: u64,
    cold: u64,
    /// `objdump -d` boundaries: address -> instruction text.
    text: BTreeMap<u64, String>,
    /// What the program prints with no debugger attached.
    stdout: String,
}

impl Fixture {
    fn insn(&self, pc: u64) -> Option<&str> {
        self.text.get(&pc).map(String::as_str)
    }
    fn next_insn(&self, pc: u64) -> Option<u64> {
        self.text.range(pc + 1..).next().map(|(a, _)| *a)
    }
    /// The two numbers the program PRINTS: the accumulated result and the loop
    /// count. The one oracle the debugger never produces, and it is read here
    /// rather than hardcoded — a literal `"6 3"` would make the parse
    /// decorative, the very defect the falsification campaign found in
    /// `live_linux_elf_symbols.rs` (its `nm` count appeared only inside
    /// `format!`).
    fn printed(&self) -> (u64, usize) {
        let mut it = self.stdout.split_whitespace();
        let n = it.next().and_then(|s| s.parse().ok()).expect("the fixture prints two numbers");
        let loops =
            it.next().and_then(|s| s.parse().ok()).expect("the fixture prints two numbers");
        assert_eq!(
            n,
            2 * loops as u64,
            "`hot` adds 2 per call: the printed result must be twice the loop count, {:?}",
            self.stdout.trim()
        );
        (n, loops)
    }

    /// The first `ret` boundary at or after `from`, per `objdump` — used to find
    /// where `hot` returns without asking the debugger.
    fn next_ret(&self, from: u64) -> Option<u64> {
        self.text.range(from..).find(|(_, i)| i.starts_with("ret")).map(|(&a, _)| a)
    }
}

fn build_fixture() -> Option<Fixture> {
    let dir = tempfile::tempdir().ok()?;
    let src = dir.path().join("devacrev.c");
    let exe = dir.path().join("devacrev");
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
    let text = disasm(&path);
    if text.is_empty() {
        eprintln!("[fixture] objdump gave no disassembly; the external oracle is unavailable");
        return None;
    }
    let o = Command::new(&path).output().ok()?;
    if !o.status.success() {
        return None;
    }
    Some(Fixture {
        _dir: dir,
        main: symbol_addr(&path, "main")?,
        hot: symbol_addr(&path, "hot")?,
        cold: symbol_addr(&path, "cold")?,
        path,
        text,
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
    })
}

/// `objdump -d` instruction boundaries. A continuation line carries an address
/// but no instruction field and is deliberately not a boundary: counting it as
/// one would let a pc landing mid-instruction pass.
fn disasm(exe: &str) -> BTreeMap<u64, String> {
    let Ok(out) = Command::new("objdump").args(["-d", exe]).output() else {
        return BTreeMap::new();
    };
    let mut map = BTreeMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut it = line.split('\t');
        let (Some(addr), Some(_b), Some(insn)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let Some(addr) = addr.trim().strip_suffix(':') else { continue };
        let Ok(addr) = u64::from_str_radix(addr, 16) else { continue };
        if !insn.trim().is_empty() {
            map.insert(addr, insn.trim().to_string());
        }
    }
    map
}

/// Address of a defined symbol, from `nm`.
fn symbol_addr(exe: &str, name: &str) -> Option<u64> {
    let out = Command::new("nm").args(["--defined-only", exe]).output().ok()?;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 3 && f.last() == Some(&name) {
            return u64::from_str_radix(f[0], 16).ok();
        }
    }
    None
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

macro_rules! oracle_or_skip {
    ($fx:expr) => {
        match forward_pc_sequence($fx, STEPS).await {
            Some(o) => o,
            None => {
                eprintln!("[skip] launch failed while measuring the oracle");
                return;
            }
        }
    };
}

async fn open(fx: &Fixture) -> Option<(LinuxDebugger, ThreadId)> {
    let dbg = LinuxDebugger::new();
    let pid = dbg.launch(LaunchOptions::new(fx.path.clone())).await.ok()?;
    Some((dbg, ThreadId(pid.0)))
}

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

/// THE ORACLE. Launch a FRESH process of the fixture, run to `main`, and record
/// the pc ptrace reports before each of `steps` single-steps.
///
/// Nothing of the session being replayed is reused: a different pid, a
/// different `LinuxDebugger`, a different chain of `get_registers` calls. That
/// is what makes the comparisons below measurements instead of identities.
async fn forward_pc_sequence(fx: &Fixture, steps: usize) -> Option<Vec<u64>> {
    let (dbg, tid) = open(fx).await?;
    if !run_to(&dbg, fx.main).await {
        let _ = dbg.kill().await;
        return None;
    }
    let mut pcs = Vec::with_capacity(steps);
    for _ in 0..steps {
        let Ok(regs) = dbg.get_registers(tid).await else { break };
        pcs.push(regs.pc);
        let Ok(ev) = dbg.single_step(tid).await else { break };
        if ev.reason.is_exit() {
            break;
        }
    }
    let _ = dbg.kill().await;
    Some(pcs)
}

/// The recording under test. Its own pc list is deliberately NOT returned: no
/// test here is allowed to build its expectation out of it.
async fn record_trace(dbg: &LinuxDebugger, tid: ThreadId, steps: usize) -> SnapshotReplayBackend {
    let mut backend = SnapshotReplayBackend::new();
    for seq in 1..=steps as u64 {
        let Ok(regs) = dbg.get_registers(tid).await else { break };
        let sp = regs.get("rsp").unwrap_or(0);
        let mut st = TtdState::new(TracePosition::new(seq, 0), regs.pc, sp);
        for name in regs.all_names() {
            if let Some(v) = regs.get(&name) {
                st.regs.insert(name, v);
            }
        }
        st.stop_reason = "recorded".to_string();
        backend.record(st);
        let Ok(ev) = dbg.single_step(tid).await else { break };
        if ev.reason.is_exit() {
            break;
        }
    }
    backend
}

/// Record `STEPS` states off a fresh process stopped at `main`.
async fn recording_from_main(fx: &Fixture) -> Option<SnapshotReplayBackend> {
    let (dbg, tid) = open(fx).await?;
    if !run_to(&dbg, fx.main).await {
        let _ = dbg.kill().await;
        return None;
    }
    let backend = record_trace(&dbg, tid, STEPS).await;
    let _ = dbg.kill().await;
    Some(backend)
}

fn session_over(backend: SnapshotReplayBackend) -> TtdSession {
    let mut s = TtdSession::new(TtdConfig::default());
    s.attach_backend(Box::new(backend));
    s
}

/// The `(hot, cold)` entry-crossing PAIR of a pc sequence.
fn crossings(seq: &[u64], fx: &Fixture) -> (usize, usize) {
    (seq.iter().filter(|&&pc| pc == fx.hot).count(), seq.iter().filter(|&&pc| pc == fx.cold).count())
}

// ═════════════════════════════════════════════════════════════════════════════
// 0. The oracle, falsified before anything leans on it
// ═════════════════════════════════════════════════════════════════════════════

/// PROVES: the forward pc sequence is REPRODUCIBLE across two separate
/// processes, consists only of instruction boundaries `objdump -d` lists,
/// follows objdump's decoded instruction lengths wherever control is not
/// transferred, and reproduces the `(hot, cold) = (3, 0)` crossing pair the
/// fixture's own stdout declares.
///
/// WHY THAT IS RIGHT: every test below asserts that the backward walk equals
/// this sequence. If the sequence itself were run-dependent, off the
/// instruction grid, or describing a different program's control flow, all of
/// them would be green about nothing. A single count would not do — `main` is
/// crossed once and so is `printf`'s entry; the PAIR (3, 0) is reproduced by
/// exactly one assignment of addresses to `hot` and `cold`.
#[tokio::test]
async fn the_forward_pc_sequence_is_a_trustworthy_oracle() {
    let fx = fixture_or_skip!();
    let a = oracle_or_skip!(&fx);
    let b = oracle_or_skip!(&fx);

    assert_eq!(a.len(), STEPS, "{STEPS} single-steps from main must not exit the process");
    assert_eq!(a, b, "two separate runs of the same static, no-pie binary must step identically");

    let strays: Vec<u64> = a.iter().copied().filter(|&pc| fx.insn(pc).is_none()).collect();
    assert!(
        strays.is_empty(),
        "{} of {} oracle pcs are not instruction boundaries in `objdump -d`: {:x?}",
        strays.len(),
        a.len(),
        &strays[..strays.len().min(6)]
    );

    // stdout is the one oracle the debugger cannot produce.
    let (_, loops) = fx.printed();
    assert!(loops > 1, "a loop count of {loops} cannot separate a per-call event from a one-off");
    assert_eq!(
        crossings(&a, &fx),
        (loops, 0),
        "the program says it looped {loops} times over `hot` and never called `cold`; the \
         measured (hot, cold) crossing pair disagrees"
    );

    // The sequence must follow objdump's instruction LENGTHS wherever control
    // is not transferred — decoded by a second tool, one instruction at a time.
    for w in a.windows(2) {
        let Some(insn) = fx.insn(w[0]) else { continue };
        let m = insn.split_whitespace().next().unwrap_or("");
        if m.starts_with('j')
            || m.starts_with("call")
            || m.starts_with("ret")
            || m.starts_with("rep")
            || m.starts_with("loop")
            || m.starts_with("syscall")
            || m.starts_with("iret")
        {
            continue;
        }
        assert_eq!(
            Some(w[1]),
            fx.next_insn(w[0]),
            "`{insn}` at {:#x} transfers no control, so the next pc must be objdump's next \
             boundary, not {:#x}",
            w[0],
            w[1]
        );
    }
    eprintln!("[oracle] {} pcs, (hot, cold) crossings {:?}", a.len(), crossings(&a, &fx));
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. The backward walk must reproduce the forward sequence
// ═════════════════════════════════════════════════════════════════════════════

/// PROVES: walking a recording backwards with `step_backward` yields exactly
/// the reverse of the pc sequence measured on a DIFFERENT process.
///
/// WHY THAT IS RIGHT: this is the whole promise of reverse execution. The
/// expectation comes from another process's ptrace measurement, so a recorder
/// that shifted, dropped or duplicated states cannot satisfy it — unlike the
/// existing tests, which compare the replay with the very list that filled it.
#[tokio::test]
async fn backward_walk_reproduces_the_independent_forward_sequence() {
    let fx = fixture_or_skip!();
    let oracle = oracle_or_skip!(&fx);
    let Some(backend) = recording_from_main(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };

    assert_eq!(backend.len(), oracle.len(), "one recorded state per measured step");
    let mut sess = session_over(backend);
    let end = sess.seek(TracePosition::new(oracle.len() as u64, 0)).expect("seek to the end");

    let mut back = vec![end.pc];
    while let Ok(st) = sess.step_backward() {
        back.push(st.pc);
    }
    assert_eq!(
        sess.step_backward().unwrap_err(),
        TtdError::AtBeginning,
        "the walk must have stopped because the recording ran out, not for another reason"
    );

    let mut expected: Vec<u64> = oracle.clone();
    expected.reverse();
    assert_eq!(
        back.len(),
        expected.len(),
        "the backward walk visited {} positions; the separate ptrace run measured {} \
         instructions",
        back.len(),
        expected.len()
    );
    if let Some(k) = back.iter().zip(&expected).position(|(a, b)| a != b) {
        panic!(
            "the backward walk diverges from the independently measured forward sequence at step \
             {k}: replay says {:#x}, ptrace measured {:#x} on a separate process",
            back[k], expected[k]
        );
    }
}

/// PROVES: `seek` to the k-th recorded position returns the k-th pc of the
/// independently measured forward sequence — for EVERY k, not for a sampled
/// one.
///
/// WHY THAT IS RIGHT: `seek` is what a reverse UI calls for every scrub of the
/// timeline. Checking one position leaves an off-by-one in the middle of the
/// trace invisible; checking all of them against another process's measurement
/// does not.
#[tokio::test]
async fn every_seek_position_matches_the_independent_forward_sequence() {
    let fx = fixture_or_skip!();
    let oracle = oracle_or_skip!(&fx);
    let Some(backend) = recording_from_main(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    let mut sess = session_over(backend);

    let mut wrong = Vec::new();
    for (k, &want) in oracle.iter().enumerate() {
        let st = sess.seek(TracePosition::new(k as u64 + 1, 0)).expect("in-range seek");
        if st.pc != want {
            wrong.push((k, st.pc, want));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} seeks report a pc the process did not have there (k, replayed, measured): {:x?}",
        wrong.len(),
        oracle.len(),
        &wrong[..wrong.len().min(6)]
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. reverse_continue against the sequence, not against itself
// ═════════════════════════════════════════════════════════════════════════════

/// PROVES: `reverse_continue` toward `hot`'s entry stops at the LAST position
/// before the cursor at which the independently measured sequence has that pc,
/// and repeating it walks back through all three calls in descending order.
///
/// WHY THAT IS RIGHT: `hot` is entered three times — a fact the fixture PRINTS
/// — so "the previous time we were there" has three distinct correct answers
/// and stopping at the wrong one is detectable. The existing suite picks a pc
/// that occurs exactly ONCE, which makes any ordering error unobservable.
#[tokio::test]
async fn reverse_continue_walks_back_through_every_hot_entry_in_order() {
    let fx = fixture_or_skip!();
    let oracle = oracle_or_skip!(&fx);
    let entries: Vec<u64> = oracle
        .iter()
        .enumerate()
        .filter(|&(_, &pc)| pc == fx.hot)
        .map(|(k, _)| k as u64 + 1)
        .collect();
    let (_, loops) = fx.printed();
    assert_eq!(
        entries.len(),
        loops,
        "the fixture prints a loop count of {loops}; measured `hot` entries: {entries:?}"
    );

    let Some(backend) = recording_from_main(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    let mut sess = session_over(backend);
    sess.seek(TracePosition::new(oracle.len() as u64, 0)).expect("seek to the end");
    sess.add_reverse_breakpoint(fx.hot);

    let mut seen = Vec::new();
    for _ in 0..entries.len() {
        let st = sess.reverse_continue().expect("reverse_continue over a recorded trace");
        assert_eq!(
            st.pc, fx.hot,
            "reverse_continue stopped at {:#x}, not at the breakpoint {:#x} (`hot`, per `nm`)",
            st.pc, fx.hot
        );
        seen.push(st.position.sequence);
    }
    let mut want = entries.clone();
    want.reverse();
    assert_eq!(
        seen, want,
        "reverse_continue must visit `hot`'s entries newest-first at the sequences the separate \
         ptrace run measured"
    );
}

/// PROVES: `cold` — which the fixture never calls — is crossed ZERO times in
/// the independently measured sequence, and the replay agrees, while `hot` is
/// crossed three times in both.
///
/// WHY THIS IS A PAIR AND NOT A COUNT: `hot` = 3 and `cold` = 0 together are
/// reproduced by exactly one assignment of addresses to those two names.
/// Giving `cold` the address of `hot` — the mutation the falsification campaign
/// used — turns this red, while a test counting crossings of one function only
/// would survive it.
#[tokio::test]
async fn the_never_called_function_appears_nowhere_in_the_replay() {
    let fx = fixture_or_skip!();
    assert_ne!(fx.hot, fx.cold, "`nm` must give `hot` and `cold` distinct addresses");
    let (_, loops) = fx.printed();
    let oracle = oracle_or_skip!(&fx);
    assert_eq!(
        crossings(&oracle, &fx),
        (loops, 0),
        "the measured (hot, cold) crossing pair contradicts the fixture's printed loop count"
    );

    let Some(backend) = recording_from_main(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    let mut sess = session_over(backend);
    let mut replayed = Vec::new();
    for k in 1..=oracle.len() as u64 {
        replayed.push(sess.seek(TracePosition::new(k, 0)).expect("in-range seek").pc);
    }
    assert_eq!(
        crossings(&replayed, &fx),
        (loops, 0),
        "the replayed trace's (hot, cold) crossing pair differs from the one measured on a \
         separate process"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. The recorded REGISTERS, not just the pcs
// ═════════════════════════════════════════════════════════════════════════════

/// PROVES: the recording holds register state that tracks the program's own
/// arithmetic — `hot` adds 2 to the global per call, so the value it returns in
/// `eax` grows 2, 4, 6, ... across the calls, ending at the number the program
/// PRINTS. Both the series and its length come from stdout, not from a
/// literal.
///
/// WHY THAT IS RIGHT: every other test here constrains pcs only. A recorder
/// capturing correct pcs with a stale or shifted register map would pass all of
/// them. This one reads a value out of the historical register file, at a `ret`
/// address `objdump` chose, and compares the series with the program's stdout.
#[tokio::test]
async fn recorded_registers_reproduce_the_value_the_program_prints() {
    let fx = fixture_or_skip!();
    let oracle = oracle_or_skip!(&fx);
    // Where `hot` returns, per objdump — not per the recording.
    let hot_ret = fx.next_ret(fx.hot).expect("objdump must show a `ret` at or after `hot`");
    let (printed, loops) = fx.printed();
    assert!(
        oracle.iter().filter(|&&pc| pc == hot_ret).count() == loops,
        "`hot`'s `ret` at {hot_ret:#x} must be reached once per call; the measured sequence \
         reaches it {} times",
        oracle.iter().filter(|&&pc| pc == hot_ret).count()
    );

    let Some(backend) = recording_from_main(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    let mut sess = session_over(backend);

    let mut returns = Vec::new();
    for k in 1..=oracle.len() as u64 {
        let st = sess.seek(TracePosition::new(k, 0)).expect("in-range seek");
        if st.pc == hot_ret {
            returns.push(st.regs.get("rax").copied().unwrap_or(u64::MAX) & 0xffff_ffff);
        }
    }
    let expected: Vec<u64> = (1..=loops as u64).map(|i| 2 * i).collect();
    assert_eq!(
        returns, expected,
        "`hot` accumulates 2 per call over {loops} calls; the recorded rax disagrees"
    );
    assert_eq!(
        *returns.last().unwrap(),
        printed,
        "the last recorded return value must be the number the program printed"
    );
}

/// PROVES: nothing this suite launched is still alive.
///
/// WHY THAT IS RIGHT: a `panic!` skips the `kill` on the success path. `-x`
/// matches the process NAME exactly and can never match cargo's own
/// `live_linux_devac_reverse-<hash>` binary — the mistake `-f` made in a
/// sibling suite, where the checker reported itself as the orphan.
#[tokio::test]
async fn zz_no_orphan_fixture_processes_remain() {
    match Command::new("pgrep").args(["-x", "devacrev"]).output() {
        Ok(o) => {
            let listed: Vec<String> = String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect();
            assert!(listed.is_empty(), "orphaned `devacrev` process(es): {listed:?}");
        }
        Err(e) => eprintln!("[skip] pgrep unavailable: {e}"),
    }
}
