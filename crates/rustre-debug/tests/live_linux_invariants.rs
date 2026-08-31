//! Live coverage for `rustre_debug::live_invariant` — the layer behind the MCP
//! tools `debug.invariant_check` and `debug.invariant_check_write`.
//!
//! Every test here drives a REAL child process: a C fixture is compiled with
//! `cc -no-pie` into a tempdir, launched under `LinuxDebugger` (fork +
//! `PTRACE_TRACEME` + exec), a hardware write watchpoint is armed on a global,
//! and the trace is collected by reading the tracee's own memory and registers
//! at every stop. Nothing here fabricates a write log in memory — that kind of
//! test already exists in `src/live_invariant.rs` and cannot tell an engine
//! that fires at the right write from one that fires at the wrong one.
//!
//! The claims under test:
//!  * the violation is reported at EXACTLY the write that breaks the predicate,
//!    and at none of the writes before it;
//!  * the violation NAMES the instruction responsible (`writer_pc`), and the
//!    name is a real address inside the writing function;
//!  * an invariant the program never breaks yields no violation, without the
//!    green being vacuous (`checked_writes > 0` and `is_conclusive()`);
//!  * what `debug.invariant_check` can actually do with a live write log.
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::live_invariant::{InvariantEngine, InvariantOp, InvariantSpec};
use rustre_debug::omniscient_query::{MemoryWrite, OmniscientIndex};
use rustre_debug::{
    BreakpointKind, Debugger, LaunchOptions, OutputRedirect, StopReason, ThreadId,
};

// ── fixture ─────────────────────────────────────────────────────────────────

/// The invariant under test is `g_counter <= 100`.
///
/// `store()` is the only writer, so "the instruction responsible" has a name
/// that `nm` can resolve. The first four writes hold the invariant, the fifth
/// breaks it, the sixth holds again — so a checker that fires early, fires
/// late, or fires on every write is distinguishable from one that is right.
const FIXTURE: &str = "volatile long g_counter = 0;\n\
     __attribute__((noinline)) static void store(long v) { g_counter = v; }\n\
     int main(void) {\n\
     store(10); store(20); store(30); store(40);\n\
     store(1000);\n\
     store(50);\n\
     return 0;\n\
     }\n";

/// The values `FIXTURE` writes, in order — the external truth every assertion
/// in this file is measured against.
const EXPECTED_VALUES: [u64; 6] = [10, 20, 30, 40, 1000, 50];
/// Index (0-based) of the write that breaks `g_counter <= 100`.
const VIOLATING_INDEX: usize = 4;
/// The right-hand side of the invariant.
const BOUND: u64 = 100;

fn compile_fixture(dir: &std::path::Path, name: &str, source: &str) -> Option<std::path::PathBuf> {
    let src = dir.join(format!("{name}.c"));
    std::fs::write(&src, source).ok()?;
    let exe = dir.join(name);
    let out = std::process::Command::new("cc")
        .args(["-no-pie", "-O0", "-g"])
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(exe)
}

/// Absolute address of a symbol in a non-PIE executable, via `nm`.
fn symbol_addr(exe: &std::path::Path, symbol: &str) -> Option<u64> {
    let out = std::process::Command::new("nm").arg(exe).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.lines().find_map(|line| {
        let mut it = line.split_whitespace();
        let addr = it.next()?;
        let _kind = it.next()?;
        if it.next()? != symbol {
            return None;
        }
        u64::from_str_radix(addr, 16).ok()
    })
}

fn exe_launch(exe: &std::path::Path) -> LaunchOptions {
    LaunchOptions {
        executable: exe.to_string_lossy().into_owned(),
        args: Vec::new(),
        env: std::collections::HashMap::new(),
        working_dir: None,
        stop_at_entry: false,
        follow_forks: false,
        redirect: OutputRedirect::default(),
    }
}

/// One observed write: the value really in the tracee's memory at the stop,
/// plus the pc of the thread that stopped.
struct Observed {
    write: MemoryWrite,
    value: u64,
}

/// Run the fixture to completion under a write watchpoint on `g_counter`,
/// returning every write the hardware reported together with the value read
/// back out of the live process.
///
/// `None` means the toolchain is not usable here (no `cc`/`nm`), which is a
/// skip, not a failure. The fixture is killed on every path out.
async fn trace_fixture(dir: &std::path::Path) -> Option<(u64, u64, Vec<Observed>)> {
    let exe = compile_fixture(dir, "inv_fixture", FIXTURE)?;
    let sym = symbol_addr(&exe, "g_counter")?;
    let store = symbol_addr(&exe, "store")?;

    let dbg = LinuxDebugger::new();
    dbg.launch(exe_launch(&exe))
        .await
        .expect("launch the fixture");
    let armed = dbg
        .set_watchpoint_sized(Address(sym), BreakpointKind::DataWrite, 8)
        .await;
    if armed.is_err() {
        let _ = dbg.kill().await;
        panic!("arming an 8-byte write watchpoint on g_counter must succeed: {armed:?}");
    }

    let mut observed = Vec::new();
    let mut seq = 0u64;
    for _ in 0..256 {
        let ev = match dbg.continue_execution().await {
            Ok(ev) => ev,
            Err(_) => break,
        };
        match ev.reason {
            StopReason::ProcessExit { .. } => break,
            StopReason::Breakpoint { address, .. } if address.as_u64() == sym => {
                // The value must be read from the TRACEE, not assumed: that is
                // the whole difference between checking an invariant and
                // reciting the fixture's source back to itself.
                let bytes = match dbg.read_memory(Address(sym), 8).await {
                    Ok(b) if b.len() == 8 => b,
                    other => {
                        let _ = dbg.kill().await;
                        panic!("read_memory on the watched global must succeed at a stop: {other:?}");
                    }
                };
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes);
                let value = u64::from_le_bytes(buf);
                let pc = dbg.get_registers(ev.tid).await.ok().map(|r| r.pc);
                seq += 1;
                observed.push(Observed {
                    write: MemoryWrite {
                        sequence: seq,
                        address: Address(sym),
                        size: 8,
                        tid: ThreadId(ev.tid.0),
                        writer_pc: pc.map(Address),
                        source_address: None,
                    },
                    value,
                });
            }
            _ => {}
        }
    }
    let _ = dbg.kill().await;
    Some((sym, store, observed))
}

fn spec_at(addr: u64) -> InvariantSpec {
    InvariantSpec {
        name: "counter_bounded".to_string(),
        address: Address(addr),
        op: InvariantOp::Le,
        rhs: BOUND,
    }
}

fn values_by_sequence(observed: &[Observed]) -> std::collections::HashMap<u64, u64> {
    observed.iter().map(|o| (o.write.sequence, o.value)).collect()
}

fn index_of(observed: &[Observed]) -> OmniscientIndex {
    OmniscientIndex::from_writes(observed.iter().map(|o| o.write.clone()).collect::<Vec<_>>())
}

/// The trace must contain the fixture's writes, in order. Every test that
/// reasons about "the fifth write" first proves the trace it reasons about is
/// the fixture's — otherwise a backend reporting half the writes would make the
/// invariant assertions pass by accident.
fn assert_trace_matches_the_fixture(observed: &[Observed]) {
    let values: Vec<u64> = observed.iter().map(|o| o.value).collect();
    assert_eq!(
        values,
        EXPECTED_VALUES.to_vec(),
        "the watchpoint must report the fixture's six writes with the values the source stores"
    );
}

// ── tests ───────────────────────────────────────────────────────────────────

/// The central claim of `debug.invariant_check_write`: called on every live
/// watchpoint hit, it must fire at EXACTLY the write that breaks the predicate.
/// Not at the writes before it (a checker comparing against the wrong bound, or
/// firing on any change, would), and not never (a checker that never sees the
/// value would).
#[tokio::test]
async fn the_check_fires_at_the_violating_write_and_at_no_earlier_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some((sym, _store, observed)) = trace_fixture(dir.path()).await else {
        eprintln!("skipping: `cc -no-pie` / `nm` are not usable here");
        return;
    };
    assert_trace_matches_the_fixture(&observed);

    let engine = InvariantEngine::new(vec![spec_at(sym)]);
    let fired: Vec<usize> = observed
        .iter()
        .enumerate()
        .filter(|(_, o)| !engine.check_write(&o.write, o.value).is_empty())
        .map(|(i, _)| i)
        .collect();

    assert_eq!(
        fired,
        vec![VIOLATING_INDEX],
        "`g_counter <= {BOUND}` is broken by exactly one of the writes {EXPECTED_VALUES:?}; \
         the live checker fired at writes {fired:?}"
    );

    let v = engine.check_write(
        &observed[VIOLATING_INDEX].write,
        observed[VIOLATING_INDEX].value,
    );
    assert_eq!(v.len(), 1, "one broken invariant is one violation");
    assert_eq!(v[0].bad_value, EXPECTED_VALUES[VIOLATING_INDEX]);
    assert_eq!(v[0].address.as_u64(), sym);
    assert_eq!(v[0].invariant_name, "counter_bounded");
    assert!(
        v[0].expected.contains(&BOUND.to_string()),
        "the violation must quote the bound it was measured against, got {:?}",
        v[0].expected
    );
}

/// The offline entry point (`check_against_with`) over the SAME live trace must
/// reach the same verdict as the per-write one, and must name which write it
/// was: the sequence number, so the caller can seek back to it.
#[tokio::test]
async fn the_offline_scan_over_a_live_trace_names_the_violating_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some((sym, _store, observed)) = trace_fixture(dir.path()).await else {
        eprintln!("skipping: `cc -no-pie` / `nm` are not usable here");
        return;
    };
    assert_trace_matches_the_fixture(&observed);

    let values = values_by_sequence(&observed);
    let index = index_of(&observed);
    let engine = InvariantEngine::new(vec![spec_at(sym)]);
    let report = engine.check_against_with(&index, |w| values.get(&w.sequence).copied());

    assert_eq!(
        report.checked_writes,
        observed.len(),
        "with a value for every write, every write must be evaluated"
    );
    assert!(report.is_conclusive(), "no write may be skipped: {report:?}");
    assert_eq!(
        report.violations.len(),
        1,
        "exactly one of the fixture's writes breaks the bound, got {:?}",
        report.violations
    );
    let v = &report.violations[0];
    assert_eq!(
        v.write.sequence, observed[VIOLATING_INDEX].write.sequence,
        "the violation must point at the fifth write, not merely report that one exists"
    );
    assert_eq!(v.bad_value, EXPECTED_VALUES[VIOLATING_INDEX]);

    let summary = InvariantEngine::summarize(&report.violations);
    assert_eq!(summary["counter_bounded"].total_violations, 1);
    assert_eq!(
        summary["counter_bounded"].first_violation.bad_value,
        EXPECTED_VALUES[VIOLATING_INDEX]
    );
}

/// A violation is only actionable if it names the instruction responsible.
/// Measured against external truth: `nm` says where `store` begins, and the
/// only code that writes `g_counter` is inside it — so the pc carried by the
/// violation must land in that function's body.
#[tokio::test]
async fn the_violation_names_the_instruction_that_wrote_the_bad_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some((sym, store, observed)) = trace_fixture(dir.path()).await else {
        eprintln!("skipping: `cc -no-pie` / `nm` are not usable here");
        return;
    };
    assert_trace_matches_the_fixture(&observed);

    let engine = InvariantEngine::new(vec![spec_at(sym)]);
    let v = engine
        .check_write(
            &observed[VIOLATING_INDEX].write,
            observed[VIOLATING_INDEX].value,
        )
        .pop()
        .expect("the fifth write breaks the invariant");

    let pc = v
        .write
        .writer_pc
        .unwrap_or_else(|| panic!("the violation carries no instruction address: {v:?}"))
        .as_u64();
    assert_ne!(pc, 0, "a zero pc names nothing");
    // The trap is taken AFTER the storing instruction retires, so the reported
    // pc is the next instruction — still inside `store`, whose body is a few
    // dozen bytes at -O0.
    assert!(
        pc >= store && pc < store + 256,
        "the writing instruction must be inside `store` ({store:#x}..{:#x}); got {pc:#x}",
        store + 256
    );
    // And the four legal writes come from the same function, which is what
    // makes the pc a discriminator of WHICH write, not of which function.
    for (i, o) in observed.iter().enumerate() {
        let p = o.write.writer_pc.map_or(0, |a| a.as_u64());
        assert!(
            p >= store && p < store + 256,
            "write {i} reports pc {p:#x}, outside `store` ({store:#x})"
        );
    }
}

/// The false-positive side, which is the half a checker usually gets wrong:
/// an invariant the program never breaks must produce NO violation — and the
/// green must not be vacuous. `checked_writes` proves the engine looked at all
/// six writes, `is_conclusive` proves none was skipped for want of a value.
#[tokio::test]
async fn an_invariant_the_program_never_breaks_produces_no_violation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some((sym, _store, observed)) = trace_fixture(dir.path()).await else {
        eprintln!("skipping: `cc -no-pie` / `nm` are not usable here");
        return;
    };
    assert_trace_matches_the_fixture(&observed);

    // Three invariants the fixture honours at every single write.
    let specs = vec![
        InvariantSpec {
            name: "never_negative".into(),
            address: Address(sym),
            op: InvariantOp::Lt,
            rhs: 1u64 << 63,
        },
        InvariantSpec {
            name: "never_zero".into(),
            address: Address(sym),
            op: InvariantOp::NonZero,
            rhs: 0,
        },
        InvariantSpec {
            name: "under_a_million".into(),
            address: Address(sym),
            op: InvariantOp::Le,
            rhs: 1_000_000,
        },
    ];
    let engine = InvariantEngine::new(specs);

    for (i, o) in observed.iter().enumerate() {
        let violations = engine.check_write(&o.write, o.value);
        assert!(
            violations.is_empty(),
            "write {i} (value {}) breaks none of the three invariants, but the checker \
             reported {violations:?}",
            o.value
        );
    }

    let values = values_by_sequence(&observed);
    let index = index_of(&observed);
    let report = engine.check_against_with(&index, |w| values.get(&w.sequence).copied());
    assert!(
        report.violations.is_empty(),
        "no false positive: {:?}",
        report.violations
    );
    assert_eq!(
        report.checked_writes,
        observed.len() * 3,
        "three invariants over six writes is eighteen evaluations; a lower number means the \
         clean report is clean because nothing was looked at"
    );
    assert!(report.is_conclusive());
}

/// An invariant on an address the program never writes must also be silent —
/// and, more importantly, silent for the RIGHT reason. There is no write to
/// evaluate, so `checked_writes` is 0: a caller cannot read this as "the
/// invariant holds", only as "nothing happened there".
#[tokio::test]
async fn an_invariant_on_an_untouched_address_evaluates_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some((sym, _store, observed)) = trace_fixture(dir.path()).await else {
        eprintln!("skipping: `cc -no-pie` / `nm` are not usable here");
        return;
    };
    assert_trace_matches_the_fixture(&observed);

    let values = values_by_sequence(&observed);
    let index = index_of(&observed);
    // Same predicate, an address 4 KiB away that the fixture never touches.
    let engine = InvariantEngine::new(vec![spec_at(sym + 0x1000)]);
    let report = engine.check_against_with(&index, |w| values.get(&w.sequence).copied());

    assert!(report.violations.is_empty());
    assert_eq!(
        report.checked_writes, 0,
        "no write landed on that address, so no evaluation can have happened"
    );
    assert_eq!(report.unchecked_writes, 0);
}

/// THE GAP, measured on a live trace rather than argued.
///
/// `debug.invariant_check` (the MCP tool) receives a write LOG and calls
/// `check_against`, which has no source for the value each write stored. Fed
/// the very trace the tests above get a correct verdict from, it evaluates
/// nothing — the violation at write 5 is invisible.
///
/// | | verdict on the fixture |
/// |---|---|
/// | atteso (external truth: the source) | 1 violation, at the 5th write, value 1000 |
/// | raggiungibile con cio' che il crate ha gia' (`check_against_with` + live `read_memory`) | 1 violation, at the 5th write, value 1000 |
/// | ottenuto oggi da `debug.invariant_check` | 0 violations, 6 writes UNCHECKED |
///
/// This is not a defect in the engine: it reports the gap honestly
/// (`unchecked_writes = 6`, `is_conclusive() == false`) instead of inventing a
/// value, which it used to do. The gap is in the MCP surface — the write log
/// carries no values and has no field to put them in — and this test is what a
/// future `values` parameter has to turn green.
#[tokio::test]
async fn a_valueless_write_log_is_inconclusive_not_clean() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some((sym, _store, observed)) = trace_fixture(dir.path()).await else {
        eprintln!("skipping: `cc -no-pie` / `nm` are not usable here");
        return;
    };
    assert_trace_matches_the_fixture(&observed);

    let index = index_of(&observed);
    let report = InvariantEngine::new(vec![spec_at(sym)]).check_against(&index);

    assert!(
        report.violations.is_empty(),
        "without values nothing can be evaluated, so nothing may be reported as a violation"
    );
    assert_eq!(report.checked_writes, 0);
    assert_eq!(
        report.unchecked_writes,
        observed.len(),
        "every write of the live trace must be COUNTED as unchecked"
    );
    assert!(
        !report.is_conclusive(),
        "an empty violation list without values must never read as the invariant holding — \
         the fixture really does break it at write {VIOLATING_INDEX}"
    );
}

/// Nothing this file launches may outlive it. `trace_fixture` kills the tracee
/// on every path, including the panicking ones; this test asks the OS whether
/// that is true.
#[tokio::test]
async fn zzz_no_fixture_process_is_left_behind() {
    let out = std::process::Command::new("pgrep")
        // `-x` matches the process NAME exactly. `-f` would match any command
        // line CONTAINING the string — including the shell that launched the
        // test run, if the operator happened to type the fixture's name in it.
        // That self-match cost this test one false red before it was measured.
        .args(["-x", "inv_fixture"])
        .output();
    let Ok(out) = out else {
        eprintln!("skipping: pgrep unavailable");
        return;
    };
    let listed = String::from_utf8_lossy(&out.stdout);
    let mine = std::process::id().to_string();
    let orphans: Vec<&str> = listed
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && *l != mine)
        .collect();
    assert!(
        orphans.is_empty(),
        "the invariant fixtures must all be dead when the file finishes; pgrep still lists \
         {orphans:?}"
    );
}
