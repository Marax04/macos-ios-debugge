//! Live causal-analysis coverage for the Linux ptrace backend.
//!
//! Area: the causal/provenance surface — `who_wrote`, `trace_origin`,
//! `root_cause`, `rank_causal_contributions`, the `DataflowQuery` script tool,
//! and `address_timeline`.
//!
//! Every test here drives a REAL child process: a C fixture is compiled with
//! `cc -no-pie` into a tempdir, launched under `LinuxDebugger`, and a hardware
//! write watchpoint on a real global turns the program's three writes into
//! three observed stops. The `MemoryWrite` records the causal layer consumes
//! are built FROM THOSE STOPS (sequence = stop ordinal, `writer_pc` = the
//! tracee's own RIP read back with `get_registers`), never from a literal in
//! the test. The external ground truth is the source: `w_first`, then
//! `w_second`, then `w_third`, in that order and no other.
//!
//! ## The gap this file measures
//!
//! Nothing in the crate feeds a live session into the causal layer. Grepped
//! over `src/`: every construction of a `MemoryWrite` outside a `#[cfg(test)]`
//! module or a doc comment is zero — there is no recorder that turns ptrace
//! stops into an `OmniscientIndex`. `LiveScriptContext::new(dbg)` therefore
//! hands the causal tools an index that is permanently empty, and
//! `who_wrote`/`trace_origin`/`DataflowQuery` answer "nobody wrote it" about a
//! process that is, at that instant, stopped ON the write.
//!
//! | question | expected (external truth: the C source) | reachable with what the crate already has | obtained today |
//! |---|---|---|---|
//! | who wrote `g_target` first? | `w_first` | `w_first` — this file's `record_live_writes` builds the index from watchpoint stops in ~30 lines using only public API | `w_first` (green, `who_wrote_names_the_right_writer_at_each_instant`) |
//! | who wrote it, asked of a live session? | `w_first` | same | **empty vector** — `LiveScriptContext::new` starts with an empty index and no code path ever pushes to it (`a_live_session_answers_who_wrote_by_itself`, `#[ignore]`, measured red) |
//! | provenance chain of the value | 1+ hops, ending at an origin | 1 hop, `OriginEnd::Origin` | 1 hop — `source_address` is `None` on every live record, because a watchpoint stop reports WHERE, not FROM WHAT: chaining needs an instruction decode the backend does not do (`trace_origin_on_live_writes_is_one_hop_deep`) |
//!
//! `source_address` being unfillable is a property of the observation
//! mechanism, not a bug in `trace_origin`; the empty live index is a missing
//! cable. The two are separated on purpose.
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::causal_contribution::rank_causal_contributions;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::omniscient_query::{MemoryWrite, OmniscientIndex, OriginEnd};
use rustre_debug::root_cause_assistant::root_cause;
use rustre_debug::scripting_api::{dispatch, ScriptContext, ScriptRequest, ScriptResponse};
use rustre_debug::semantic_run_diff::address_timeline;
use rustre_debug::time_travel_debug::SnapshotReplayBackend;
use rustre_debug::{
    BreakpointKind, Debugger, LaunchOptions, OutputRedirect, StopReason, ThreadId,
};

// ── fixtures ────────────────────────────────────────────────────────────────

/// Three writers, in a known order, each followed by a `nop` so the address
/// reported after the store still lies inside the writing function (an x86
/// data watchpoint traps AFTER the instruction that wrote).
const THREE_WRITERS: &str = "volatile long g_target = 0;\n\
     void w_first(void)  { g_target = 111; __asm__ volatile(\"nop\"); }\n\
     void w_second(void) { g_target = 222; __asm__ volatile(\"nop\"); }\n\
     void w_third(void)  { g_target = 333; __asm__ volatile(\"nop\"); }\n\
     volatile long g_seen = 0;\n\
     int main(void) {\n\
     w_first(); w_second(); w_third();\n\
     g_seen = g_target;\n\
     return (int)(g_seen & 1);\n\
     }\n";

/// Same program with the THIRD writer never called — the "good baseline" run
/// for the root-cause comparison.
const TWO_WRITERS: &str = "volatile long g_target = 0;\n\
     void w_first(void)  { g_target = 111; __asm__ volatile(\"nop\"); }\n\
     void w_second(void) { g_target = 222; __asm__ volatile(\"nop\"); }\n\
     void w_third(void)  { g_target = 333; __asm__ volatile(\"nop\"); }\n\
     volatile long g_seen = 0;\n\
     int main(void) {\n\
     w_first(); w_second();\n\
     g_seen = g_target;\n\
     return (int)(g_seen & 1);\n\
     }\n";

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

/// `(address, name)` for every symbol `nm` reports, sorted by address.
fn symbol_table(exe: &std::path::Path) -> Vec<(u64, String)> {
    let Ok(out) = std::process::Command::new("nm").arg(exe).output() else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut syms: Vec<(u64, String)> = text
        .lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let addr = u64::from_str_radix(it.next()?, 16).ok()?;
            let kind = it.next()?;
            let name = it.next()?;
            // Text symbols only: a data symbol sitting numerically below a PC
            // would win the "greatest address <= pc" search and name the wrong
            // thing.
            if kind == "t" || kind == "T" {
                Some((addr, name.to_string()))
            } else {
                None
            }
        })
        .collect();
    syms.sort_unstable();
    syms
}

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

/// Name of the function containing `pc`: the greatest text symbol at or below
/// it.
fn function_of(syms: &[(u64, String)], pc: u64) -> String {
    syms.iter()
        .rev()
        .find(|(a, _)| *a <= pc)
        .map_or_else(|| format!("<unmapped {pc:#x}>"), |(_, n)| n.clone())
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

/// What one live recording produced.
struct LiveRecording {
    /// The writes, in the order the process performed them, sequence numbers
    /// starting at 1 (so `at_time = 0` means "before anything happened").
    writes: Vec<MemoryWrite>,
    /// Function name for each write, resolved from the tracee's own RIP.
    writers: Vec<String>,
    /// Address of `g_target` in the launched image.
    target: u64,
}

impl LiveRecording {
    fn index(&self) -> OmniscientIndex {
        OmniscientIndex::from_writes(self.writes.clone())
    }
}

/// Run `exe` under ptrace with a write watchpoint on `g_target`, and turn every
/// resulting stop into a `MemoryWrite`. This is the piece the crate does not
/// have: it uses ONLY public backend API, which is what makes the missing cable
/// a missing cable rather than a missing capability.
///
/// Returns `None` when the toolchain is unusable here, so the tests skip
/// instead of failing for an unrelated reason.
async fn record_live_writes(exe: &std::path::Path) -> Option<LiveRecording> {
    let target = symbol_addr(exe, "g_target")?;
    let syms = symbol_table(exe);

    let dbg = LinuxDebugger::new();
    let pid = dbg.launch(exe_launch(exe)).await.ok()?;
    let tid = ThreadId(pid.0);

    if dbg
        .set_watchpoint_sized(Address(target), BreakpointKind::DataWrite, 8)
        .await
        .is_err()
    {
        let _ = dbg.kill().await;
        return None;
    }

    let mut writes = Vec::new();
    let mut writers = Vec::new();
    for _ in 0..64 {
        let Ok(ev) = dbg.continue_execution().await else { break };
        match ev.reason {
            StopReason::ProcessExit { .. } => break,
            StopReason::Breakpoint { address, .. } if address.as_u64() == target => {
                // The PC is read out of the LIVE process; nothing here is a
                // constant from the test.
                let pc = dbg.get_registers(tid).await.ok().map(|r| r.pc);
                let seq = writes.len() as u64 + 1;
                writes.push(MemoryWrite {
                    sequence: seq,
                    address: Address(target),
                    size: 8,
                    tid,
                    writer_pc: pc.map(Address),
                    // A watchpoint stop says WHERE the value landed, never what
                    // it was copied from — see the module header.
                    source_address: None,
                });
                writers.push(pc.map_or_else(
                    || "<no pc>".to_string(),
                    |p| function_of(&syms, p),
                ));
            }
            _ => {}
        }
    }
    // Kill on every path, including the ones above that returned early.
    let _ = dbg.kill().await;
    Some(LiveRecording { writes, writers, target })
}

/// Compile + record in one step, or `None` to skip.
async fn record(dir: &std::path::Path, name: &str, source: &str) -> Option<LiveRecording> {
    let exe = compile_fixture(dir, name, source)?;
    record_live_writes(&exe).await
}

macro_rules! rec_or_skip {
    ($dir:expr, $name:expr, $src:expr) => {
        match record($dir.path(), $name, $src).await {
            Some(r) if r.writes.len() >= 2 => r,
            _ => {
                eprintln!("skipping: cc/nm/ptrace watchpoints are not usable here");
                return;
            }
        }
    };
}

// ── the recording itself ────────────────────────────────────────────────────

/// The premise every other test rests on: the three writes are observed, in the
/// order the source performs them, and each is attributed to the right
/// function. If this is wrong, nothing below means anything.
#[tokio::test]
async fn the_three_writes_are_observed_in_source_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let r = rec_or_skip!(dir, "causal3", THREE_WRITERS);

    assert_eq!(
        r.writers,
        vec!["w_first", "w_second", "w_third"],
        "the source writes g_target from w_first, then w_second, then w_third; \
         the recording says {:?}",
        r.writers
    );
    assert_eq!(
        r.writes.iter().map(|w| w.sequence).collect::<Vec<_>>(),
        vec![1, 2, 3],
        "sequence numbers must be the real stop order"
    );
    assert!(
        r.writes.iter().all(|w| w.address.as_u64() == r.target),
        "every recorded write must be to g_target itself"
    );
}

/// Every recorded PC must be a real address inside the tracee's text, not a
/// zero left behind by a failed register read. A recording of three `None` PCs
/// would satisfy "three writes were seen" and attribute none of them.
#[tokio::test]
async fn every_recorded_write_carries_a_real_writer_pc() {
    let dir = tempfile::tempdir().expect("tempdir");
    let r = rec_or_skip!(dir, "causal_pc", THREE_WRITERS);

    for w in &r.writes {
        let pc = w.writer_pc.expect("a live watchpoint stop must have a readable PC").as_u64();
        assert!(pc > 0x1000, "PC {pc:#x} is not a plausible text address");
    }
    let distinct: std::collections::BTreeSet<u64> =
        r.writes.iter().filter_map(|w| w.writer_pc.map(|p| p.as_u64())).collect();
    assert_eq!(
        distinct.len(),
        r.writes.len(),
        "three different functions wrote the global, so the three PCs must differ"
    );
}

// ── who_wrote ───────────────────────────────────────────────────────────────

/// The headline query, asked at each instant. At time 1 only `w_first` has run;
/// at 2 the most recent writer is `w_second`; at 3 it is `w_third`.
#[tokio::test]
async fn who_wrote_names_the_right_writer_at_each_instant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let r = rec_or_skip!(dir, "causal_who", THREE_WRITERS);
    let idx = r.index();
    let syms = symbol_table(&dir.path().join("causal_who"));

    for (at_time, expected) in [(1u64, "w_first"), (2, "w_second"), (3, "w_third")] {
        let hits = idx.who_wrote(Address(r.target), at_time);
        assert_eq!(
            hits.len() as u64,
            at_time,
            "at t={at_time} exactly {at_time} writes have happened"
        );
        let top = hits[0].writer_pc.expect("writer pc").as_u64();
        assert_eq!(
            function_of(&syms, top),
            expected,
            "at t={at_time} the most recent writer of g_target is {expected}"
        );
    }
}

/// Before the first write, nobody wrote it — and the honest answer is an empty
/// vector, not "the earliest write we know of".
#[tokio::test]
async fn who_wrote_is_empty_before_the_first_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let r = rec_or_skip!(dir, "causal_pre", THREE_WRITERS);
    assert!(
        r.index().who_wrote(Address(r.target), 0).is_empty(),
        "no write has sequence 0, so t=0 must name nobody"
    );
}

/// Ordering contract: most-recent-first. A caller that reads element 0 as "the
/// instruction that produced this value" gets `w_third`, the last writer.
#[tokio::test]
async fn who_wrote_returns_most_recent_first() {
    let dir = tempfile::tempdir().expect("tempdir");
    let r = rec_or_skip!(dir, "causal_order", THREE_WRITERS);
    let idx = r.index();
    let syms = symbol_table(&dir.path().join("causal_order"));

    let names: Vec<String> = idx
        .who_wrote(Address(r.target), u64::MAX)
        .iter()
        .map(|w| function_of(&syms, w.writer_pc.expect("pc").as_u64()))
        .collect();
    assert_eq!(names, vec!["w_third", "w_second", "w_first"]);

    let last = idx.last_writer(Address(r.target), u64::MAX).expect("a last writer");
    assert_eq!(function_of(&syms, last.writer_pc.expect("pc").as_u64()), "w_third");
}

/// An address nothing in the program writes must not be attributed to the
/// writers of the neighbouring one. `g_seen` lives next to `g_target`; only
/// `main` touches it, and the watchpoint never covered it.
#[tokio::test]
async fn who_wrote_does_not_attribute_a_neighbouring_address() {
    let dir = tempfile::tempdir().expect("tempdir");
    let r = rec_or_skip!(dir, "causal_neigh", THREE_WRITERS);
    let Some(other) = symbol_addr(&dir.path().join("causal_neigh"), "g_seen") else {
        eprintln!("skipping: nm did not report g_seen");
        return;
    };
    assert_ne!(other, r.target);
    assert!(
        r.index().who_wrote(Address(other), u64::MAX).is_empty(),
        "g_seen ({other:#x}) was never watched, so no write may be attributed to it"
    );
}

// ── address_timeline ────────────────────────────────────────────────────────

/// `address_timeline` must list the writes in the order they really happened —
/// oldest first, one row per write — even though `who_wrote` underneath it
/// answers newest-first.
#[tokio::test]
async fn address_timeline_lists_the_writes_in_real_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let r = rec_or_skip!(dir, "causal_tl", THREE_WRITERS);
    let idx = r.index();
    let syms = symbol_table(&dir.path().join("causal_tl"));

    let rows = address_timeline(Address(r.target), &idx, &idx);
    assert_eq!(rows.len(), 3, "three writes, three rows");
    let order: Vec<String> = rows
        .iter()
        .map(|row| {
            let w = row.run_a.as_ref().expect("run A write");
            function_of(&syms, w.writer_pc.expect("pc").as_u64())
        })
        .collect();
    assert_eq!(order, vec!["w_first", "w_second", "w_third"]);
    assert_eq!(
        rows.iter().map(|row| row.ordinal).collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert!(
        rows.iter().all(|row| !row.diverges),
        "a trace compared with itself cannot diverge"
    );
}

/// Two independent LIVE runs of the same binary must produce the same timeline.
/// This is the control: it proves the recording is a property of the program,
/// not of the run.
#[tokio::test]
async fn two_live_runs_of_the_same_binary_agree() {
    let dir = tempfile::tempdir().expect("tempdir");
    let exe = match compile_fixture(dir.path(), "causal_twice", THREE_WRITERS) {
        Some(e) => e,
        None => {
            eprintln!("skipping: cc unusable");
            return;
        }
    };
    let (Some(a), Some(b)) = (
        record_live_writes(&exe).await,
        record_live_writes(&exe).await,
    ) else {
        eprintln!("skipping: ptrace watchpoints unusable here");
        return;
    };
    if a.writes.len() < 3 {
        eprintln!("skipping: watchpoint did not report the writes");
        return;
    }
    assert_eq!(a.writers, b.writers, "two runs of one binary must write from the same places");
    let rows = address_timeline(Address(a.target), &a.index(), &b.index());
    assert!(
        rows.iter().all(|r| !r.diverges),
        "two runs of the same non-PIE binary must not diverge"
    );
}

/// A run that skips the third writer must diverge from the full run at exactly
/// the third row, and that row must be one-sided.
#[tokio::test]
async fn address_timeline_finds_the_missing_third_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let full = rec_or_skip!(dir, "causal_full", THREE_WRITERS);
    let short = rec_or_skip!(dir, "causal_short", TWO_WRITERS);
    if full.writes.len() != 3 || short.writes.len() != 2 {
        eprintln!("skipping: expected 3 and 2 writes, got {} and {}", full.writes.len(), short.writes.len());
        return;
    }

    let rows = address_timeline(Address(full.target), &full.index(), &short.index());
    assert_eq!(rows.len(), 3, "the longer run decides the row count");
    assert!(!rows[0].diverges && !rows[1].diverges, "the first two writes match");
    assert!(rows[2].diverges, "the third write exists only in the full run");
    assert!(rows[2].run_a.is_some() && rows[2].run_b.is_none());
}

// ── trace_origin ────────────────────────────────────────────────────────────

/// Measured contract of a watchpoint-sourced trace: the provenance walk is one
/// hop deep and terminates as `Origin`, because a data watchpoint reports the
/// destination of a store and never its source. That is a limit of the
/// OBSERVATION, not of `trace_origin` — the walk does the right thing with what
/// it is given, and says so via `OriginEnd::Origin`.
#[tokio::test]
async fn trace_origin_on_live_writes_is_one_hop_deep() {
    let dir = tempfile::tempdir().expect("tempdir");
    let r = rec_or_skip!(dir, "causal_org", THREE_WRITERS);
    let idx = r.index();
    let syms = symbol_table(&dir.path().join("causal_org"));

    let trace = idx.trace_origin_full(Address(r.target), u64::MAX);
    assert_eq!(trace.end, OriginEnd::Origin, "the last hop has no source, so the walk ends cleanly");
    assert!(trace.reached_origin());
    assert_eq!(trace.hops.len(), 1, "no live record carries a source_address, so no chain exists");
    assert_eq!(
        function_of(&syms, trace.hops[0].write.writer_pc.expect("pc").as_u64()),
        "w_third",
        "the one hop must be the most recent writer"
    );
    assert!(
        r.writes.iter().all(|w| w.source_address.is_none()),
        "documenting the cause: a watchpoint stop cannot fill source_address"
    );
}

/// Asked before any write exists, the walk must report `NoEarlierWriter` — not
/// an empty `Origin`, which would read as "the value has no cause" instead of
/// "I have no history".
#[tokio::test]
async fn trace_origin_before_the_first_write_says_no_earlier_writer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let r = rec_or_skip!(dir, "causal_org0", THREE_WRITERS);
    let trace = r.index().trace_origin_full(Address(r.target), 0);
    assert!(trace.hops.is_empty());
    assert_eq!(trace.end, OriginEnd::NoEarlierWriter);
    assert!(!trace.reached_origin());
}

// ── root_cause / contribution ranking ───────────────────────────────────────

/// The bad run writes `g_target` from three places; the good baseline only from
/// two. The writer present in one and absent from the other must be the top
/// suspect — and both runs are real processes, not fabricated indexes.
#[tokio::test]
async fn root_cause_ranks_the_writer_absent_from_the_good_run_first() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bad = rec_or_skip!(dir, "rc_bad", THREE_WRITERS);
    let good = rec_or_skip!(dir, "rc_good", TWO_WRITERS);
    if bad.writes.len() != 3 || good.writes.len() != 2 {
        eprintln!("skipping: expected 3 and 2 writes");
        return;
    }
    // Two separately compiled binaries would place the writers at different
    // addresses; the comparison is only meaningful if they line up. Both are
    // -no-pie builds of near-identical sources, so check rather than assume.
    let bad_syms = symbol_table(&dir.path().join("rc_bad"));
    let good_syms = symbol_table(&dir.path().join("rc_good"));
    let same_layout = ["w_first", "w_second", "w_third"].iter().all(|n| {
        let a = bad_syms.iter().find(|(_, s)| s == n).map(|(a, _)| *a);
        let b = good_syms.iter().find(|(_, s)| s == n).map(|(a, _)| *a);
        a.is_some() && a == b
    });
    if !same_layout || bad.target != good.target {
        eprintln!("skipping: the two fixtures did not land at matching addresses");
        return;
    }

    let report = root_cause(&bad.index(), Address(bad.target), u64::MAX, &good.index());
    let top = report.top_suspect().expect("a top suspect");
    assert_eq!(
        function_of(&bad_syms, top.pc.as_u64()),
        "w_third",
        "w_third writes g_target in the bad run and never in the good one"
    );
    assert_eq!(top.good_hits, 0, "the top suspect must be unseen in the baseline");
    assert!(report.has_clean_origin(), "the slice ends at a write with no source");
    assert_eq!(report.causal_slice.len(), 1);
}

/// Contribution ranking over a live slice: one hop, so it holds the whole
/// blame, it is the root, and the normalised score is exactly 1.
#[tokio::test]
async fn causal_contribution_rank_over_a_live_slice() {
    let dir = tempfile::tempdir().expect("tempdir");
    let r = rec_or_skip!(dir, "causal_rank", THREE_WRITERS);
    let syms = symbol_table(&dir.path().join("causal_rank"));

    let report = rank_causal_contributions(&r.index(), Address(r.target), u64::MAX, 32);
    assert_eq!(report.chain_length, 1);
    assert!(report.chain_complete, "a one-hop chain ending at an origin is complete");
    assert!(!report.truncated);
    let top = report.ranked.first().expect("a ranked entry");
    assert!(top.is_root);
    assert!(
        (top.contribution - 1.0).abs() < 1e-9,
        "a single hop carries all the blame, got {}",
        top.contribution
    );
    assert_eq!(
        function_of(&syms, top.hop.write.writer_pc.expect("pc").as_u64()),
        "w_third"
    );
}

// ── the scripting surface ───────────────────────────────────────────────────

/// `WhoWrote`, `TraceOrigin` and `DataflowQuery` driven through `dispatch` over
/// a `LiveScriptContext` seeded with the live recording — the path an agent
/// actually takes.
#[tokio::test]
async fn the_script_tools_answer_from_a_live_recording() {
    let dir = tempfile::tempdir().expect("tempdir");
    let r = rec_or_skip!(dir, "causal_script", THREE_WRITERS);
    let syms = symbol_table(&dir.path().join("causal_script"));

    let dbg = LinuxDebugger::new();
    let mut ctx = rustre_debug::live_script_context::LiveScriptContext::new_with_trace(
        &dbg,
        r.index(),
        SnapshotReplayBackend::new(),
    );

    let resp = dispatch(&mut ctx, ScriptRequest::WhoWrote { address: r.target, at_time: 1 })
        .expect("WhoWrote must succeed");
    let ScriptResponse::Writers { writes, .. } = resp else { panic!("wrong variant") };
    assert_eq!(writes.len(), 1);
    assert_eq!(function_of(&syms, writes[0].writer_pc.expect("pc").as_u64()), "w_first");

    let q = format!("FIND WRITES TO {:#x} BEFORE 3", r.target);
    let resp = dispatch(&mut ctx, ScriptRequest::DataflowQuery { query: q })
        .expect("DataflowQuery must succeed");
    let ScriptResponse::Writers { writes, .. } = resp else { panic!("wrong variant") };
    assert_eq!(writes.len(), 3, "all three writes are at or before sequence 3");
    assert_eq!(
        function_of(&syms, writes[0].writer_pc.expect("pc").as_u64()),
        "w_third",
        "the DSL inherits who_wrote's most-recent-first order"
    );

    let q = format!("TRACE {:#x} BACKWARD", r.target);
    let resp = dispatch(&mut ctx, ScriptRequest::DataflowQuery { query: q })
        .expect("TRACE must succeed");
    let ScriptResponse::Origin { hops, .. } = resp else { panic!("wrong variant") };
    assert_eq!(hops.len(), 1);
}

// ── the measured gap ────────────────────────────────────────────────────────

/// PINS the current behaviour: a `LiveScriptContext` built the ordinary way
/// over a real, attached, stopped-on-the-write process answers `who_wrote` with
/// an empty vector. Green today; it is the "obtained" column of the table in
/// the module header, and it will go red the day someone cables a live
/// recorder in — which is the point.
#[tokio::test]
async fn a_plain_live_session_has_no_causal_data_at_all() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(exe) = compile_fixture(dir.path(), "gap_pin", THREE_WRITERS) else {
        eprintln!("skipping: cc unusable");
        return;
    };
    let Some(target) = symbol_addr(&exe, "g_target") else { return };

    let dbg = LinuxDebugger::new();
    let Ok(pid) = dbg.launch(exe_launch(&exe)).await else {
        eprintln!("skipping: launch failed");
        return;
    };
    if dbg
        .set_watchpoint_sized(Address(target), BreakpointKind::DataWrite, 8)
        .await
        .is_err()
    {
        let _ = dbg.kill().await;
        return;
    }
    // Run until the process is stopped ON a write to g_target.
    let mut on_the_write = false;
    for _ in 0..64 {
        let Ok(ev) = dbg.continue_execution().await else { break };
        match ev.reason {
            StopReason::ProcessExit { .. } => break,
            StopReason::Breakpoint { address, .. } if address.as_u64() == target => {
                on_the_write = true;
                break;
            }
            _ => {}
        }
    }
    if !on_the_write {
        let _ = dbg.kill().await;
        eprintln!("skipping: the watchpoint never reported a write");
        return;
    }
    assert!(dbg.is_attached(), "still attached to {pid:?}");

    let ctx = rustre_debug::live_script_context::LiveScriptContext::new(&dbg);
    let writers = ctx.who_wrote(target, u64::MAX).len();
    let hops = ctx.trace_origin(target, u64::MAX).len();
    // Kill BEFORE asserting, on purpose. An assertion that fires while a tracee
    // is still attached leaves that tracee stopped AND leaves this debugger's
    // reader thread alive inside the same test binary; because the backend
    // reaps with `waitpid(-1)`, that leaked thread then steals the events of
    // the NEXT test's tracee and the whole file hangs. Measured: mutating this
    // very assertion during falsification hung every test that ran after it.
    let _ = dbg.kill().await;
    assert_eq!(
        writers, 0,
        "MEASURED: a live session answers who_wrote with nothing, while stopped on the write"
    );
    assert_eq!(hops, 0, "MEASURED: same for trace_origin");
}

/// The same situation, asserted the way it SHOULD answer. Measured red, kept
/// `#[ignore]` because the fix is a backend/wiring change (a recorder that
/// pushes ptrace stops into the session's `OmniscientIndex`), not a test bug.
///
/// Expected: one writer, `w_first`. Obtained: an empty vector — the assertion
/// below fails on `left: 0, right: 1`.
#[tokio::test]
#[ignore = "no code path feeds a live session's OmniscientIndex: who_wrote is always empty"]
async fn a_live_session_answers_who_wrote_by_itself() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(exe) = compile_fixture(dir.path(), "gap_red", THREE_WRITERS) else { return };
    let Some(target) = symbol_addr(&exe, "g_target") else { return };

    let dbg = LinuxDebugger::new();
    let Ok(_pid) = dbg.launch(exe_launch(&exe)).await else { return };
    if dbg
        .set_watchpoint_sized(Address(target), BreakpointKind::DataWrite, 8)
        .await
        .is_err()
    {
        let _ = dbg.kill().await;
        return;
    }
    for _ in 0..64 {
        let Ok(ev) = dbg.continue_execution().await else { break };
        match ev.reason {
            StopReason::ProcessExit { .. } => break,
            StopReason::Breakpoint { address, .. } if address.as_u64() == target => break,
            _ => {}
        }
    }

    let ctx = rustre_debug::live_script_context::LiveScriptContext::new(&dbg);
    let writers = ctx.who_wrote(target, u64::MAX);
    let n = writers.len();
    let _ = dbg.kill().await;
    assert_eq!(
        n, 1,
        "the process is stopped on the very write to g_target ({target:#x}); a live \
         session must be able to name w_first as its writer"
    );
}

// ── hygiene ─────────────────────────────────────────────────────────────────

/// No fixture may outlive its test. Every recording above kills its tracee on
/// every path; this checks the result with `pgrep`, because a leaked stopped
/// tracee is invisible to every other assertion in the file.
#[tokio::test]
async fn no_fixture_process_is_left_behind() {
    // Give any just-reaped child a moment to disappear from the process table.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    for name in [
        "causal3", "causal_pc", "causal_who", "causal_pre", "causal_order", "causal_neigh",
        "causal_tl", "causal_twice", "causal_full", "causal_short", "causal_org", "causal_org0",
        "rc_bad", "rc_good", "causal_rank", "causal_script", "gap_pin", "gap_red",
    ] {
        let out = std::process::Command::new("pgrep")
            .arg("-x")
            .arg(name)
            .output()
            .expect("pgrep must be available");
        let pids = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert!(
            pids.is_empty(),
            "fixture {name} is still running as pid(s) {pids} — a test leaked a tracee"
        );
    }
}
