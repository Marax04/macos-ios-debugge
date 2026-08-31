//! Live-process coverage for tracepoints and conditional breakpoints evaluated
//! against a REAL process that crosses the same address five times.
//!
//! Everything here drives a fixture compiled on the fly with `cc -no-pie -O0`
//! and launched under `ptrace`. `-no-pie` makes the binary `ET_EXEC`, so the
//! address `nm` prints for `trace_me` / `g_iter` IS the address it occupies at
//! run time, and both a code breakpoint and a `mem4[…]` condition can be aimed
//! without a symbol backend.
//!
//! What is under test, and why a live process is required:
//!
//! * A tracepoint message is only interesting if its operands are resolved
//!   from state that CHANGES. Rendered against a `MapEvalContext` the caller
//!   filled in itself, `TracepointFormat::render` can only ever hand back what
//!   the test already wrote. Here the argument register and `g_iter` carry a
//!   different value on each of the five crossings, so a renderer that resolved
//!   once and cached, or that read a stale register snapshot, produces five
//!   identical messages and is caught.
//! * A condition is only interesting if it is false on some crossings and true
//!   on another. `rdi == 22` and `mem4[&g_iter] == 3` are both true only on the
//!   fourth pass, which no single-hit test can distinguish from "always true".
//! * A tracepoint that "does not stop the process" can only be demonstrated by
//!   a process that actually runs to completion.
//! * A tracepoint on an address the program never executes must produce NO
//!   output. This is the invented-answer check: `never_called` is compiled and
//!   linked (so the address is real and a trap can be planted there) but is
//!   guarded by a condition that never holds.
//!
//! ── MEASURED GAP: tracepoints have no entry point in the `Debugger` trait ──
//!
//! `conditional_breakpoint::{Tracepoint, TracepointFormat, TracepointSet}`
//! implement the dprintf semantics completely, and the Linux backend evaluates
//! breakpoint CONDITIONS live (`set_breakpoint_condition` → `condition_allows_stop`),
//! but nothing connects the two: there is no `set_tracepoint`, and `TracepointSet`
//! is referenced by no backend. Measured, not assumed:
//!
//! ```text
//! $ grep -rn "TracepointSet" crates/rustre-debug/src --include=*.rs | grep -v conditional_breakpoint.rs
//! (no output)
//! $ grep -c "async fn set_breakpoint_condition" crates/rustre-debug/src/linux_debugger.rs
//! 1
//! $ grep -ci "tracepoint" crates/rustre-debug/src/linux_debugger.rs
//! 0
//! ```
//!
//! | | expected (gdb `dprintf`, external truth) | reachable with what the crate already has | obtained today |
//! |---|---|---|---|
//! | user-visible call to arm one | `dprintf trace_me,"x=%d\n",x` — one command | none: the caller must `set_breakpoint`, then hand-roll the fire-and-continue loop these tests contain | hand-rolled loop, ~25 lines per call site |
//! | stops of the tracee for 5 crossings | 0 (gdb resumes internally; the user is never handed a stop) | 5 — every crossing is a real `SIGTRAP` delivered to the caller | **5**, asserted by `the_tracepoint_contract_is_non_stopping_but_the_backend_stops_five_times` |
//! | message rendering from live state | correct | correct — `TracepointFormat::render` over a per-hit context works | correct, 5/5 distinct messages |
//! | conditions on a tracepoint | evaluated by the debugger | evaluated by the CALLER via `Tracepoint::fire` | correct |
//!
//! So the missing piece is the WIRING, not the logic: every assertion below
//! passes, and every one of them had to drive the stop loop by hand. A cure is
//! a `set_tracepoint(addr, format)` on the trait plus a branch in
//! `condition_allows_stop` that fires the set and returns `false` (never stop),
//! which is the one place that already holds the registers and the memory
//! reader a render needs.
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::conditional_breakpoint::{
    BreakpointCondition, ConditionOperand, EvalContext, MapEvalContext, Tracepoint,
    TracepointFormat, TracepointSet, memory_operands,
};
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::{
    BreakpointKind, DebugEvent, Debugger, LaunchOptions, OutputRedirect, StopReason, ThreadId,
};

/// The first integer-argument register on this host. A breakpoint planted on a
/// function's ENTRY address stops before the prologue, so this still holds the
/// caller's argument — which is what makes it a moving target across the five
/// crossings.
#[cfg(target_arch = "x86_64")]
const ARG_REG: &str = "rdi";
#[cfg(target_arch = "aarch64")]
const ARG_REG: &str = "x0";

/// The arguments `main` passes to `trace_me`, in order. Ground truth read off
/// the fixture source below (`i * 7 + 1` for `i` in `0..5`), NOT off the
/// debugger — otherwise the tests would be checking the debugger against
/// itself.
const EXPECTED_ARGS: [u64; 5] = [1, 8, 15, 22, 29];

/// The pass on which the interesting conditions become true (0-based), and the
/// argument seen on that pass.
const TARGET_PASS: u64 = 3;
const TARGET_ARG: u64 = EXPECTED_ARGS[TARGET_PASS as usize];

/// The C fixture.
///
/// `trace_me` is called exactly five times with a different argument each
/// time, and `g_iter` is written with the pass index immediately before each
/// call — so at the moment the breakpoint fires, `mem4[&g_iter]` and the
/// argument register are two independent witnesses of the same pass number.
///
/// `never_called` is compiled, linked and reachable in the CFG (so its address
/// is real and a trap can be planted there) but its guard is never true, so it
/// never executes. It is the target of the invented-output check.
const FIXTURE_C: &str = r#"
#include <stdio.h>
volatile int g_iter = -1;
volatile long g_sum = 0;
__attribute__((noinline)) int trace_me(int x) { g_sum += x; return x + 1; }
__attribute__((noinline)) int never_called(int x) { return x - 1; }
int main(void) {
    int s = 0;
    for (int i = 0; i < 5; i++) { g_iter = i; s += trace_me(i * 7 + 1); }
    if (s == 0x7ffffff0) { s = never_called(s); }
    printf("%d %ld\n", s, (long) g_sum);
    return 0;
}
"#;

struct Fixture {
    _dir: tempfile::TempDir,
    exe: String,
    trace_me: u64,
    never_called: u64,
    g_iter: u64,
}

fn build_fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("tp_fixture.c");
    let exe = dir.path().join("tp_fixture");
    std::fs::write(&src, FIXTURE_C).expect("write fixture source");
    let out = std::process::Command::new("cc")
        .args(["-no-pie", "-O0", "-g"])
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .output()
        .expect("cc must be available to run the live tracepoint tests");
    assert!(
        out.status.success(),
        "cc failed to build the fixture: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let nm = std::process::Command::new("nm").arg(&exe).output().expect("nm");
    assert!(nm.status.success(), "nm failed on the fixture binary");
    let listing = String::from_utf8_lossy(&nm.stdout).to_string();
    Fixture {
        _dir: dir,
        exe: exe.to_string_lossy().to_string(),
        trace_me: sym(&listing, "trace_me"),
        never_called: sym(&listing, "never_called"),
        g_iter: sym(&listing, "g_iter"),
    }
}

/// Resolve a symbol out of an `nm` listing. Any kind is accepted: `trace_me`
/// is `T` while `g_iter` is a data symbol, and hard-coding a kind would
/// silently resolve nothing for one of them.
fn sym(nm_listing: &str, want: &str) -> u64 {
    for line in nm_listing.lines() {
        let mut parts = line.split_whitespace();
        let Some(addr) = parts.next() else { continue };
        if parts.next().is_none() {
            continue;
        }
        if parts.next().unwrap_or("") == want
            && let Ok(v) = u64::from_str_radix(addr, 16)
        {
            return v;
        }
    }
    panic!("the fixture must export `{want}`; without it no test here has a target");
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

/// Launch the fixture. The returned debugger is stopped at the exec trap: the
/// tracee has NOT yet executed anything of `main`, so no crossing has happened
/// and no register below holds a meaningful argument yet.
async fn launched(fx: &Fixture) -> LinuxDebugger {
    let dbg = LinuxDebugger::new();
    dbg.launch(launch_opts(&fx.exe)).await.expect("launch should succeed");
    dbg
}

/// Continue until a breakpoint stop at `addr` **belonging to this target**, or
/// the process exits.
///
/// The pid filter is not decoration: the backend waits with `waitpid(-1)`, so a
/// straggler child left by an earlier test in the same process can be handed to
/// this one. An unfiltered loop would then attribute another program's stop to
/// this fixture.
async fn next_hit(dbg: &LinuxDebugger, addr: u64, budget: usize) -> Option<DebugEvent> {
    let mine = dbg.target_pid().expect("a live pid").0;
    for _ in 0..budget {
        let ev = dbg.continue_execution().await.ok()?;
        if ev.pid.0 != mine {
            continue;
        }
        match &ev.reason {
            StopReason::Breakpoint { address, .. } if address.as_u64() == addr => return Some(ev),
            StopReason::ProcessExit { .. } => return None,
            _ => {}
        }
    }
    panic!("budget exhausted without reaching {addr:#x} or an exit");
}

/// Run to completion, returning the exit code and how many breakpoint stops at
/// `addr` were delivered on the way.
async fn run_to_exit_counting(dbg: &LinuxDebugger, addr: u64, budget: usize) -> (i32, usize) {
    let mine = dbg.target_pid().expect("a live pid").0;
    let mut hits = 0usize;
    for _ in 0..budget {
        let Ok(ev) = dbg.continue_execution().await else {
            panic!("continue_execution failed before the tracee exited");
        };
        if ev.pid.0 != mine {
            continue;
        }
        match ev.reason {
            StopReason::Breakpoint { address, .. } if address.as_u64() == addr => hits += 1,
            StopReason::ProcessExit { exit_code } => return (exit_code, hits),
            _ => {}
        }
    }
    panic!("budget exhausted without an exit; {hits} hits so far");
}

/// Build the evaluation context the way the backend does for a live stop:
/// every register the OS reported, the narrowed sub-register names derived from
/// them, the generic `pc`/`sp` roles, and any memory operand pre-read through
/// the debugger.
///
/// `EvalContext` is synchronous while every backend read is `async`, so the
/// snapshot has to be materialised up front — which is exactly what
/// `condition_allows_stop` does internally.
async fn snapshot(dbg: &LinuxDebugger, tid: ThreadId, mem: &[(u64, u8)]) -> MapEvalContext {
    let regs = dbg.get_registers(tid).await.expect("get_registers at a live stop");
    let mut ctx = MapEvalContext::new();
    for (name, value) in &regs.regs {
        ctx.set_reg(name.clone(), *value);
    }
    for alias in rustre_debug::SUB_REGISTER_NAMES {
        if !regs.regs.contains_key(*alias)
            && let Some(v) = regs.get_narrowed(alias)
        {
            ctx.set_reg((*alias).to_string(), v);
        }
    }
    ctx.set_reg("pc", regs.pc);
    ctx.set_reg("sp", regs.sp);
    for &(addr, width) in mem {
        let bytes = dbg
            .read_memory(Address(addr), usize::from(width))
            .await
            .expect("read_memory for a tracepoint operand");
        let mut buf = [0u8; 8];
        let n = bytes.len().min(8);
        buf[..n].copy_from_slice(&bytes[..n]);
        ctx.set_mem(addr, u64::from_le_bytes(buf), width);
    }
    ctx
}

// ── Ground truth ─────────────────────────────────────────────────────────────

/// Establishes the external truth every other test leans on: the fixture really
/// crosses `trace_me` five times, and on each crossing the argument register
/// holds the value the SOURCE says it should. Without this, a tracepoint that
/// rendered five different-but-wrong messages would look like a success.
#[tokio::test]
async fn the_fixture_crosses_the_traced_address_five_times_with_distinct_arguments() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    dbg.set_breakpoint(Address(fx.trace_me), BreakpointKind::Software)
        .await
        .expect("set_breakpoint");

    let mut seen = Vec::new();
    while let Some(ev) = next_hit(&dbg, fx.trace_me, 64).await {
        let ctx = snapshot(&dbg, ev.tid, &[(fx.g_iter, 4)]).await;
        let arg = ctx.register(ARG_REG).expect("the argument register must be readable");
        let iter = ctx.read_memory(fx.g_iter, 4).expect("g_iter must be readable");
        seen.push((arg, iter));
        if seen.len() > 8 {
            break;
        }
    }
    let _ = dbg.kill().await;

    assert_eq!(
        seen.len(),
        5,
        "the source calls trace_me five times; the debugger delivered {} crossings: {seen:?}",
        seen.len()
    );
    let args: Vec<u64> = seen.iter().map(|(a, _)| *a).collect();
    assert_eq!(
        args,
        EXPECTED_ARGS.to_vec(),
        "the argument register does not follow the source's `i * 7 + 1`"
    );
    let iters: Vec<u64> = seen.iter().map(|(_, i)| *i).collect();
    assert_eq!(iters, vec![0, 1, 2, 3, 4], "g_iter must count the passes 0..5");
}

// ── Tracepoint message formatting from live state ────────────────────────────

/// A tracepoint message must interpolate the register value as it is AT THE
/// MOMENT OF THE HIT, on every hit. Five crossings of the same address with
/// five different arguments is the only shape that can tell a live resolve from
/// a value captured once and replayed — both produce a well-formed message.
#[tokio::test]
async fn tracepoint_message_interpolates_the_live_argument_register_on_every_pass() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    dbg.set_breakpoint(Address(fx.trace_me), BreakpointKind::Software)
        .await
        .expect("set_breakpoint");

    let mut tp = Tracepoint::new(
        Address(fx.trace_me),
        TracepointFormat::new()
            .literal("trace_me x=")
            .operand(ConditionOperand::Register(ARG_REG.to_string())),
    );

    let mut messages = Vec::new();
    while let Some(ev) = next_hit(&dbg, fx.trace_me, 64).await {
        let ctx = snapshot(&dbg, ev.tid, &[]).await;
        let fired = tp.fire(&ctx).expect("an unconditional tracepoint must render");
        messages.push(fired.expect("an unconditional tracepoint always fires").message);
        if messages.len() > 8 {
            break;
        }
    }
    let _ = dbg.kill().await;

    let want: Vec<String> = EXPECTED_ARGS.iter().map(|a| format!("trace_me x={a:#x}")).collect();
    assert_eq!(messages, want, "the rendered messages do not track the live argument register");
    assert_eq!(tp.hit_count, 5, "hit_count must count every render");
    assert_eq!(tp.eval_count, 5, "eval_count must count every evaluation");
}

/// The same, through a memory operand: `mem4[&g_iter]` is re-read from the live
/// tracee on each hit. A renderer that cached the first read, or that resolved
/// the address at ARM time instead of at FIRE time, yields five copies of `0x0`.
#[tokio::test]
async fn tracepoint_message_interpolates_live_memory_on_every_pass() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    dbg.set_breakpoint(Address(fx.trace_me), BreakpointKind::Software)
        .await
        .expect("set_breakpoint");

    let mut tp = Tracepoint::new(
        Address(fx.trace_me),
        TracepointFormat::new()
            .literal("pass=")
            .operand(ConditionOperand::Memory { addr: fx.g_iter, width: 4 })
            .literal(" x=")
            .operand(ConditionOperand::Register(ARG_REG.to_string())),
    );

    let mut messages = Vec::new();
    while let Some(ev) = next_hit(&dbg, fx.trace_me, 64).await {
        let ctx = snapshot(&dbg, ev.tid, &[(fx.g_iter, 4)]).await;
        if let Some(e) = tp.fire(&ctx).expect("render must not fail") {
            messages.push(e.message);
        }
        if messages.len() > 8 {
            break;
        }
    }
    let _ = dbg.kill().await;

    let want: Vec<String> = (0..5)
        .map(|i: usize| format!("pass={:#x} x={:#x}", i, EXPECTED_ARGS[i]))
        .collect();
    assert_eq!(messages, want, "the message does not follow live memory");
}

/// `TracepointEvent::hit_count` must be the ORDINAL of this render, not a
/// constant. It is what a log line is numbered with (`[trace @ … #3]`), so a
/// field that stayed at 1 would label five different messages identically.
#[tokio::test]
async fn every_tracepoint_event_carries_its_own_ordinal_and_address() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    dbg.set_breakpoint(Address(fx.trace_me), BreakpointKind::Software)
        .await
        .expect("set_breakpoint");

    let mut tp = Tracepoint::new(Address(fx.trace_me), TracepointFormat::new().literal("hit"));
    let mut ordinals = Vec::new();
    let mut rendered = Vec::new();
    while let Some(ev) = next_hit(&dbg, fx.trace_me, 64).await {
        let ctx = snapshot(&dbg, ev.tid, &[]).await;
        if let Some(e) = tp.fire(&ctx).expect("render") {
            assert_eq!(
                e.address.as_u64(),
                fx.trace_me,
                "the event must name the address it was armed at"
            );
            ordinals.push(e.hit_count);
            rendered.push(e.to_string());
        }
        if ordinals.len() > 8 {
            break;
        }
    }
    let _ = dbg.kill().await;

    assert_eq!(ordinals, vec![1, 2, 3, 4, 5], "hit ordinals must increase per render");
    assert!(
        rendered[2].contains("#3") && rendered[2].contains("hit"),
        "the Display form must carry the ordinal and the message: {}",
        rendered[2]
    );
}

// ── Conditions that become true only at the k-th pass ────────────────────────

/// A tracepoint condition that is true only on the fourth crossing must render
/// exactly once, and must render THERE. Five evaluations, one hit: the counters
/// separate "was evaluated" from "fired", which a single-crossing test cannot.
#[tokio::test]
async fn a_tracepoint_condition_true_only_at_the_fourth_pass_renders_exactly_once() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    dbg.set_breakpoint(Address(fx.trace_me), BreakpointKind::Software)
        .await
        .expect("set_breakpoint");

    let mut tp = Tracepoint::new(
        Address(fx.trace_me),
        TracepointFormat::new()
            .literal("late x=")
            .operand(ConditionOperand::Register(ARG_REG.to_string())),
    );
    tp.add_condition(BreakpointCondition::reg_eq(ARG_REG, TARGET_ARG));

    let mut messages = Vec::new();
    let mut crossings = 0usize;
    while let Some(ev) = next_hit(&dbg, fx.trace_me, 64).await {
        crossings += 1;
        let ctx = snapshot(&dbg, ev.tid, &[]).await;
        if let Some(e) = tp.fire(&ctx).expect("condition must evaluate against live registers") {
            messages.push(e.message);
        }
        if crossings > 8 {
            break;
        }
    }
    let _ = dbg.kill().await;

    assert_eq!(crossings, 5, "the address must still be crossed five times");
    assert_eq!(
        messages,
        vec![format!("late x={TARGET_ARG:#x}")],
        "the condition fired on the wrong passes"
    );
    assert_eq!(tp.eval_count, 5, "every crossing must be evaluated");
    assert_eq!(tp.hit_count, 1, "only the fourth crossing satisfies the condition");
}

/// The same k-th-pass condition expressed over live MEMORY (`mem4[&g_iter] == 3`)
/// rather than a register. Both spellings must select the same crossing; if they
/// disagree, one of the two operand kinds is not being resolved from the tracee.
#[tokio::test]
async fn a_memory_condition_selects_the_same_pass_as_the_register_condition() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    dbg.set_breakpoint(Address(fx.trace_me), BreakpointKind::Software)
        .await
        .expect("set_breakpoint");

    let cond = BreakpointCondition::parse(&format!("mem4[{:#x}] == {TARGET_PASS}", fx.g_iter))
        .expect("the memory condition must parse");
    let mem = memory_operands(&cond);
    assert_eq!(mem, vec![(fx.g_iter, 4)], "the operand extractor must see the memory read");

    let mut tp = Tracepoint::new(
        Address(fx.trace_me),
        TracepointFormat::new().operand(ConditionOperand::Register(ARG_REG.to_string())),
    );
    tp.add_condition(cond);

    let mut messages = Vec::new();
    let mut crossings = 0usize;
    while let Some(ev) = next_hit(&dbg, fx.trace_me, 64).await {
        crossings += 1;
        let ctx = snapshot(&dbg, ev.tid, &mem).await;
        if let Some(e) = tp.fire(&ctx).expect("render") {
            messages.push(e.message);
        }
        if crossings > 8 {
            break;
        }
    }
    let _ = dbg.kill().await;

    assert_eq!(crossings, 5);
    assert_eq!(
        messages,
        vec![format!("{TARGET_ARG:#x}")],
        "the memory condition selected a different crossing than the register condition"
    );
}

/// A CONDITIONAL BREAKPOINT, evaluated by the backend itself rather than by the
/// test: `set_breakpoint_condition` with an expression only the fourth crossing
/// satisfies. The tracee must be handed back stopped exactly once, and at that
/// stop the live state must be the fourth pass — proving the backend filtered
/// the other four rather than the test never reaching them.
#[tokio::test]
async fn the_backend_stops_only_at_the_fourth_pass_for_a_live_condition() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let at = Address(fx.trace_me);
    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set_breakpoint");
    dbg.set_breakpoint_condition(at, Some(format!("{ARG_REG} == {TARGET_ARG}")))
        .await
        .expect("the Linux backend must hold a breakpoint condition");

    let ev = next_hit(&dbg, fx.trace_me, 64).await.expect("the condition must be reachable");
    let ctx = snapshot(&dbg, ev.tid, &[(fx.g_iter, 4)]).await;
    assert_eq!(
        ctx.register(ARG_REG),
        Some(TARGET_ARG),
        "the backend stopped on a crossing whose argument does not satisfy the condition"
    );
    assert_eq!(
        ctx.read_memory(fx.g_iter, 4),
        Some(TARGET_PASS),
        "the stop is not on the fourth pass"
    );

    // Nothing after the fourth crossing satisfies it, so the rest of the run
    // must be uninterrupted.
    let (code, further) = run_to_exit_counting(&dbg, fx.trace_me, 64).await;
    let _ = dbg.kill().await;
    assert_eq!(further, 0, "the condition stopped the tracee again after the fourth pass");
    assert_eq!(code, 0, "the fixture must still run to a clean exit under a condition");
}

/// The condition-filtered crossings must not be COUNTED. `breakpoints()`
/// publishes `hit_count`, and a count inflated by the suppressed crossings
/// would contradict what the user watched happen — they were stopped once.
#[tokio::test]
async fn crossings_filtered_by_a_live_condition_do_not_inflate_the_hit_count() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let at = Address(fx.trace_me);
    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set_breakpoint");
    dbg.set_breakpoint_condition(at, Some(format!("{ARG_REG} == {TARGET_ARG}")))
        .await
        .expect("set_breakpoint_condition");

    next_hit(&dbg, fx.trace_me, 64).await.expect("the condition must fire once");
    let list = dbg.breakpoints().await.expect("breakpoints");
    let bp = list
        .iter()
        .find(|b| b.address.as_u64() == fx.trace_me)
        .expect("the conditional breakpoint must still be listed")
        .clone();
    let _ = dbg.kill().await;

    assert_eq!(
        bp.condition,
        Some(format!("{ARG_REG} == {TARGET_ARG}")),
        "the listing must report the condition that is actually attached"
    );
    assert_eq!(
        bp.hit_count, 1,
        "one stop was delivered but the listing counts {}; the suppressed crossings were counted as hits",
        bp.hit_count
    );
}

/// A condition that is false on EVERY crossing must never stop the tracee, and
/// the program must run to its normal exit. This is the other half of the
/// filtering contract: a backend that failed open on an unsatisfied condition
/// would stop five times here.
#[tokio::test]
async fn a_condition_false_on_every_pass_never_stops_the_tracee() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let at = Address(fx.trace_me);
    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set_breakpoint");
    dbg.set_breakpoint_condition(at, Some(format!("{ARG_REG} == 0x5eaf00d")))
        .await
        .expect("set_breakpoint_condition");

    let (code, hits) = run_to_exit_counting(&dbg, fx.trace_me, 64).await;
    let _ = dbg.kill().await;
    assert_eq!(hits, 0, "an unsatisfiable condition stopped the tracee {hits} times");
    assert_eq!(code, 0, "the fixture must reach its normal exit");
}

// ── The non-stopping contract ────────────────────────────────────────────────

/// A tracepoint must never request a stop: whatever its conditions do, the
/// caller keeps the target running and the program reaches its own `exit(0)`
/// with all five crossings logged. Measured on the process, not on the API —
/// the exit code is compared with the one the fixture produces with no debugger
/// at all.
#[tokio::test]
async fn a_tracepoint_lets_the_program_run_to_its_own_exit() {
    let fx = build_fixture();

    // External truth: what the fixture does with no debugger involved.
    let bare = std::process::Command::new(&fx.exe).output().expect("run the fixture bare");
    assert!(bare.status.success(), "the fixture must exit 0 on its own");
    let bare_stdout = String::from_utf8_lossy(&bare.stdout).to_string();

    let dbg = launched(&fx).await;
    dbg.set_breakpoint(Address(fx.trace_me), BreakpointKind::Software)
        .await
        .expect("set_breakpoint");

    let mut tp = Tracepoint::new(
        Address(fx.trace_me),
        TracepointFormat::new().operand(ConditionOperand::Register(ARG_REG.to_string())),
    );
    let mine = dbg.target_pid().expect("a live pid").0;
    let mut logged = 0usize;
    let mut exit = None;
    for _ in 0..64 {
        let ev = dbg.continue_execution().await.expect("continue_execution");
        if ev.pid.0 != mine {
            continue;
        }
        match ev.reason {
            StopReason::Breakpoint { address, .. } if address.as_u64() == fx.trace_me => {
                let ctx = snapshot(&dbg, ev.tid, &[]).await;
                // `fire` returns a message or nothing — it has no way to say
                // "stop", which is the contract. The caller resumes either way.
                if tp.fire(&ctx).expect("render").is_some() {
                    logged += 1;
                }
            }
            StopReason::ProcessExit { exit_code } => {
                exit = Some(exit_code);
                break;
            }
            _ => {}
        }
    }
    let _ = dbg.kill().await;

    assert_eq!(logged, 5, "the tracepoint logged {logged} of 5 crossings");
    assert_eq!(
        exit,
        Some(0),
        "the traced program did not reach its own exit: {exit:?} (bare run printed {bare_stdout:?})"
    );
}

/// THE GAP, measured. A tracepoint is defined as non-stopping, but nothing in
/// the backend knows what a tracepoint is: arming one still means planting an
/// ordinary software breakpoint, so the tracee is genuinely STOPPED on every
/// crossing and handed to the caller, who must resume it by hand.
///
/// gdb's `dprintf` hands the user zero stops for the same five crossings. This
/// test records the real number so a future `set_tracepoint` has a figure to
/// beat, and so a regression in the other direction is visible.
#[tokio::test]
async fn the_tracepoint_contract_is_non_stopping_but_the_backend_stops_five_times() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    dbg.set_breakpoint(Address(fx.trace_me), BreakpointKind::Software)
        .await
        .expect("set_breakpoint");

    let (code, stops) = run_to_exit_counting(&dbg, fx.trace_me, 64).await;
    let _ = dbg.kill().await;

    assert_eq!(code, 0);
    assert_eq!(
        stops, 5,
        "expected the measured cost of a hand-rolled tracepoint: 5 real stops (gdb dprintf: 0)"
    );
}

// ── No invented output ───────────────────────────────────────────────────────

/// A tracepoint on an address the program never executes must produce NOTHING:
/// no message, no hit, no evaluation. The trap is really planted (the address
/// is a real, linked function), the program really runs to completion, and the
/// tracepoint is still untouched — which is the difference between "never
/// reached" and "reached and rendered a default".
#[tokio::test]
async fn a_tracepoint_on_an_address_never_reached_invents_no_output() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    assert_ne!(fx.never_called, fx.trace_me, "the two targets must be distinct addresses");
    dbg.set_breakpoint(Address(fx.never_called), BreakpointKind::Software)
        .await
        .expect("a breakpoint on a real linked function must be settable");

    let mut tp = Tracepoint::new(
        Address(fx.never_called),
        TracepointFormat::new()
            .literal("never x=")
            .operand(ConditionOperand::Register(ARG_REG.to_string())),
    );

    let mine = dbg.target_pid().expect("a live pid").0;
    let mut messages: Vec<String> = Vec::new();
    let mut exit = None;
    for _ in 0..64 {
        let ev = dbg.continue_execution().await.expect("continue_execution");
        if ev.pid.0 != mine {
            continue;
        }
        match ev.reason {
            StopReason::Breakpoint { address, .. } if address.as_u64() == fx.never_called => {
                let ctx = snapshot(&dbg, ev.tid, &[]).await;
                if let Some(e) = tp.fire(&ctx).expect("render") {
                    messages.push(e.message);
                }
            }
            StopReason::ProcessExit { exit_code } => {
                exit = Some(exit_code);
                break;
            }
            _ => {}
        }
    }
    let _ = dbg.kill().await;

    assert_eq!(exit, Some(0), "the fixture must run to completion with the unused trap planted");
    assert!(messages.is_empty(), "a never-executed tracepoint produced output: {messages:?}");
    assert_eq!(tp.hit_count, 0, "hit_count must stay 0 for an address never reached");
    assert_eq!(tp.eval_count, 0, "eval_count must stay 0: nothing was ever evaluated");
}

/// `TracepointSet::fire_at` must dispatch on the ADDRESS. Two tracepoints are
/// registered — one on the crossed address, one on the never-executed one — and
/// only the first may ever render, on every one of the five live crossings. A
/// set that fired everything registered would put a message about
/// `never_called` in the log of a program that never called it.
#[tokio::test]
async fn a_tracepoint_set_fires_only_the_entry_matching_the_live_address() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    dbg.set_breakpoint(Address(fx.trace_me), BreakpointKind::Software)
        .await
        .expect("set_breakpoint");

    let mut set = TracepointSet::new();
    let live = set.add(Tracepoint::new(
        Address(fx.trace_me),
        TracepointFormat::new()
            .literal("live=")
            .operand(ConditionOperand::Register(ARG_REG.to_string())),
    ));
    let dead = set.add(Tracepoint::new(
        Address(fx.never_called),
        TracepointFormat::new().literal("dead"),
    ));
    assert_eq!(set.len(), 2);

    let mut messages = Vec::new();
    let mut crossings = 0usize;
    while let Some(ev) = next_hit(&dbg, fx.trace_me, 64).await {
        crossings += 1;
        let ctx = snapshot(&dbg, ev.tid, &[]).await;
        for e in set.fire_at(Address(fx.trace_me), &ctx) {
            messages.push(e.message);
        }
        if crossings > 8 {
            break;
        }
    }
    let _ = dbg.kill().await;

    let want: Vec<String> = EXPECTED_ARGS.iter().map(|a| format!("live={a:#x}")).collect();
    assert_eq!(messages, want, "the set rendered the wrong entries");
    assert_eq!(set.get(live).expect("live entry").hit_count, 5);
    assert_eq!(
        set.get(dead).expect("dead entry").eval_count,
        0,
        "the entry armed at another address was evaluated, so dispatch ignores the address"
    );
}

/// A DISABLED tracepoint must stay silent across every live crossing, and must
/// not even evaluate — the documented short-circuit. Re-enabling it mid-run
/// must resume logging, so the five crossings split cleanly into a silent half
/// and a logged half. A flag consulted only at arm time would log all five or
/// none.
#[tokio::test]
async fn a_disabled_tracepoint_stays_silent_and_resumes_when_re_enabled() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    dbg.set_breakpoint(Address(fx.trace_me), BreakpointKind::Software)
        .await
        .expect("set_breakpoint");

    let mut tp = Tracepoint::new(
        Address(fx.trace_me),
        TracepointFormat::new().operand(ConditionOperand::Register(ARG_REG.to_string())),
    );
    tp.enabled = false;

    let mut messages = Vec::new();
    let mut crossings = 0usize;
    while let Some(ev) = next_hit(&dbg, fx.trace_me, 64).await {
        crossings += 1;
        if crossings == 3 {
            tp.enabled = true;
        }
        let ctx = snapshot(&dbg, ev.tid, &[]).await;
        if let Some(e) = tp.fire(&ctx).expect("render") {
            messages.push(e.message);
        }
        if crossings > 8 {
            break;
        }
    }
    let _ = dbg.kill().await;

    assert_eq!(crossings, 5);
    let want: Vec<String> = EXPECTED_ARGS[2..].iter().map(|a| format!("{a:#x}")).collect();
    assert_eq!(messages, want, "the disabled window did not match crossings 1-2");
    assert_eq!(tp.eval_count, 3, "a disabled tracepoint must short-circuit before evaluating");
}

/// An operand that cannot be resolved must SURFACE as an error, not as a
/// plausible number. A tracepoint whose message silently rendered `0x0` for an
/// unreadable register would put a fabricated value in a log that is read as
/// evidence. Measured live, so the failing lookup happens against a real
/// register set rather than an empty map.
#[tokio::test]
async fn an_unresolvable_operand_is_reported_rather_than_rendered_as_zero() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    dbg.set_breakpoint(Address(fx.trace_me), BreakpointKind::Software)
        .await
        .expect("set_breakpoint");

    let ev = next_hit(&dbg, fx.trace_me, 64).await.expect("first crossing");
    let ctx = snapshot(&dbg, ev.tid, &[]).await;
    let _ = dbg.kill().await;

    assert!(
        ctx.register(ARG_REG).is_some(),
        "the context must be populated, or the negative below proves nothing"
    );
    let mut tp = Tracepoint::new(
        Address(fx.trace_me),
        TracepointFormat::new()
            .literal("v=")
            .operand(ConditionOperand::Register("no_such_register".into())),
    );
    let err = tp.fire(&ctx).expect_err("an unknown register must not render");
    assert!(
        err.to_string().contains("no_such_register"),
        "the error must name the operand that failed: {err}"
    );
}

// ── Hygiene ──────────────────────────────────────────────────────────────────

/// No test above may leave the fixture running. Named to sort last so it runs
/// after the others under `--test-threads=1`; it asks the OS, not the debugger,
/// because a leaked tracee is precisely the case where the debugger's own
/// bookkeeping is not to be trusted.
#[tokio::test]
async fn zz_no_orphan_fixture_process_survives_the_suite() {
    let out = std::process::Command::new("pgrep")
        .args(["-f", "tp_fixture"])
        .output()
        .expect("pgrep must be available for the orphan check");
    let listing = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let mine = std::process::id().to_string();
    let strays: Vec<&str> =
        listing.lines().filter(|l| !l.trim().is_empty() && l.trim() != mine).collect();
    assert!(strays.is_empty(), "fixture processes survived the suite: {strays:?}");
}
