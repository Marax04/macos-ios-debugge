//! Live-process coverage for breakpoint CONDITIONS on the Linux backend.
//!
//! Every test here drives a REAL process: a small C fixture is compiled on the
//! fly with `cc -no-pie -O0 -g`, launched under `ptrace`, and a condition is
//! attached to a breakpoint that the fixture crosses a known number of times.
//! What is asserted is always the OBSERVABLE consequence of evaluation — where
//! the process stopped, or that it ran to exit — not the contents of an
//! in-memory structure. That distinction is the point of the file: a condition
//! that is stored, parsed and then never applied looks identical to a working
//! one from the outside, and the crate has already paid for that once (see the
//! deleted third assertion in
//! `conditions_meet_a_real_register_set_on_this_platform`, which passed just as
//! happily with the filter neutralised because the breakpoint address was never
//! crossed a second time). Here the fixture loops, so a filter that does
//! nothing stops on the FIRST crossing and every test that names a later one
//! fails.
//!
//! `-no-pie` is load-bearing: the binary is `ET_EXEC`, so the addresses `nm`
//! prints — for the function AND for the globals the memory operands read —
//! are the addresses those objects occupy at run time.
//!
//! ## The one shape here that is still self-referential
//!
//! Measured: 6 of these 9 bite. What the file cannot show on its own is that the
//! REGISTER it reads at the stop is the one the program put there — the tests
//! assert `rdi == N` after a condition selected on `rdi == N`, so the operand
//! and the check come from the same read. `live_linux_devac_regs_mem.rs` pins
//! that half down: the fixture there reports in writing the two argument values
//! it is about to pass, and the debugger must read exactly those.
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::{
    BreakpointKind, DebugEvent, Debugger, LaunchOptions, OutputRedirect, StopReason, ThreadId,
};

/// The fixture. `hot` is called ten times with `i` in its first argument
/// register, and `g_iter` is set to the SAME value immediately before each
/// call, so at `hot`'s entry the register condition `rdi == N` and the memory
/// condition `mem8[&g_iter] == N` must select the same crossing. `g_signed`
/// holds a negative value whose unsigned reading is huge, and `g_ptr` points at
/// `g_magic`, giving the pointer-dereference test a two-step chain that only
/// resolves if both reads hit the real process.
const FIXTURE_C: &str = r#"
#include <stdio.h>
long g_iter = -1;
long g_signed = -5;
long g_magic = 0x1122334455667788L;
long *g_ptr = 0;

__attribute__((noinline)) void hot(long i) { g_iter = i; }

int main(void) {
    g_ptr = &g_magic;
    for (long i = 0; i < 10; i++) { g_iter = i; hot(i); }
    printf("%ld\n", g_iter);
    return 0;
}
"#;

struct Fixture {
    _dir: tempfile::TempDir,
    exe: String,
    hot: u64,
    g_iter: u64,
    g_signed: u64,
    g_ptr: u64,
    g_magic: u64,
}

fn build_fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("fixture.c");
    let exe = dir.path().join("fixture");
    std::fs::write(&src, FIXTURE_C).expect("write fixture source");
    let out = std::process::Command::new("cc")
        .args(["-no-pie", "-O0", "-g"])
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .output()
        .expect("cc must be available to run the live condition tests");
    assert!(
        out.status.success(),
        "cc failed to build the fixture: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let nm = std::process::Command::new("nm").arg(&exe).output().expect("nm");
    assert!(nm.status.success(), "nm failed on the fixture binary");
    let listing = String::from_utf8_lossy(&nm.stdout).to_string();
    let sym = |want: &str| {
        symbol_address(&listing, want).unwrap_or_else(|| {
            panic!("the fixture must define `{want}`; without it the test has no target")
        })
    };
    Fixture {
        exe: exe.to_string_lossy().to_string(),
        hot: sym("hot"),
        g_iter: sym("g_iter"),
        g_signed: sym("g_signed"),
        g_ptr: sym("g_ptr"),
        g_magic: sym("g_magic"),
        _dir: dir,
    }
}

/// Any symbol kind: `T`/`t` for the function, `D`/`d`/`B`/`b` for the globals.
fn symbol_address(nm_listing: &str, want: &str) -> Option<u64> {
    for line in nm_listing.lines() {
        let mut parts = line.split_whitespace();
        let addr = parts.next()?;
        let Some(_kind) = parts.next() else { continue };
        if parts.next().unwrap_or("") == want {
            return u64::from_str_radix(addr, 16).ok();
        }
    }
    None
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

/// Resume until the breakpoint at `addr` reports a stop. `None` means the
/// process exited first — which several tests below require, so the two
/// outcomes are deliberately distinguishable rather than both being "no stop".
async fn run_until_breakpoint(dbg: &LinuxDebugger, addr: u64, budget: usize) -> Option<DebugEvent> {
    for _ in 0..budget {
        let ev = dbg.continue_execution().await.ok()?;
        match &ev.reason {
            StopReason::Breakpoint { address, .. } if address.as_u64() == addr => return Some(ev),
            StopReason::ProcessExit { .. } => return None,
            _ => {}
        }
    }
    None
}

/// Read an 8-byte little-endian word out of the live process.
async fn read_u64(dbg: &LinuxDebugger, addr: u64) -> u64 {
    let bytes = dbg
        .read_memory(Address(addr), 8)
        .await
        .unwrap_or_else(|e| panic!("read_memory at {addr:#x} failed: {e}"));
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(buf)
}

/// Plant a breakpoint at `hot` carrying `cond`.
async fn armed(dbg: &LinuxDebugger, fx: &Fixture, cond: &str) {
    dbg.set_breakpoint(Address(fx.hot), BreakpointKind::Software)
        .await
        .expect("set_breakpoint at `hot`");
    dbg.set_breakpoint_condition(Address(fx.hot), Some(cond.to_string()))
        .await
        .unwrap_or_else(|e| panic!("the backend refused the well-formed condition {cond:?}: {e}"));
}

/// A condition comparing a REGISTER against a literal must select the crossing
/// it names, not the first one. The fixture calls `hot` ten times with the loop
/// counter in `rdi`, so `rdi == 7` has exactly one true crossing; a filter that
/// is stored but never applied stops at `rdi == 0` and fails here, which is
/// what makes this test worth running against a live process at all.
#[tokio::test]
async fn a_register_condition_selects_the_crossing_it_names() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    armed(&dbg, &fx, "rdi == 7").await;

    let ev = run_until_breakpoint(&dbg, fx.hot, 32)
        .await
        .expect("`rdi == 7` is true on one of the ten crossings, so the process must stop");
    let regs = dbg.get_registers(ev.tid).await.expect("get_registers at the stop");
    let rdi = regs.get("rdi").expect("x86-64 ptrace reports rdi");
    assert_eq!(
        rdi, 7,
        "the condition named rdi == 7 but the process stopped with rdi = {rdi}: the filter let a \
         crossing through that does not satisfy it"
    );
    let _ = dbg.kill().await;
}

/// A condition that is true on NO crossing must let the process run to exit.
/// This is the half a neutralised filter cannot fake: if the condition is
/// ignored, the very first crossing stops and `run_until_breakpoint` returns a
/// stop instead of `None`.
#[tokio::test]
async fn a_condition_true_on_no_crossing_lets_the_process_exit() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    armed(&dbg, &fx, "rdi == 999").await;

    let stopped = run_until_breakpoint(&dbg, fx.hot, 32).await;
    assert!(
        stopped.is_none(),
        "`rdi == 999` is false on all ten crossings, yet the process stopped at `hot` — the \
         condition was not applied"
    );
    let _ = dbg.kill().await;
}

/// A memory operand must read the LIVE process's global, not a stale image of
/// the file. `g_iter` is written by the loop immediately before each call, so
/// `mem8[&g_iter] == 4` is true on exactly one crossing — and the value in the
/// on-disk binary is `-1`, so a read that came from the file rather than the
/// process would never be 4 and the process would exit instead of stopping.
#[tokio::test]
async fn a_memory_operand_reads_a_global_out_of_the_live_process() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let cond = format!("mem8[{:#x}] == 4", fx.g_iter);
    armed(&dbg, &fx, &cond).await;

    let ev = run_until_breakpoint(&dbg, fx.hot, 32)
        .await
        .unwrap_or_else(|| panic!("{cond} is true on the fifth crossing; the process must stop"));
    let regs = dbg.get_registers(ev.tid).await.expect("get_registers at the stop");
    assert_eq!(
        regs.get("rdi").expect("rdi"),
        4,
        "the memory condition selected a crossing where the loop counter is not 4"
    );
    assert_eq!(
        read_u64(&dbg, fx.g_iter).await,
        4,
        "the global the condition read must itself hold 4 at the stop"
    );
    let _ = dbg.kill().await;
}

/// A pointer DEREFERENCE, in the only form this engine can express it: the
/// pointer is read out of the live process first, and its value becomes the
/// address of the memory operand. The chain only resolves if both reads hit the
/// real process — `g_ptr` is zero in the on-disk image and is filled in by
/// `main`, and `g_magic`'s value is a 64-bit pattern no accidental read
/// produces.
#[tokio::test]
async fn a_condition_dereferences_a_pointer_read_from_the_live_process() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    dbg.set_breakpoint(Address(fx.hot), BreakpointKind::Software)
        .await
        .expect("set_breakpoint at `hot`");
    run_until_breakpoint(&dbg, fx.hot, 8)
        .await
        .expect("the unconditional breakpoint must stop on the first crossing");

    let pointee = read_u64(&dbg, fx.g_ptr).await;
    assert_eq!(
        pointee, fx.g_magic,
        "`g_ptr` in the live process must hold the address of `g_magic`; it holds {pointee:#x}"
    );
    let cond = format!("mem8[{pointee:#x}] == 0x1122334455667788");
    dbg.set_breakpoint_condition(Address(fx.hot), Some(cond.clone()))
        .await
        .unwrap_or_else(|e| panic!("the backend refused {cond:?}: {e}"));

    let ev = run_until_breakpoint(&dbg, fx.hot, 32)
        .await
        .unwrap_or_else(|| panic!("{cond} is true at every crossing; the process must stop again"));
    assert!(
        matches!(&ev.reason, StopReason::Breakpoint { address, .. } if address.as_u64() == fx.hot),
        "the stop must be the conditional breakpoint at `hot`"
    );
    let _ = dbg.kill().await;
}

/// A malformed expression must be REFUSED, and refused loudly. The alternative
/// this test exists to exclude is the quiet one: an operand that fails to parse
/// being treated as zero, which turns `rdi == <garbage>` into `rdi == 0` — a
/// condition that is true on the first crossing and looks like it worked.
/// Rejection must also leave nothing behind: a stored-but-unparsable condition
/// takes the fail-open path and stops on EVERY hit, so `breakpoints()` is
/// required to still report `None`.
#[tokio::test]
async fn a_malformed_condition_is_refused_and_not_stored() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let at = Address(fx.hot);
    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set_breakpoint");

    for bad in ["rdi", "== 7", "rdi ==", "rdi == @@@", "mem3[0x1000] == 0", "   "] {
        let res = dbg.set_breakpoint_condition(at, Some(bad.to_string())).await;
        assert!(
            res.is_err(),
            "the malformed condition {bad:?} was ACCEPTED; an expression that cannot be read must \
             not be evaluated at all, least of all as a comparison against zero"
        );
        let held = dbg
            .breakpoints()
            .await
            .expect("breakpoints")
            .iter()
            .find(|b| b.address == at)
            .and_then(|b| b.condition.clone());
        assert_eq!(
            held, None,
            "the rejected condition {bad:?} was still stored; on the next hit it would take the \
             fail-open path and stop unconditionally"
        );
    }

    // The breakpoint must still be usable afterwards: rejection must not have
    // damaged it. A well-formed condition on the same address still selects.
    dbg.set_breakpoint_condition(at, Some("rdi == 2".to_string()))
        .await
        .expect("a well-formed condition must still be accepted after a rejection");
    let ev = run_until_breakpoint(&dbg, fx.hot, 32)
        .await
        .expect("`rdi == 2` is true on the third crossing");
    let regs = dbg.get_registers(ev.tid).await.expect("get_registers");
    assert_eq!(regs.get("rdi").expect("rdi"), 2, "the surviving condition must still select");
    let _ = dbg.kill().await;
}

/// An ordering comparison must be SIGNED. `g_signed` holds `-5`, whose bit
/// pattern read as unsigned is 0xFFFF_FFFF_FFFF_FFFB — larger than every
/// positive value. So `mem8[&g_signed] < 0` is true under signed rules and
/// false under unsigned ones, and the two verdicts have opposite observable
/// outcomes: a stop, or a process that exits. gdb and lldb both treat a
/// register-width value as signed here, and `rax < 0` — catching a negative
/// return code — is the most common conditional breakpoint there is.
#[tokio::test]
async fn an_ordering_comparison_of_a_negative_value_is_signed_not_unsigned() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let cond = format!("mem8[{:#x}] < 0", fx.g_signed);
    armed(&dbg, &fx, &cond).await;

    // Read straight out of the live process first, so a failure below cannot be
    // blamed on the fixture holding something other than -5.
    let raw = read_u64(&dbg, fx.g_signed).await;
    assert_eq!(raw, (-5i64) as u64, "the fixture's `g_signed` must hold -5; it holds {raw:#x}");

    let stopped = run_until_breakpoint(&dbg, fx.hot, 32).await;
    assert!(
        stopped.is_some(),
        "{cond} is TRUE for -5 under signed ordering, but the process ran to exit — the \
         comparison used the unsigned reading {raw:#x}, under which no value is below zero"
    );
    let _ = dbg.kill().await;
}

/// The complement, which the previous test cannot prove on its own: an
/// evaluator comparing unsigned would call the same value GREATER than zero.
/// `mem8[&g_signed] > 0` must therefore be false and the process must run to
/// exit. Together the pair pins the sign down from both sides — one test alone
/// is satisfied by an evaluator that always answers "stop".
#[tokio::test]
async fn a_negative_value_is_not_reported_as_greater_than_zero() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let cond = format!("mem8[{:#x}] > 0", fx.g_signed);
    armed(&dbg, &fx, &cond).await;

    let stopped = run_until_breakpoint(&dbg, fx.hot, 32).await;
    assert!(
        stopped.is_none(),
        "{cond} stopped the process: -5 was read as the unsigned 0xFFFFFFFFFFFFFFFB and judged \
         greater than zero, which is the exact case a user writes this condition to EXCLUDE"
    );
    let _ = dbg.kill().await;
}

/// A condition that PARSES but cannot be RESOLVED must fail OPEN — stop — not
/// fail closed. `nosuchreg` is a bare word, so the parser reads it as a
/// register name and accepts the expression; nothing in the live register set
/// answers to it, so the comparison has no value to make. The rule the backend
/// documents, and gdb's, is to stop anyway: a breakpoint that silently never
/// fires tells the user their code never reaches that line — a wrong conclusion
/// about their PROGRAM drawn from a typo in their condition. Stopping is noisy
/// and the user is standing at the breakpoint, so the noise explains itself.
///
/// This is the one place where "no value" must NOT become zero: treating the
/// missing register as 0 would make `nosuchreg == 1` false and quietly delete
/// the breakpoint.
#[tokio::test]
async fn an_unresolvable_but_well_formed_condition_fails_open_and_stops() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    // `== 1` on purpose: if the unknown operand were silently read as zero the
    // condition would be FALSE and the process would exit, which is exactly the
    // failure this asserts against.
    armed(&dbg, &fx, "nosuchreg == 1").await;

    let ev = run_until_breakpoint(&dbg, fx.hot, 32).await;
    assert!(
        ev.is_some(),
        "a condition naming a register the target does not have was treated as FALSE and the          process ran to exit; an unevaluable condition must stop, not delete the breakpoint"
    );
    let ev = ev.expect("checked above");
    let regs = dbg.get_registers(ev.tid).await.expect("get_registers");
    assert_eq!(
        regs.get("rdi").expect("rdi"),
        0,
        "failing open means stopping on the FIRST crossing, not filtering to a later one"
    );
    let _ = dbg.kill().await;
}

/// `ThreadId` is used by the assertion below and by the register reads above;
/// this also records that on this backend the pid addresses the main thread,
/// which every `get_registers(ev.tid)` above relies on.
#[tokio::test]
async fn the_process_pid_addresses_the_main_threads_register_set() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let pid = dbg.target_pid().expect("a live pid");
    let regs = dbg
        .get_registers(ThreadId(pid.0))
        .await
        .expect("the pid must address the main thread's register set");
    assert_ne!(regs.pc, 0, "a stopped process has a non-zero program counter");
    let _ = dbg.kill().await;
}
