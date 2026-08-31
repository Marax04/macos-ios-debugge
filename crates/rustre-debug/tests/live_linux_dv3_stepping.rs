//! Stepping coverage that PINS ADDRESSES, written after measuring how much
//! `tests/live_linux_stepping.rs` actually bites.
//!
//! That file is good, and six of its seven live tests are honest. But a
//! mutation sweep over its ground truth (2026-08-31, recorded in
//! `status_parts/dv3-stepping.md`) found three specific blind spots, and every
//! test here exists to close exactly one of them:
//!
//!  * Moving `callee`'s entry 8 bytes forward — a real instruction boundary
//!    inside the same function — left all 7 tests green. Nothing in the file
//!    pins an ADDRESS: `run_to(X)` plants a breakpoint at `X` and then asserts
//!    the stop happened at `X`, which is true for every `X`.
//!  * Pointing `call_site`/`after_call` at the instruction PAIR after the call
//!    left `step_over_a_call_does_not_enter_the_callee` green — the one test
//!    whose stated purpose is stepping OVER a call cannot tell a call from a
//!    `mov`, because `step_over` degenerates to `single_step` on a non-call and
//!    the landing address is the oracle's own next field.
//!  * Making the fixture unbuildable turned all 7 tests green in 0.40s. The
//!    `[skip]` line goes to stdout, which libtest hides for a passing test.
//!
//! The cure used throughout is the same: never let the debugger's stop address
//! be compared only against the address the test itself asked for. Every
//! assertion below is a TRIPLE whose legs come from three different places —
//! the ELF symbol table (`nm`), the disassembly (`objdump`), and the C source's
//! own arithmetic — so no single corrupted oracle can satisfy all of them.
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::{BreakpointKind, Debugger, LaunchOptions, StopReason, ThreadId};
use std::process::Command;

// ── Fixture ──────────────────────────────────────────────────────────────────
//
// Identical in shape to the sibling file's fixture, deliberately: what is new
// here is the assertions, not the program. `callee` returns `x * 2 + 1`, so
// with `a == 21` the result is 43 — a number that comes from the C source and
// from nowhere inside the debugger, which is what makes it usable as an
// independent third leg.

const FIXTURE_C: &str = r#"
#include <stdio.h>

__attribute__((noinline)) int callee(int x) { return x * 2 + 1; }

int main(void) {
    volatile int a = 21;
    int b = callee((int)a);
    printf("%d\n", b);
    return 0;
}
"#;

/// What `callee` returns for the fixture's `a == 21`, computed from the C
/// source above and not from anything the debugger reports.
const CALLEE_RESULT: u64 = 43;

struct Fixture {
    _dir: tempfile::TempDir,
    path: String,
    callee: (u64, u64),
    main: (u64, u64),
    call_site: u64,
    after_call: u64,
}

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
    let callee = symbol_extent(&path, "callee")?;
    let main = symbol_extent(&path, "main")?;
    let (call_site, after_call) = find_call_to_callee(&path, main)?;
    Some(Fixture { _dir: dir, path, callee, main, call_site, after_call })
}

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

fn find_call_to_callee(exe: &str, main: (u64, u64)) -> Option<(u64, u64)> {
    let out = Command::new("objdump").args(["-d", exe]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut addrs: Vec<u64> = Vec::new();
    let mut call_idx: Option<usize> = None;
    for line in text.lines() {
        let Some((lhs, rhs)) = line.split_once(':') else { continue };
        let Ok(addr) = u64::from_str_radix(lhs.trim(), 16) else { continue };
        if addr < main.0 || addr >= main.1 {
            continue;
        }
        addrs.push(addr);
        if rhs.contains("call") && rhs.contains("<callee>") {
            call_idx = Some(addrs.len() - 1);
        }
    }
    let i = call_idx?;
    Some((addrs[i], *addrs.get(i + 1)?))
}

// ── Harness helpers ──────────────────────────────────────────────────────────

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

/// The 64-bit word the target holds at `addr`, or `None` when it cannot be
/// read.
async fn peek_u64(dbg: &LinuxDebugger, addr: u64) -> Option<u64> {
    let bytes = dbg.read_memory(Address(addr), 8).await.ok()?;
    Some(u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?))
}

/// The low 32 bits of a named register, which is where an `int` return value
/// lives on x86-64.
fn eax_of(regs: &rustre_debug::RegisterSet) -> Option<u64> {
    regs.regs.get("rax").copied().map(|r| r & 0xffff_ffff)
}

// ── (0) the silent-skip class ────────────────────────────────────────────────

/// PROVES: this host really can build and disassemble the fixture, and reports
/// that as a PASS/FAIL rather than as a line on stdout nobody reads.
///
/// WHY THAT IS RIGHT: measured 2026-08-31 — making `build_fixture` return
/// `None` turns all seven live tests of `live_linux_stepping.rs` green in
/// 0.40s (against 2.33s when they really run). Each prints
/// `[skip] no usable C toolchain` and returns, and libtest hides the stdout of
/// a passing test, so that file can go from "seven live ptrace round trips" to
/// "seven no-ops" without one character of the report changing.
///
/// The `fixture_or_skip!` pattern itself is defensible — a missing compiler is
/// not a debugger defect — but it has to be VISIBLE. One non-skipping test
/// makes it visible for the whole directory: if the toolchain disappears this
/// goes red, and the neighbouring greens are then correctly read as "not
/// measured" instead of "measured and fine".
///
/// The extra assertions are cheap invariants on the ground truth itself, so a
/// silently mis-parsed `nm`/`objdump` cannot pass for a working fixture: a
/// direct near call is exactly 5 bytes on x86-64, so `after_call - call_site`
/// is known independently of what objdump chose to print next.
#[test]
fn the_fixture_toolchain_is_present_so_the_other_greens_are_earned() {
    let fx = build_fixture()
        .expect("no usable C toolchain / static libc: every stepping test on this host is a no-op");
    assert!(fx.callee.1 > fx.callee.0, "nm reported callee with zero size");
    assert!(fx.main.1 > fx.main.0, "nm reported main with zero size");
    assert!(
        fx.call_site >= fx.main.0 && fx.call_site < fx.main.1,
        "the call to callee ({:#x}) is not inside main [{:#x}, {:#x})",
        fx.call_site,
        fx.main.0,
        fx.main.1
    );
    assert_eq!(
        fx.after_call - fx.call_site,
        5,
        "a direct near call is 5 bytes on x86-64, but objdump says {:#x} follows {:#x}",
        fx.after_call,
        fx.call_site
    );
}

// ── (1) address-level pinning of the callee entry ────────────────────────────

/// PROVES: single-stepping the `call callee` instruction performs a real CALL,
/// checked as a TRIPLE that three independent oracles must all agree on:
///   (a) the new pc is `callee`'s address in the ELF SYMBOL TABLE,
///   (b) the stack pointer dropped by exactly 8,
///   (c) the word now at `[rsp]` is the address `objdump` says follows the
///       call.
///
/// WHY THAT IS RIGHT: this is the check the sibling file does not have. There,
/// `run_to(X)` plants a breakpoint at `X` and asserts the stop was at `X` —
/// self-referential, which is why moving `callee` 8 bytes forward (still a
/// legal instruction boundary inside the same function) left all 7 tests
/// green. Here leg (a) is an address the debugger arrived at ON ITS OWN,
/// having been told only about `call_site`; legs (b) and (c) come from the
/// x86-64 call ABI and from the disassembly. No single corrupted field can
/// satisfy all three: shifting `callee` breaks (a), shifting `after_call`
/// breaks (c), and pointing `call_site` at a non-call breaks (a) and (b)
/// together.
#[tokio::test]
async fn stepping_the_call_pins_the_callee_entry_the_stack_drop_and_the_return_slot() {
    let Some(fx) = build_fixture() else {
        eprintln!("[skip] no usable C toolchain / static libc on this host");
        return;
    };
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };

    assert!(run_to(&dbg, fx.call_site).await, "the fixture should reach the call site in main");
    let before = dbg.get_registers(tid).await.expect("get_registers at the call site");
    assert_eq!(before.pc, fx.call_site, "run_to did not stop where it was asked to");

    dbg.single_step(tid).await.expect("single_step at a call should succeed");
    let after = dbg.get_registers(tid).await.expect("get_registers after stepping the call");
    let slot = peek_u64(&dbg, after.sp).await.expect("read_memory at the new rsp");

    let got = (after.pc, before.sp.wrapping_sub(after.sp), slot);
    let want = (fx.callee.0, 8u64, fx.after_call);
    assert_eq!(
        got, want,
        "single-stepping the call at {:#x} must land on callee's ELF entry, drop rsp by 8, and \
         push the address after the call; got (pc={:#x}, sp_drop={}, [rsp]={:#x}) while the \
         symbol table and objdump say (pc={:#x}, sp_drop=8, [rsp]={:#x})",
        fx.call_site,
        got.0,
        got.1,
        got.2,
        want.0,
        want.2
    );

    let _ = dbg.kill().await;
}

// ── (2) step_over must be DISTINGUISHABLE from single_step ───────────────────

/// PROVES: from one and the same machine state — stopped on the `call callee`
/// instruction — `single_step` and `step_over` go to DIFFERENT places, and to
/// the two specific places the compiler's own output names: `single_step` into
/// `callee`, `step_over` onto the instruction after the call, with the
/// callee's result (43, from the C source) already in `eax`.
///
/// WHY THAT IS RIGHT: `step_over_a_call_does_not_enter_the_callee` in the
/// sibling file asserts only `pc == after_call`. Measured 2026-08-31: point
/// `call_site`/`after_call` at the instruction pair AFTER the call and that
/// test stays green — because on a non-call `step_over` degenerates to
/// `single_step`, which also lands on the next instruction, which is also what
/// the moved oracle says. What it proves is therefore "step_over advances one
/// instruction", a property `single_step` has too.
///
/// Running BOTH primitives from the same state is what makes the claim
/// falsifiable: if `call_site` is not a call the two land in the same place and
/// leg (a) fails; if `step_over` were secretly `single_step`, leg (b) fails.
/// Two launches rather than one, because there is no way back over a call.
#[tokio::test]
async fn step_over_and_single_step_diverge_at_the_call() {
    let Some(fx) = build_fixture() else {
        eprintln!("[skip] no usable C toolchain / static libc on this host");
        return;
    };

    // Launch A — single_step at the call.
    let ss_pc = {
        let Some((dbg, tid)) = open(&fx).await else {
            eprintln!("[skip] launch failed");
            return;
        };
        assert!(run_to(&dbg, fx.call_site).await, "launch A should reach the call site");
        dbg.single_step(tid).await.expect("single_step at the call");
        let pc = dbg.get_registers(tid).await.expect("get_registers after single_step").pc;
        let _ = dbg.kill().await;
        pc
    };

    // Launch B — step_over at the very same instruction.
    let (so_pc, so_eax) = {
        let Some((dbg, tid)) = open(&fx).await else {
            eprintln!("[skip] second launch failed");
            return;
        };
        assert!(run_to(&dbg, fx.call_site).await, "launch B should reach the call site");
        dbg.step_over(tid).await.expect("step_over at the call");
        let regs = dbg.get_registers(tid).await.expect("get_registers after step_over");
        let eax = eax_of(&regs);
        let _ = dbg.kill().await;
        (regs.pc, eax)
    };

    assert_ne!(
        fx.callee.0, fx.after_call,
        "the fixture is degenerate: callee's entry and the instruction after the call coincide, \
         so the two primitives could not be told apart even in principle"
    );
    assert_eq!(
        (ss_pc, so_pc),
        (fx.callee.0, fx.after_call),
        "from the identical state at {:#x}, single_step must ENTER callee ({:#x}) and step_over \
         must STEP OVER it (landing at {:#x}); got single_step -> {:#x}, step_over -> {:#x}. \
         Equal destinations mean step_over is indistinguishable from single_step here",
        fx.call_site,
        fx.callee.0,
        fx.after_call,
        ss_pc,
        so_pc
    );
    // The callee was not merely skipped past — it RAN. 43 = 21 * 2 + 1, and
    // that arithmetic exists only in the C source above.
    assert_eq!(
        so_eax,
        Some(CALLEE_RESULT),
        "after step_over, eax should hold callee(21) = {CALLEE_RESULT}; got {so_eax:?} — the call \
         was jumped past rather than executed"
    );
}

// ── (3) step_out lands on an ADDRESS, not somewhere in a range ───────────────

/// PROVES: `step_out` from inside `callee` returns to the EXACT instruction
/// after the call, with the callee's return value intact.
///
/// WHY THAT IS RIGHT: the sibling test asserts only that the landing pc is
/// somewhere in `[main, main_end)` and above `call_site`. `main` is a few dozen
/// bytes here, so that admits nearly every address the return could plausibly
/// have; measured, adding 1 to `after_call` does not disturb it at all. A
/// return address is a single number and the disassembly knows which one, so
/// there is no reason to accept a range. `eax` is checked for the same reason
/// as above: a `step_out` implemented as "continue until something stops us"
/// could land on the right address by accident, but not with the callee's
/// result in the return register.
#[tokio::test]
async fn step_out_lands_on_the_exact_instruction_after_the_call() {
    let Some(fx) = build_fixture() else {
        eprintln!("[skip] no usable C toolchain / static libc on this host");
        return;
    };
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };

    assert!(run_to(&dbg, fx.callee.0).await, "the fixture should reach callee");
    // Run the callee's prologue so `[rbp + 8]` describes THIS frame's return
    // slot rather than the caller's.
    for _ in 0..3 {
        dbg.single_step(tid).await.expect("single_step through the callee prologue");
    }

    let ev = dbg.step_out(tid).await.expect("step_out from a framed callee should succeed");
    assert!(!ev.reason.is_exit(), "step_out ran the fixture to exit instead of returning to main");
    let after = dbg.get_registers(tid).await.expect("get_registers after step_out");

    assert_eq!(
        after.pc, fx.after_call,
        "step_out landed at {:#x}; objdump says the instruction after the call to callee is \
         {:#x}. Landing merely inside main [{:#x}, {:#x}) is not a return",
        after.pc,
        fx.after_call,
        fx.main.0,
        fx.main.1
    );
    assert_eq!(
        eax_of(&after),
        Some(CALLEE_RESULT),
        "step_out returned to the right address but eax is not callee(21) = {CALLEE_RESULT}"
    );

    let _ = dbg.kill().await;
}

// ── (4) main entry pinned against its CALLER, not against itself ─────────────

/// PROVES: the address `nm` gives for `main` is the address libc actually
/// CALLS — checked by reading the return slot the call pushed and requiring it
/// to point inside `__libc_start_call_main`, whose extent comes from a second,
/// unrelated row of the symbol table.
///
/// WHY THAT IS RIGHT: measured 2026-08-31, shifting `main`s entry 8 bytes
/// forward (past `endbr64; push rbp; mov rbp,rsp` — a legal instruction
/// boundary) left ALL seven tests of `live_linux_stepping.rs` green, and the
/// first three tests of this file too. Every use of `main.0` in both files is
/// `run_to(main.0)` followed by "did we stop at main.0", which holds for any
/// address in the function, and every use of the `[main, main_end)` interval is
/// a membership test that a shifted interval still satisfies.
///
/// A functions entry point is only distinguishable from its second instruction
/// by something OUTSIDE the function, and the caller is that something: at the
/// true entry `[rsp]` is a return address in libc, whereas 8 bytes later the
/// prologue has pushed `rbp` and `[rsp]` holds a stack address instead. The two
/// legs of the check come from two different symbols, so shifting either one
/// alone breaks it.
#[tokio::test]
async fn the_entry_of_main_is_the_address_libc_calls() {
    let Some(fx) = build_fixture() else {
        eprintln!("[skip] no usable C toolchain / static libc on this host");
        return;
    };
    let Some(caller) = symbol_extent(&fx.path, "__libc_start_call_main") else {
        eprintln!("[skip] this libc does not expose __libc_start_call_main");
        return;
    };
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };

    assert!(run_to(&dbg, fx.main.0).await, "the fixture should reach main");
    let regs = dbg.get_registers(tid).await.expect("get_registers at main");
    let ret = peek_u64(&dbg, regs.sp).await.expect("read_memory at rsp on entry to main");

    assert!(
        ret > caller.0 && ret < caller.1,
        "at main ({:#x}) the word at rsp should be the return address pushed by the call in \
         __libc_start_call_main [{:#x}, {:#x}); it is {:#x}. Either main`s entry is not where \
         nm says it is, or the stop is past the prologue and this is a saved rbp",
        fx.main.0,
        caller.0,
        caller.1,
        ret
    );

    let _ = dbg.kill().await;
}
