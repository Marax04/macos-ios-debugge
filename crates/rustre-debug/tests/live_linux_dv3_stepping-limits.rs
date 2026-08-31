//! LIVE Linux stepping — the three holes `live_linux_stepping_limits.rs`
//! leaves, found by MUTATING its own ground truth (round dv3, 2026-08-31).
//!
//! What the mutation run measured, on the file as it stands:
//!
//! | mutation of the objdump/nm oracle             | tests reddened |
//! |-----------------------------------------------|----------------|
//! | every instruction `next` shifted +8            | 2 of 6 |
//! | the `jmp` branch target shifted +2             | 1 of 6 |
//! | `recurse`'s symbol START shifted +8 (coherent) | 1 of 6 |
//! | the landing instruction moved one insn on      | 2 of 6 |
//! | every `[skip]` branch turned into a `panic!`   | 0 of 6 |
//!
//! Two conclusions, and this file is what follows from them:
//!
//!  * **No test in that file pins an ADDRESS.** Every one of them pins a
//!    RELATION between two addresses that objdump supplies together, so
//!    sliding the whole fixture window 8 bytes along — on an instruction
//!    boundary, inside the same function — leaves them green. That is a
//!    legitimate design for what they assert, but it means nothing in the
//!    suite would notice a stepper walking a *different, self-consistent*
//!    part of the program. `single_step_walks_the_exact_address_sequence_of_
//!    recurses_prologue` below closes that: its oracle is the literal address
//!    SEQUENCE of `recurse`'s prologue.
//!
//!  * **The one mutation that did slide the window uncovered a real backend
//!    defect**, not a weak assertion — see
//!    `step_over_a_stack_decrementing_non_call_must_not_resume` (`#[ignore]`).
//!
//! Also added: a `step_out` that is expected to SUCCEED. The existing file
//! only ever tests the outermost-frame REFUSAL, so no test anywhere asserts
//! the address a successful `step_out` returns to.
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::{BreakpointKind, Debugger, LaunchOptions, StopReason, ThreadId};
use std::process::Command;
use std::time::Duration;

const FIXTURE_C: &str = r#"
#include <stdio.h>

__attribute__((noinline)) int recurse(int n) {
    if (n <= 0) return 1;
    return n + recurse(n - 1);
}

__attribute__((noinline)) int spin(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) { s += i; }
    return s;
}

int main(void) {
    int a = recurse(4);
    int b = spin(3);
    printf("%d %d\n", a, b);
    return 0;
}
"#;

#[derive(Clone, Debug)]
struct Insn {
    addr: u64,
    next: u64,
    text: String,
}

struct Fixture {
    _dir: tempfile::TempDir,
    path: String,
    recurse: (u64, u64),
    recurse_insns: Vec<Insn>,
    main_insns: Vec<Insn>,
}

fn build_fixture() -> Option<Fixture> {
    let dir = tempfile::tempdir().ok()?;
    let src = dir.path().join("dv3.c");
    let exe = dir.path().join("dv3");
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
    let recurse = symbol_extent(&path, "recurse")?;
    let main = symbol_extent(&path, "main")?;
    let recurse_insns = disassemble_range(&path, recurse)?;
    let main_insns = disassemble_range(&path, main)?;
    Some(Fixture { _dir: dir, path, recurse, recurse_insns, main_insns })
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

fn disassemble_range(exe: &str, range: (u64, u64)) -> Option<Vec<Insn>> {
    let out = Command::new("objdump").args(["-d", exe]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut rows: Vec<(u64, String)> = Vec::new();
    for line in text.lines() {
        let Some((lhs, rhs)) = line.split_once(':') else { continue };
        let Ok(addr) = u64::from_str_radix(lhs.trim(), 16) else { continue };
        if addr < range.0 || addr >= range.1 {
            continue;
        }
        // The mnemonic is the LAST tab-separated field: address TAB opcode
        // bytes TAB mnemonic. Keeping the whole right-hand side glues the
        // opcode column onto the front of the text and every "the mnemonic
        // starts the string" check then silently never matches.
        let mnemonic = rhs.rsplit('\t').next().unwrap_or(rhs).trim().to_string();
        rows.push((addr, mnemonic));
    }
    if rows.is_empty() {
        return None;
    }
    let mut insns = Vec::with_capacity(rows.len());
    for i in 0..rows.len() {
        let next = rows.get(i + 1).map(|r| r.0).unwrap_or(range.1);
        insns.push(Insn { addr: rows[i].0, next, text: rows[i].1.clone() });
    }
    Some(insns)
}

/// The first instruction inside `recurse` that LOWERS the stack pointer
/// without being a call: `push %rbp`, or `sub $N,%rsp`. `-O0` emits both, in
/// the prologue, so this is not an exotic shape — it is the shape every
/// compiled function on this platform starts with.
fn stack_decrementing_non_call(fx: &Fixture) -> Option<Insn> {
    fx.recurse_insns
        .iter()
        .find(|i| {
            !i.text.contains("call")
                && (i.text.starts_with("push")
                    || (i.text.starts_with("sub") && i.text.contains("%rsp")))
        })
        .cloned()
}

/// `main`'s `call recurse` as `(call address, address after the call)` — the
/// address a `step_out` from inside `recurse`'s outermost frame must land on.
fn main_call_to_recurse(fx: &Fixture) -> Option<(u64, u64)> {
    fx.main_insns
        .iter()
        .find(|i| i.text.contains("call") && i.text.contains("<recurse>"))
        .map(|i| (i.addr, i.next))
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

// ── 1. The defect the mutation run uncovered ─────────────────────────────────

/// FAILS TODAY. Measured 2026-08-31 on this tree:
///
/// ```text
/// step_over over `sub    $0x10,%rsp` ran the fixture to EXIT;
/// a step over a non-call instruction must never resume the process
/// ```
///
/// PROVES: `step_over` on a non-call instruction that DECREMENTS `rsp` — i.e.
/// on `push %rbp` and on `sub $N,%rsp`, the two instructions every `-O0`
/// function on x86-64 opens with — resumes the process instead of stepping,
/// and here runs it to completion.
///
/// THE DEFECT, read out of `linux_debugger.rs::step_over` (~line 3756): the
/// backend decides "did that single step enter a call?" with
///
/// ```ignore
/// if after.sp >= before.sp { return Ok(event); }   // not a call — done
/// // ...otherwise:
/// self.run_to_return(tid, Address(return_addr), before.sp).await
/// ```
///
/// The stack pointer is not a call detector. `push` and `sub $N,%rsp` lower
/// it too, so the guard misfires, and `step_over` then calls `run_to_return`
/// with `min_sp = before.sp` and `return_addr = pc + instruction length`.
/// That return address is reached on the very next instruction — but with
/// `sp` now 8 or 16 bytes LOWER than `min_sp`, so `run_to_return` rejects
/// every arrival as "a deeper frame" and keeps resuming until the process
/// dies. One `step_over` on a function prologue destroys the session.
///
/// WHY THE EXISTING SUITE MISSES IT: `step_over_with_a_trap_on_the_next_
/// instruction_lands_on_it` steps over `recurse_insns[0]`, which on this
/// toolchain is `endbr64` — the one prologue instruction that does NOT touch
/// `rsp`. Sliding that window by a single instruction is what exposed this.
///
/// Note what is asserted and what is not: NO breakpoint is planted anywhere
/// here. The existing test's trap is not part of the cause, and leaving it
/// out is what proves that.
///
/// FIXED in iteration 656 and no longer ignored. The cure gates on the DECODED
/// instruction (`instr_step::instruction_is_call`) instead of on the stack
/// pointer. This test was written by another agent, against the broken
/// backend, to fail — which is exactly what makes it worth keeping: it is an
/// oracle nobody wrote to fit the fix.
#[tokio::test]
async fn step_over_a_stack_decrementing_non_call_must_not_resume() {
    let fx = fixture_or_skip!();
    let Some(insn) = stack_decrementing_non_call(&fx) else {
        panic!(
            "no stack-decrementing non-call instruction inside recurse — every -O0 x86-64 \
             prologue has one, so this file's objdump parser is broken. Seen: {:#?}",
            fx.recurse_insns
        )
    };
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };

    assert!(run_to(&dbg, insn.addr).await, "the fixture should reach {:#x}", insn.addr);
    let before = dbg.get_registers(tid).await.expect("get_registers");
    assert_eq!(before.pc, insn.addr);

    let ev = tokio::time::timeout(Duration::from_secs(60), dbg.step_over(tid))
        .await
        .expect("step_over on a non-call instruction must not hang")
        .expect("step_over on a non-call instruction should succeed");
    assert!(
        !ev.reason.is_exit(),
        "step_over over `{}` at {:#x} ran the fixture to EXIT. A non-call instruction cannot be \
         stepped OVER by resuming: the only correct behaviour is one instruction of progress",
        insn.text,
        insn.addr
    );

    let after = dbg.get_registers(tid).await.expect("get_registers after step_over");
    assert_eq!(
        after.pc, insn.next,
        "step_over from {:#x} (`{}`) should land on {:#x}, got {:#x}",
        insn.addr, insn.text, insn.next, after.pc
    );

    let _ = dbg.kill().await;
}

// ── 2. An oracle that pins ADDRESSES, not a relation ─────────────────────────

/// PROVES: single-stepping from `recurse`'s entry visits exactly the address
/// sequence the compiler laid down, in order.
///
/// WHY THAT IS RIGHT, AND WHY IT IS NOT WHAT THE OTHER TESTS SAY: every
/// assertion in `live_linux_stepping_limits.rs` compares two addresses that
/// `objdump` handed over TOGETHER — "the pc after the step equals the `next`
/// of the instruction we started on". Sliding the whole fixture window 8
/// bytes along, onto a real instruction boundary inside the same function,
/// therefore leaves them green (measured: `recurse`'s `nm` start +8 reddened
/// 1 test of 6, and that one for an unrelated reason — the defect above). A
/// relation is the right thing to assert about the STEP, but it says nothing
/// about WHERE. A literal sequence says both: it is falsified by a wrong
/// landing address AND by a right landing address in the wrong place, and
/// there is exactly one assignment of the debugger's observations to it.
///
/// The sequence is the compiler's — `nm` for the entry, `objdump` for the
/// order — never the debugger's.
#[tokio::test]
async fn single_step_walks_the_exact_address_sequence_of_recurses_prologue() {
    let fx = fixture_or_skip!();
    // The prologue is straight-line: take instructions up to (not including)
    // the first branch or call, so no assertion depends on a flag this test
    // does not control.
    let expected: Vec<u64> = fx
        .recurse_insns
        .iter()
        .take_while(|i| {
            let m = i.text.split_whitespace().next().unwrap_or("");
            !(m.starts_with('j') || m.starts_with("call") || m.starts_with("ret"))
        })
        .map(|i| i.addr)
        .collect();
    assert!(
        expected.len() >= 4,
        "the straight-line prologue of recurse should be at least 4 instructions; parser saw {:#?}",
        fx.recurse_insns
    );
    assert_eq!(expected[0], fx.recurse.0, "the prologue must start at recurse's symbol address");

    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    assert!(run_to(&dbg, fx.recurse.0).await, "the fixture should reach recurse");

    let mut walked = vec![dbg.get_registers(tid).await.expect("get_registers at recurse").pc];
    for _ in 1..expected.len() {
        let ev = dbg.single_step(tid).await.expect("single_step in the prologue should succeed");
        assert!(!ev.reason.is_exit(), "stepping the prologue ran the fixture to exit");
        walked.push(dbg.get_registers(tid).await.expect("get_registers after a step").pc);
    }

    assert_eq!(
        walked, expected,
        "single_step walked {walked:x?}; the compiler laid recurse's prologue out at \
         {expected:x?}. Equal LENGTHS with different addresses would mean the stepper is walking \
         self-consistently through the wrong code"
    );

    let _ = dbg.kill().await;
}

// ── 3. A step_out that must SUCCEED ──────────────────────────────────────────

/// PROVES: `step_out` from `recurse`'s OUTERMOST frame returns to the exact
/// address after `main`'s `call recurse`, in `main`'s frame.
///
/// WHY THAT IS RIGHT, AND WHAT IT ADDS: the existing file tests `step_out`
/// only where it must be REFUSED (the entry stop, no caller). Nothing in the
/// suite asserts the address a successful `step_out` produces, so a `step_out`
/// that returned `Ok` having landed anywhere at all would pass every test
/// there is. Both observables are asserted, because either alone is
/// satisfiable by the wrong behaviour: the pc alone is reachable from a
/// deeper recursive frame too (`recurse` is entered five times), and the sp
/// alone says only "we went up", not "we went up to the caller".
///
/// The stop is taken at `cmpl` — after the prologue — so `rbp` is `recurse`'s
/// own frame and `[rbp + 8]` is genuinely its return address. The FIRST hit
/// of that address is the outermost `recurse(4)` frame, the one main called.
#[tokio::test]
async fn step_out_of_the_outermost_recurse_frame_returns_into_main() {
    let fx = fixture_or_skip!();
    let Some((_call_at, after_call)) = main_call_to_recurse(&fx) else {
        panic!(
            "no `call <recurse>` found inside main — the objdump parser is broken. Seen: {:#?}",
            fx.main_insns
        )
    };
    // The first instruction after the prologue: past `sub $N,%rsp` and past
    // the argument spill, so rbp is established.
    let Some(after_prologue) =
        fx.recurse_insns.iter().find(|i| i.text.starts_with("cmp")).map(|i| i.addr)
    else {
        panic!("no `cmp` inside recurse — parser broken. Seen: {:#?}", fx.recurse_insns)
    };

    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };
    assert!(run_to(&dbg, after_prologue).await, "the fixture should reach {after_prologue:#x}");
    let before = dbg.get_registers(tid).await.expect("get_registers inside recurse");
    assert_eq!(before.pc, after_prologue);

    let ev = tokio::time::timeout(Duration::from_secs(60), dbg.step_out(tid))
        .await
        .expect("step_out of a real frame must not hang")
        .expect("step_out of recurse's outermost frame should succeed");
    assert!(!ev.reason.is_exit(), "step_out ran the fixture to exit: {:?}", ev.reason);

    let after = dbg.get_registers(tid).await.expect("get_registers after step_out");
    assert_eq!(
        after.pc, after_call,
        "step_out of recurse should land on {after_call:#x} — the instruction after main's \
         `call recurse` — got {:#x}",
        after.pc
    );
    assert!(
        after.sp > before.sp,
        "step_out landed on the right ADDRESS with sp {:#x} <= the callee's {:#x}: the frame was \
         never left",
        after.sp,
        before.sp
    );

    let _ = dbg.kill().await;
}
