//! LIVE Linux stepping — the EDGE CASES, not the happy path.
//!
//! `live_linux_stepping.rs` already covers "does `single_step` move the pc",
//! "does `step_over` skip a call", "does `step_out` return into main". This
//! file starts where those stop, on the five shapes that break a stepper for
//! reasons the ordinary cases never reach:
//!
//!   1. `step_over` at a RECURSIVE call site — the return address the step
//!      plants a trap on is an address the target reaches again in deeper
//!      frames, so "we came back" is only true together with the stack
//!      pointer.
//!   2. `step_out` from the OUTERMOST frame — there is no caller, so the
//!      correct answer is a refusal, and specifically a refusal that leaves
//!      the target exactly where it was.
//!   3. `single_step` on an instruction that JUMPS — the pc must land on the
//!      branch target, not on the following address.
//!   4. stepping while one of our own `int3` traps is planted exactly on the
//!      instruction the step is about to land on.
//!   5. stepping a thread that is NOT the current one.
//!
//! Every test drives a real process: a C fixture compiled on the fly with
//! `cc -O0 -g -static -no-pie` (static + no-pie so the addresses `nm` and
//! `objdump` report are the addresses the process really runs at), launched
//! under `ptrace(2)`. Ground truth for every address assertion comes from the
//! compiler's own output (`nm`, `objdump -d`), never from the debugger.
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::{BreakpointKind, DebugError, Debugger, LaunchOptions, StopReason, ThreadId};
use std::process::Command;
use std::time::Duration;

// ── Fixture ──────────────────────────────────────────────────────────────────

/// `recurse` calls ITSELF, so the instruction after its recursive call site is
/// an address the process visits once per frame — the shape test (1) needs.
/// `spin` contains an ordinary `-O0` `for` loop, which gcc compiles to an
/// unconditional `jmp` to the loop condition — the shape test (3) needs.
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

/// One decoded instruction from `objdump -d`: where it starts, where the next
/// one starts, and the disassembly text.
#[derive(Clone, Debug)]
struct Insn {
    addr: u64,
    next: u64,
    text: String,
}

struct Fixture {
    _dir: tempfile::TempDir,
    path: String,
    /// `[start, end)` of `recurse`, from the ELF symbol table.
    recurse: (u64, u64),
    /// Every instruction of `recurse`, in address order.
    recurse_insns: Vec<Insn>,
    /// Every instruction of `spin`, in address order.
    spin_insns: Vec<Insn>,
}

/// Compile the fixture, or `None` when this host has no usable C toolchain /
/// static libc. `None` rather than a failure: a missing toolchain is not a
/// debugger defect, and a test that reported one would be lying.
fn build_fixture() -> Option<Fixture> {
    let dir = tempfile::tempdir().ok()?;
    let src = dir.path().join("limits.c");
    let exe = dir.path().join("limits");
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
    let spin = symbol_extent(&path, "spin")?;
    let recurse_insns = disassemble_range(&path, recurse)?;
    let spin_insns = disassemble_range(&path, spin)?;
    Some(Fixture { _dir: dir, path, recurse, recurse_insns, spin_insns })
}

/// `[address, address + size)` of a named symbol, from `nm --print-size`.
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

/// Every instruction inside `[range.0, range.1)`, read out of `objdump -d`.
/// `next` is the address of the following listed instruction (the last one in
/// a function gets the function's end), which is exactly "the address a
/// non-branching single step must land on".
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
        // Measured, not assumed — `objdump -d | cat -A` on this fixture:
        //     "  40187f:^Ieb 12                ^Ijmp    401893 <recurse+0x2e>$"
        // i.e. address, TAB, the raw opcode bytes, TAB, the mnemonic. Keeping
        // the whole right-hand side leaves the opcode column glued to the
        // front of the text, and `unconditional_jump`'s "the mnemonic starts
        // the string" check then never matches — the first version of this
        // parser skipped that test silently for exactly that reason. The
        // mnemonic is the LAST tab-separated field.
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

/// The `call <recurse>` instruction inside `recurse` itself — the recursive
/// call site — as `(call address, address after the call)`.
fn recursive_call_site(fx: &Fixture) -> Option<(u64, u64)> {
    fx.recurse_insns
        .iter()
        .find(|i| i.text.contains("call") && i.text.contains("<recurse>"))
        .map(|i| (i.addr, i.next))
}

/// The first unconditional `jmp <hex> <...>` inside `spin`, as
/// `(jmp address, branch target)`. `-O0` compiles the `for` header into
/// exactly one such jump to the loop condition.
///
/// Only `jmp` — never `jle`/`jne`/…: a conditional branch's outcome depends on
/// flags this test does not control, so asserting a landing address for one
/// would be asserting on a coin flip.
fn unconditional_jump(fx: &Fixture) -> Option<(u64, u64)> {
    for i in &fx.spin_insns {
        // objdump prints "jmp    401d3e <spin+0x2a>". Splitting on the
        // mnemonic and requiring the left side (the raw opcode bytes column
        // has already been trimmed away) to be empty means a `jmp` appearing
        // inside a symbol comment cannot be mistaken for the mnemonic.
        let Some((lhs, rhs)) = i.text.split_once("jmp") else { continue };
        if !lhs.trim().is_empty() {
            continue;
        }
        let Some(tok) = rhs.split_whitespace().next() else { continue };
        let Ok(target) = u64::from_str_radix(tok.trim_start_matches("0x"), 16) else { continue };
        if target != i.next {
            return Some((i.addr, target));
        }
    }
    None
}

// ── Harness helpers ──────────────────────────────────────────────────────────

async fn open(fx: &Fixture) -> Option<(LinuxDebugger, ThreadId)> {
    let dbg = LinuxDebugger::new();
    let pid = dbg.launch(LaunchOptions::new(fx.path.clone())).await.ok()?;
    Some((dbg, ThreadId(pid.0)))
}

/// Run the target until it stops at `addr` (planting a software breakpoint
/// there first). `false` when the process exited before getting there —
/// reported by the caller, never asserted away here.
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

// ── 1. step_over at a recursive call site ────────────────────────────────────

/// PROVES: `step_over` at the RECURSIVE `call recurse` inside `recurse` lands
/// on the instruction after that call **in the frame it started in** — not in
/// one of the four deeper frames that reach the very same address first.
///
/// WHY THAT IS RIGHT: `step_over` works by planting a trap at the return
/// address and resuming. With recursion that address is not unique in time:
/// `recurse(4)` returns to it several times, and every one but the last is the
/// WRONG stop. A stepper that matches on the address alone reports a deeper
/// frame's return as the caller's step — the pc assertion passes and the
/// answer is still wrong. The stack pointer is the only observable that tells
/// the frames apart, which is why `sp` is asserted here and not just `pc`.
/// (`before.sp` is exactly what the backend hands `run_to_return` as `min_sp`,
/// so this test exercises the guard that exists for this case.)
#[tokio::test]
async fn step_over_a_recursive_call_returns_to_the_frame_it_started_in() {
    let fx = fixture_or_skip!();
    // A PANIC, not a skip. The fixture compiled (`build_fixture` returned),
    // and `recurse` calls itself, so "no recursive call site" can only mean
    // this file's objdump parser is broken — and a silent skip there is a
    // green that was never earned. It already happened once: the parser kept
    // the opcode-byte column and this test skipped itself while reporting ok.
    let Some((call_site, after_call)) = recursive_call_site(&fx) else {
        panic!(
            "no `call <recurse>` found inside recurse — the objdump parser is broken. \
             Disassembly seen: {:#?}",
            fx.recurse_insns
        )
    };
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };

    assert!(run_to(&dbg, call_site).await, "the fixture should reach the recursive call site");
    let before = dbg.get_registers(tid).await.expect("get_registers at the recursive call site");
    assert_eq!(before.pc, call_site, "run_to should leave the pc on the call, not past it");

    let ev = tokio::time::timeout(Duration::from_secs(60), dbg.step_over(tid))
        .await
        .expect("step_over over a recursive call must not hang")
        .expect("step_over over a recursive call should succeed");
    assert!(
        !ev.reason.is_exit(),
        "step_over over a recursive call ran the fixture to exit: {:?}",
        ev.reason
    );

    let after = dbg.get_registers(tid).await.expect("get_registers after step_over");
    assert_eq!(
        after.pc, after_call,
        "step_over should land on the instruction after the recursive call ({after_call:#x}), got {:#x}",
        after.pc
    );
    assert!(
        after.sp >= before.sp,
        "step_over reported a stop at the right ADDRESS but in a DEEPER frame: sp went {:#x} -> \
         {:#x}. That is one of the recursive calls returning, not the step the caller asked for",
        before.sp,
        after.sp
    );

    let _ = dbg.kill().await;
}

// ── 2. step_out from the outermost frame ─────────────────────────────────────

/// PROVES: `step_out` at the process's very first stop — the trap raised by
/// `execve` under `PTRACE_TRACEME`, where no user frame has been pushed and
/// the frame register is zero per the SysV ABI — is REFUSED, and refusing it
/// leaves the target exactly where it was.
///
/// WHY THAT IS RIGHT: "step out of the outermost frame" has no correct
/// destination. The only two honest answers are an error or a no-op; the one
/// answer that must never happen is the target being resumed, because
/// `step_out` computes its destination by reading `[fp + 8]` and, with `fp`
/// zero or garbage, that word is not a return address — planting a trap on it
/// writes an `int3` into whatever it happens to point at. The second half of
/// this test is the load-bearing half: after the refusal the pc must be
/// unchanged and the process must still be steppable, which is what proves the
/// refusal happened BEFORE anything was resumed or patched.
#[tokio::test]
async fn step_out_from_the_outermost_frame_is_refused_without_disturbing_the_target() {
    let fx = fixture_or_skip!();
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };

    let before = dbg.get_registers(tid).await.expect("get_registers at the exec trap");
    let outcome = dbg.step_out(tid).await;

    match outcome {
        Err(DebugError::StepError(msg)) => {
            eprintln!("[measured] step_out at the entry stop refused with: {msg}");
        }
        Err(other) => {
            panic!("step_out at the outermost frame failed with the wrong error kind: {other:?}")
        }
        Ok(ev) => panic!(
            "step_out from the OUTERMOST frame reported SUCCESS ({:?}). There is no caller to \
             return to: the destination it used came from reading [fp + 8] with fp = {:?}, which \
             is not a return address",
            ev.reason, before.fp
        ),
    }

    let after = dbg.get_registers(tid).await.expect("get_registers after the refused step_out");
    assert_eq!(
        after.pc, before.pc,
        "a REFUSED step_out moved the program counter from {:#x} to {:#x} — the refusal came \
         after the target had already been resumed",
        before.pc, after.pc
    );

    // A refusal that left the session unusable would be no better than the
    // resume it avoided, so the target is stepped once to prove it survived.
    let ev = dbg
        .single_step(tid)
        .await
        .expect("the target must still be steppable after a refused step_out");
    assert!(!ev.reason.is_exit(), "the target died during a refused step_out");
    let stepped = dbg.get_registers(tid).await.expect("get_registers after the recovery step");
    assert_ne!(stepped.pc, before.pc, "the target did not advance after the refused step_out");

    let _ = dbg.kill().await;
}

// ── 3. single_step over a branch ─────────────────────────────────────────────

/// PROVES: `single_step` on an unconditional `jmp` leaves the pc on the BRANCH
/// TARGET, not on the address that follows the jump in memory.
///
/// WHY THAT IS RIGHT: every other stepping test in this suite would pass on a
/// backend that simply added the instruction length to the pc — the fixtures
/// walk straight-line code. A jump is the one instruction where "the next
/// instruction" and "the next address" differ, so it is the only shape that
/// can tell a real `PTRACE_SINGLESTEP` apart from arithmetic on the pc. Both
/// the jump's address and its target come from `objdump`, so the expected
/// answer is the compiler's, not the debugger's.
#[tokio::test]
async fn single_step_over_an_unconditional_jump_lands_on_the_branch_target() {
    let fx = fixture_or_skip!();
    // A PANIC, not a skip — same reasoning as the recursive test: `-O0`
    // compiles `spin`'s `for` header into an unconditional `jmp` to the loop
    // condition, so an empty result means this file's parser stopped working,
    // and a skip would hide that behind a green.
    let Some((jmp_at, target)) = unconditional_jump(&fx) else {
        panic!(
            "no unconditional `jmp` found inside spin — the objdump parser is broken. \
             Disassembly seen: {:#?}",
            fx.spin_insns
        )
    };
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };

    assert!(run_to(&dbg, jmp_at).await, "the fixture should reach the jmp at {jmp_at:#x}");
    let before = dbg.get_registers(tid).await.expect("get_registers at the jmp");
    assert_eq!(before.pc, jmp_at);

    let ev = dbg.single_step(tid).await.expect("single_step on a jmp should succeed");
    assert!(!ev.reason.is_exit(), "single_step on a jmp ran the fixture to exit");
    let after = dbg.get_registers(tid).await.expect("get_registers after stepping the jmp");

    assert_eq!(
        after.pc, target,
        "single_step on the `jmp` at {jmp_at:#x} landed at {:#x}; the branch target is \
         {target:#x}. Landing on the address that merely FOLLOWS the jump would mean the pc was \
         computed rather than executed",
        after.pc
    );

    let _ = dbg.kill().await;
}

// ── 4. stepping onto a planted breakpoint ────────────────────────────────────

/// PROVES: when one of our own `int3` traps is planted on exactly the
/// instruction a `single_step` is about to LAND on, the step reports itself as
/// a step (pc on the trapped instruction, which has not run yet) — and a
/// second `single_step` from there still executes the real instruction rather
/// than the `0xCC` that replaced it.
///
/// WHY THAT IS RIGHT: a single step stops BEFORE the instruction at the
/// destination executes, so the trap must not fire and the stop is not a
/// breakpoint hit — reporting `Breakpoint` here would tell the caller its
/// breakpoint was reached when the program never ran that instruction. The
/// second step is the half that actually bites: standing on a planted trap, a
/// naive `PTRACE_SINGLESTEP` executes the `int3` instead of the byte it
/// replaced, the trap fires at the same address, and the pc does not move — a
/// debugger that looks frozen while reporting success. The backend's
/// `step_off_planted_breakpoint` exists for exactly this, and only a live
/// process with a real `0xCC` in it can prove it runs.
#[tokio::test]
async fn stepping_onto_a_planted_trap_reports_a_step_and_can_step_off_it() {
    let fx = fixture_or_skip!();
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };

    // Park on `recurse`'s entry, then take its first two instructions: `here`
    // is where we stand, `next` is where the step must land and where the
    // extra trap is planted. Neither is a branch (they are the opening
    // instructions of a function body), so `next` is decidable.
    assert!(run_to(&dbg, fx.recurse.0).await, "the fixture should reach recurse");
    let here = fx.recurse_insns[0].clone();
    let next = fx.recurse_insns[1].clone();
    let regs = dbg.get_registers(tid).await.expect("get_registers at recurse");
    assert_eq!(regs.pc, here.addr, "run_to should park us on recurse's first instruction");

    dbg.set_breakpoint(Address(next.addr), BreakpointKind::Software)
        .await
        .expect("planting a trap on the next instruction should succeed");

    let ev = dbg
        .single_step(tid)
        .await
        .expect("single_step onto a trapped instruction should succeed");
    assert!(!ev.reason.is_exit(), "the step ran the fixture to exit");
    assert!(
        matches!(ev.reason, StopReason::SingleStep { .. }),
        "stepping ONTO a planted trap was reported as {:?}. The instruction at {:#x} has not \
         executed yet, so its breakpoint has not been hit",
        ev.reason,
        next.addr
    );
    let landed = dbg.get_registers(tid).await.expect("get_registers after the step");
    assert_eq!(
        landed.pc, next.addr,
        "the step should land on {:#x} (the trapped instruction), got {:#x}",
        next.addr, landed.pc
    );

    // Now the load-bearing half: step again while standing on the trap.
    let ev2 = dbg.single_step(tid).await.expect("single_step off a planted trap should succeed");
    assert!(!ev2.reason.is_exit(), "the second step ran the fixture to exit");
    let after = dbg.get_registers(tid).await.expect("get_registers after the second step");
    assert_ne!(
        after.pc, next.addr,
        "single_step from ON a planted trap at {:#x} left the pc where it was — the `int3` was \
         executed instead of the instruction it replaced, so the caller asked for one \
         instruction and got none",
        next.addr
    );
    assert_eq!(
        after.pc, next.next,
        "the second step should land on {:#x} (the instruction after the trapped one), got {:#x}",
        next.next, after.pc
    );

    let _ = dbg.kill().await;
}

/// PROVES: `step_over` on a NON-call instruction whose successor carries one
/// of our own planted traps still lands on that successor, exactly once.
///
/// WHY THAT IS RIGHT: `step_over` decodes the instruction at the pc to compute
/// a return address, and it reads those bytes with `read_memory` — which
/// returns the process's memory verbatim, `0xCC` patches included. The trap
/// planted here sits on the NEXT instruction, so a decoder that reads one byte
/// too far, or a length computed over patched bytes, shows up as a landing
/// address that is not `next`. The instruction stepped is not a call, so
/// `step_over` must behave exactly like `single_step` and must not resume.
#[tokio::test]
async fn step_over_with_a_trap_on_the_next_instruction_lands_on_it() {
    let fx = fixture_or_skip!();
    let Some((dbg, tid)) = open(&fx).await else {
        eprintln!("[skip] launch failed");
        return;
    };

    assert!(run_to(&dbg, fx.recurse.0).await, "the fixture should reach recurse");
    let here = fx.recurse_insns[0].clone();
    let next = fx.recurse_insns[1].clone();
    assert!(
        !here.text.contains("call"),
        "this test needs a non-call instruction; recurse starts with `{}`",
        here.text
    );
    dbg.set_breakpoint(Address(next.addr), BreakpointKind::Software)
        .await
        .expect("planting a trap on the next instruction should succeed");

    let ev = tokio::time::timeout(Duration::from_secs(30), dbg.step_over(tid))
        .await
        .expect("step_over must not hang when a trap sits on the next instruction")
        .expect("step_over should succeed");
    assert!(
        !ev.reason.is_exit(),
        "step_over over `{}` ran the fixture to EXIT; a step over a non-call instruction must \
         never resume the process",
        here.text
    );
    let after = dbg.get_registers(tid).await.expect("get_registers after step_over");
    assert_eq!(
        after.pc, next.addr,
        "step_over from {:#x} (`{}`) should land on {:#x}, got {:#x}",
        here.addr, here.text, next.addr, after.pc
    );

    let _ = dbg.kill().await;
}

// ── 5. stepping a thread that is not the current one ─────────────────────────

/// A two-thread fixture: the worker spins forever so it is guaranteed alive,
/// and main spins after `raise(SIGTRAP)` so the process cannot exit while the
/// test is inspecting it.
const THREADED_C: &str = r#"
#include <pthread.h>
#include <signal.h>
static volatile int ready = 0;
static void *worker(void *arg) { (void)arg; ready = 1; for (;;) { } return 0; }
int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    while (!ready) { }
    raise(SIGTRAP);
    for (;;) { }
    return 0;
}
"#;

fn build_threaded() -> Option<(tempfile::TempDir, String)> {
    let dir = tempfile::tempdir().ok()?;
    let src = dir.path().join("threaded.c");
    let exe = dir.path().join("threaded");
    std::fs::write(&src, THREADED_C).ok()?;
    let out = Command::new("cc")
        .args(["-O0", "-g"])
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .arg("-lpthread")
        .output()
        .ok()?;
    if !out.status.success() {
        eprintln!("[fixture] cc failed: {}", String::from_utf8_lossy(&out.stderr));
        return None;
    }
    let path = exe.to_str()?.to_string();
    Some((dir, path))
}

/// PROVES: `single_step(tid)` steps the thread it was HANDED, and the event it
/// returns belongs to that thread — even when the thread that most recently
/// stopped (and which `current_thread()` therefore reports) is a different
/// one.
///
/// WHY THAT IS RIGHT: the Linux backend's debug loop waits on the whole
/// process, and `step_off_planted_breakpoint` used to read `current_tid`
/// unconditionally, so asking to step thread B while thread A sat on a trap
/// stepped **A** and handed that event back as B's answer — the caller was
/// told its thread had advanced when a different one had. `event.tid` is the
/// observable that separates the two, and the target thread's own pc is the
/// observable that proves it really ran. Both are asserted, because either one
/// alone can be satisfied by the wrong behaviour.
#[tokio::test]
async fn single_step_targets_the_requested_thread_not_the_current_one() {
    let Some((_dir, bin)) = build_threaded() else {
        eprintln!("[skip] no usable C toolchain / pthreads on this host");
        return;
    };
    let dbg = LinuxDebugger::new();
    let Ok(pid) = dbg.launch(LaunchOptions::new(bin.clone())).await else {
        eprintln!("[skip] launch failed");
        return;
    };

    // Resume until the fixture's own `raise(SIGTRAP)`, consuming the thread
    // birth stops on the way. Bounded, and `break`ing on anything unexpected:
    // resuming *until* a condition holds would hang on a host that never
    // delivers another stop, and a hang is not a measurement.
    let mut reached = false;
    for _ in 0..64 {
        let Ok(res) = tokio::time::timeout(Duration::from_secs(30), dbg.continue_execution()).await
        else {
            break;
        };
        let Ok(ev) = res else { break };
        match ev.reason {
            StopReason::ThreadCreate { .. } => continue,
            StopReason::ProcessExit { .. } => break,
            _ => {
                reached = true;
                break;
            }
        }
    }
    if !reached {
        eprintln!("[skip] the threaded fixture never reached its synchronisation stop");
        let _ = dbg.kill().await;
        return;
    }

    let threads = dbg.threads().await.expect("threads() must work on a live multi-threaded target");
    let current = dbg.current_thread().await.expect("current_thread() after a stop");
    let Some(other) = threads.iter().copied().find(|t| *t != current) else {
        eprintln!("[skip] only one thread visible ({}) — nothing to cross-step", threads.len());
        let _ = dbg.kill().await;
        return;
    };
    assert_eq!(pid.0, dbg.target_pid().expect("target_pid").0);

    let before_other = dbg
        .get_registers(other)
        .await
        .expect("get_registers on the non-current thread must work before stepping it");

    let ev = tokio::time::timeout(Duration::from_secs(30), dbg.single_step(other))
        .await
        .expect("single_step on a non-current thread must not hang")
        .expect("single_step on a non-current thread should succeed");

    assert_eq!(
        ev.tid, other,
        "single_step({other:?}) returned an event for {:?} — the caller asked for one thread and \
         was told about another (current_thread was {current:?})",
        ev.tid
    );
    assert!(!ev.reason.is_exit(), "stepping the worker thread killed the process: {:?}", ev.reason);

    let after_other = dbg.get_registers(other).await.expect("get_registers on the stepped thread");
    assert_ne!(
        after_other.pc, before_other.pc,
        "single_step({other:?}) returned successfully but the thread's pc stayed at {:#x} — the \
         step was applied somewhere else",
        before_other.pc
    );

    let _ = dbg.kill().await;
}
