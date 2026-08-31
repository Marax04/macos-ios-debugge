#![cfg(target_os = "linux")]
//! Address-pinning and trap-presence coverage for tracepoints, measured live.
//!
//! WHY THIS FILE EXISTS — the measured gap in `live_linux_tracepoints.rs`.
//!
//! That file was mutated coherently (every oracle moved together) to find out
//! what it really pins down. Two mutations left all sixteen of its tests green:
//!
//! ```text
//! trace_me := nm("trace_me") + 8   -> 16 passed; 0 failed
//! trace_me := nm("trace_me") + 11  -> 16 passed; 0 failed
//! ```
//!
//! +8 is `mov %edi,-0x4(%rbp)` and +11 is `mov -0x4(%rbp),%eax`: both are real
//! instruction boundaries INSIDE `trace_me`, both are past `push %rbp`. Every
//! oracle in that file is a property of the FUNCTION — five crossings, the
//! argument register, `g_iter` — and all of them survive the target sliding
//! down the prologue. Its own doc comment claims the breakpoint "stops before
//! the prologue"; nothing there can tell whether that is true.
//!
//! It matters for tracepoints specifically. The whole file reads `rdi` as "the
//! caller's argument", which is only sound at the entry instruction; a few
//! bytes further in, a compiler that reused `rdi` would hand a tracepoint a
//! plausible wrong number and no assertion would notice.
//!
//! So the tests below pin the ADDRESS, with witnesses that are outside the
//! debugger's own bookkeeping:
//!
//! * the return address on the stack. At the entry instruction `[sp]` is the
//!   return address and must point inside `main`; one instruction later it is
//!   the saved `rbp` and points at the stack. This is an off-by-anything
//!   detector that needs no symbol from the debugger.
//! * `/proc/<pid>/mem`, read by the test process itself (which IS the tracer,
//!   so the read is permitted). It shows the raw byte the tracee will execute,
//!   so "the trap is planted" stops being an act of faith.
//! * a third witness of the pass number, `g_sum`, whose value at each entry the
//!   SOURCE fixes at 0, 1, 9, 24, 46. Together with `rdi` and `g_iter` that is
//!   a triple, not a count: no single relocated oracle can reproduce it.
//!
//! The `/proc` witness also closes a vacuity: the existing
//! `a_tracepoint_on_an_address_never_reached_invents_no_output` asserts only
//! absences, so it passes just as well if the trap was never written into the
//! tracee at all. Here the 0xCC is shown to be present first.

use rustre_core::address::Address;
use rustre_debug::conditional_breakpoint::{
    ConditionOperand, EvalContext, MapEvalContext, Tracepoint, TracepointFormat,
};
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::{
    BreakpointKind, DebugEvent, Debugger, LaunchOptions, OutputRedirect,
    StopReason, ThreadId,
};

#[cfg(target_arch = "x86_64")]
const ARG_REG: &str = "rdi";
#[cfg(target_arch = "aarch64")]
const ARG_REG: &str = "x0";

/// Ground truth read off the fixture source, never off the debugger: on the
/// i-th crossing the argument is `i * 7 + 1`, `g_iter` is `i`, and `g_sum` is
/// the sum of the arguments of the PREVIOUS crossings (it is added to inside
/// the callee, so at the entry it still holds the running total).
const WITNESSES: [(u64, u64, u64); 5] =
    [(1, 0, 0), (8, 1, 1), (15, 2, 9), (22, 3, 24), (29, 4, 46)];

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
    /// Entry address AND size, so "inside the function" is expressible.
    trace_me: (u64, u64),
    never_called: (u64, u64),
    main: (u64, u64),
    g_iter: u64,
    g_sum: u64,
}

/// `nm -S` — the size column is what lets a test say "this address is inside
/// `main`" without asking the debugger, which is the point of the whole file.
fn build_fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("dv3tp_fixture.c");
    let exe = dir.path().join("dv3tp_fixture");
    std::fs::write(&src, FIXTURE_C).expect("write fixture source");
    let out = std::process::Command::new("cc")
        .args(["-no-pie", "-O0", "-g"])
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .output()
        .expect("cc must be available");
    assert!(out.status.success(), "cc failed: {}", String::from_utf8_lossy(&out.stderr));
    let nm = std::process::Command::new("nm")
        .arg("-S")
        .arg(&exe)
        .output()
        .expect("nm -S");
    assert!(nm.status.success(), "nm -S failed");
    let listing = String::from_utf8_lossy(&nm.stdout).to_string();
    Fixture {
        _dir: dir,
        exe: exe.to_string_lossy().to_string(),
        trace_me: sized(&listing, "trace_me"),
        never_called: sized(&listing, "never_called"),
        main: sized(&listing, "main"),
        g_iter: sized(&listing, "g_iter").0,
        g_sum: sized(&listing, "g_sum").0,
    }
}

/// A sized `nm -S` row is `addr size kind name`; an unsized one is
/// `addr kind name`. Only the four-column form carries the extent, and every
/// symbol this file wants has one.
fn sized(listing: &str, want: &str) -> (u64, u64) {
    for line in listing.lines() {
        let p: Vec<&str> = line.split_whitespace().collect();
        if p.len() == 4
            && p[3] == want
            && let (Ok(a), Ok(s)) = (u64::from_str_radix(p[0], 16), u64::from_str_radix(p[1], 16))
        {
            return (a, s);
        }
    }
    panic!("`nm -S` must report an address AND a size for `{want}`");
}

/// Read the tracee's memory WITHOUT the debugger. The test process is the
/// tracer and the tracee is stopped, so `/proc/<pid>/mem` is readable and is
/// the byte the CPU would actually fetch — no shadow, no cache, no bookkeeping.
fn raw_bytes(pid: u32, addr: u64, n: usize) -> Vec<u8> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(format!("/proc/{pid}/mem"))
        .expect("the tracer must be able to open /proc/<pid>/mem of its tracee");
    f.seek(SeekFrom::Start(addr)).expect("seek /proc/<pid>/mem");
    let mut b = vec![0u8; n];
    f.read_exact(&mut b).expect("read /proc/<pid>/mem");
    b
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

/// Continue to the next breakpoint stop at `addr` belonging to THIS tracee.
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

async fn read_u64(dbg: &LinuxDebugger, addr: u64, width: usize) -> u64 {
    let bytes = dbg.read_memory(Address(addr), width).await.expect("read_memory");
    let mut buf = [0u8; 8];
    let n = bytes.len().min(8);
    buf[..n].copy_from_slice(&bytes[..n]);
    u64::from_le_bytes(buf)
}

async fn ctx_at(dbg: &LinuxDebugger, tid: ThreadId) -> MapEvalContext {
    let regs = dbg.get_registers(tid).await.expect("get_registers");
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
    ctx
}

// ── The address, not just the function ───────────────────────────────────────

/// THE MISSING ORACLE. Every crossing must stop at the ENTRY instruction, and
/// the proof is the return address sitting at `[sp]`: at the entry it is the
/// address `call` pushed and therefore points inside `main`; one instruction
/// later `push %rbp` has run and `[sp]` is a stack pointer instead.
///
/// The tuple `(crossings, pc_at_entry, ret_in_main)` is asserted as a whole,
/// so no single relocated constant reproduces it. Moving the target eight
/// bytes — which the sixteen tests of `live_linux_tracepoints.rs` cannot see —
/// fails this on both the second and the third component.
#[tokio::test]
async fn every_crossing_stops_at_the_entry_witnessed_by_the_return_address_on_the_stack() {
    let fx = build_fixture();
    let (entry, size) = fx.trace_me;
    let (main_a, main_sz) = fx.main;
    let dbg = launched(&fx).await;
    dbg.set_breakpoint(Address(entry), BreakpointKind::Software)
        .await
        .expect("set_breakpoint");

    let mut crossings = 0usize;
    let mut pc_at_entry = 0usize;
    let mut ret_in_main = 0usize;
    let mut sample = Vec::new();
    while let Some(ev) = next_hit(&dbg, entry, 64).await {
        crossings += 1;
        let regs = dbg.get_registers(ev.tid).await.expect("get_registers");
        assert!(
            regs.pc >= entry && regs.pc < entry + size,
            "the stop left the traced function entirely: pc={:#x} not in [{entry:#x},{:#x})",
            regs.pc,
            entry + size
        );
        if regs.pc == entry {
            pc_at_entry += 1;
        }
        let ret = read_u64(&dbg, regs.sp, 8).await;
        if ret >= main_a && ret < main_a + main_sz {
            ret_in_main += 1;
        }
        sample.push((regs.pc, ret));
        if crossings > 8 {
            break;
        }
    }
    let _ = dbg.kill().await;

    assert_eq!(
        (crossings, pc_at_entry, ret_in_main),
        (5, 5, 5),
        "expected five crossings, all at the entry instruction with a return address inside \
         main [{main_a:#x},{:#x}); got (crossings, pc_at_entry, ret_in_main) from {sample:#x?}",
        main_a + main_sz
    );
}

/// Three independent witnesses of the same pass number must agree on every
/// crossing: the argument register, `g_iter`, and `g_sum`. `g_sum` is a
/// SEPARATE variable at a separate address whose value the source fixes
/// (0, 1, 9, 24, 46), so relocating any one of the three breaks the agreement
/// instead of merely shifting a count.
#[tokio::test]
async fn three_independent_witnesses_agree_on_the_pass_number_at_every_crossing() {
    let fx = build_fixture();
    let (entry, _) = fx.trace_me;
    assert_ne!(fx.g_iter, fx.g_sum, "the two data witnesses must be distinct addresses");
    let dbg = launched(&fx).await;
    dbg.set_breakpoint(Address(entry), BreakpointKind::Software)
        .await
        .expect("set_breakpoint");

    let mut seen = Vec::new();
    while let Some(ev) = next_hit(&dbg, entry, 64).await {
        let ctx = ctx_at(&dbg, ev.tid).await;
        let arg = ctx.register(ARG_REG).expect("the argument register must be readable");
        let iter = read_u64(&dbg, fx.g_iter, 4).await;
        let sum = read_u64(&dbg, fx.g_sum, 8).await;
        seen.push((arg, iter, sum));
        if seen.len() > 8 {
            break;
        }
    }
    let _ = dbg.kill().await;

    assert_eq!(
        seen,
        WITNESSES.to_vec(),
        "the three witnesses of the pass number do not agree with the fixture source"
    );
}

// ── The trap is really there ─────────────────────────────────────────────────

/// A software breakpoint must be a byte IN THE TRACEE, and removing it must put
/// the original instruction back. Witnessed through `/proc/<pid>/mem`, so the
/// debugger's own breakpoint list cannot be the thing that answers.
///
/// The three-state sequence is the assertion: `original -> 0xCC -> original`.
/// A backend that recorded the breakpoint and never wrote it, or that wrote it
/// and never took it back, differs from this in exactly one state.
#[tokio::test]
async fn the_software_trap_is_written_into_the_tracee_and_taken_back_out() {
    let fx = build_fixture();
    let (entry, _) = fx.trace_me;
    let dbg = launched(&fx).await;
    let pid = dbg.target_pid().expect("a live pid").0;

    let before = raw_bytes(pid, entry, 4);
    assert_ne!(before[0], 0xCC, "the fixture must not already begin with a trap byte");
    dbg.set_breakpoint(Address(entry), BreakpointKind::Software)
        .await
        .expect("set_breakpoint");
    let armed = raw_bytes(pid, entry, 4);
    let at_stop = {
        let _ev = next_hit(&dbg, entry, 64).await.expect("the first crossing");
        raw_bytes(pid, entry, 4)
    };
    dbg.remove_breakpoint(Address(entry)).await.expect("remove_breakpoint");
    let removed = raw_bytes(pid, entry, 4);
    let _ = dbg.kill().await;

    assert_eq!(
        (armed[0], removed.clone()),
        (0xCCu8, before.clone()),
        "the trap byte was not written into the tracee, or the original instruction was not \
         restored: before={before:02x?} armed={armed:02x?} removed={removed:02x?}"
    );
    assert_eq!(
        armed[1..],
        before[1..],
        "arming clobbered more than the first byte: {armed:02x?} vs {before:02x?}"
    );
    assert_eq!(
        at_stop[0], 0xCC,
        "the trap was gone at the first stop, so later crossings could not be caught: \
         {at_stop:02x?}"
    );
}

/// `read_memory` must HIDE the trap byte. This is a tracepoint concern, not a
/// cosmetic one: a `mem1[…]` operand aimed at instrumented code would otherwise
/// render `0xcc` — a number the program never contained — into a log that is
/// read as evidence.
///
/// The two reads are taken at the same instant from the same address, and they
/// must disagree in exactly this direction.
#[tokio::test]
async fn read_memory_hides_the_trap_byte_that_proc_mem_shows() {
    let fx = build_fixture();
    let (entry, _) = fx.trace_me;
    let dbg = launched(&fx).await;
    let pid = dbg.target_pid().expect("a live pid").0;
    let pristine = raw_bytes(pid, entry, 4);
    dbg.set_breakpoint(Address(entry), BreakpointKind::Software)
        .await
        .expect("set_breakpoint");

    let raw = raw_bytes(pid, entry, 4);
    let via_dbg = dbg.read_memory(Address(entry), 4).await.expect("read_memory");
    let _ = dbg.kill().await;

    assert_eq!(raw[0], 0xCC, "precondition: the trap must be present for this to mean anything");
    assert_eq!(
        via_dbg, pristine,
        "read_memory leaked the breakpoint byte into the caller: {via_dbg:02x?} (raw {raw:02x?})"
    );
}

/// Closes the vacuity in `a_tracepoint_on_an_address_never_reached_invents_no_output`,
/// which asserts only absences and therefore passes just as well when nothing
/// was ever armed. Here the trap is SHOWN present in the tracee first, so the
/// silence afterwards is the silence of an armed-and-never-crossed address.
#[tokio::test]
async fn the_unreached_tracepoint_is_provably_armed_before_it_stays_silent() {
    let fx = build_fixture();
    let (dead, _) = fx.never_called;
    let (live, _) = fx.trace_me;
    assert_ne!(dead, live, "the two targets must be distinct addresses");
    let dbg = launched(&fx).await;
    let pid = dbg.target_pid().expect("a live pid").0;
    dbg.set_breakpoint(Address(dead), BreakpointKind::Software)
        .await
        .expect("set_breakpoint on a real linked function");
    let armed = raw_bytes(pid, dead, 1);
    assert_eq!(
        armed[0], 0xCC,
        "the trap on the never-executed function was never written, so the silence below \
         would prove nothing"
    );

    let mut tp = Tracepoint::new(
        Address(dead),
        TracepointFormat::new()
            .literal("never x=")
            .operand(ConditionOperand::Register(ARG_REG.to_string())),
    );
    let mut messages: Vec<String> = Vec::new();
    let mut exit = None;
    for _ in 0..64 {
        let ev = dbg.continue_execution().await.expect("continue_execution");
        if ev.pid.0 != pid {
            continue;
        }
        match ev.reason {
            StopReason::Breakpoint { address, .. } if address.as_u64() == dead => {
                let ctx = ctx_at(&dbg, ev.tid).await;
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

    assert_eq!(
        (exit, messages.len(), tp.hit_count, tp.eval_count),
        (Some(0), 0, 0, 0),
        "an armed-but-never-crossed tracepoint produced output: {messages:?}"
    );
}

/// A tracepoint operand read from the STACK must follow the live frame. `[sp]`
/// at the entry is the return address of this call, and the fixture calls
/// `trace_me` from one site, so all five renders name the same address — and
/// that address must be inside `main`, which a stale or zeroed read is not.
///
/// This is the one operand kind the sibling file never exercises: it only reads
/// a global, whose address is fixed at link time and therefore cannot detect a
/// context assembled from the wrong frame.
#[tokio::test]
async fn a_stack_operand_renders_the_live_return_address_on_every_pass() {
    let fx = build_fixture();
    let (entry, _) = fx.trace_me;
    let (main_a, main_sz) = fx.main;
    let dbg = launched(&fx).await;
    dbg.set_breakpoint(Address(entry), BreakpointKind::Software)
        .await
        .expect("set_breakpoint");

    let mut rendered = Vec::new();
    while let Some(ev) = next_hit(&dbg, entry, 64).await {
        let regs = dbg.get_registers(ev.tid).await.expect("get_registers");
        let ret = read_u64(&dbg, regs.sp, 8).await;
        let mut ctx = ctx_at(&dbg, ev.tid).await;
        ctx.set_mem(regs.sp, ret, 8);
        let mut tp = Tracepoint::new(
            Address(entry),
            TracepointFormat::new()
                .literal("ret=")
                .operand(ConditionOperand::Memory { addr: regs.sp, width: 8 }),
        );
        let e = tp.fire(&ctx).expect("render").expect("unconditional");
        rendered.push((e.message, ret));
        if rendered.len() > 8 {
            break;
        }
    }
    let _ = dbg.kill().await;

    assert_eq!(rendered.len(), 5, "five crossings expected, got {}", rendered.len());
    for (msg, ret) in &rendered {
        assert_eq!(msg, &format!("ret={ret:#x}"), "the stack operand did not render its value");
        assert!(
            *ret >= main_a && *ret < main_a + main_sz,
            "the rendered return address {ret:#x} is not inside main [{main_a:#x},{:#x})",
            main_a + main_sz
        );
    }
    let unique: std::collections::BTreeSet<u64> = rendered.iter().map(|(_, r)| *r).collect();
    assert_eq!(
        unique.len(),
        1,
        "the fixture has one call site, so all five return addresses must coincide: {unique:#x?}"
    );
}

// ── Hygiene ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn zz_no_orphan_dv3_fixture_process_survives() {
    let out = std::process::Command::new("pgrep")
        .args(["-f", "dv3tp_fixture"])
        .output()
        .expect("pgrep must be available");
    let listing = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let mine = std::process::id().to_string();
    let strays: Vec<&str> =
        listing.lines().filter(|l| !l.trim().is_empty() && l.trim() != mine).collect();
    assert!(strays.is_empty(), "fixture processes survived: {strays:?}");
}
