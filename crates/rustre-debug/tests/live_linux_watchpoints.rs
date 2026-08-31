//! Live hardware-watchpoint coverage for the Linux ptrace backend.
//!
//! Every test in this file drives a REAL child process through
//! `LinuxDebugger`: it forks, `PTRACE_TRACEME`s, execs, and the assertions are
//! made against debug registers read back out of the tracee with
//! `PTRACE_PEEKUSER`. Nothing here builds a struct in memory and inspects it —
//! that kind of test already exists in the crate by the thousand and cannot
//! tell an armed watchpoint from a forgotten one.
//!
//! The area covered is the hardware-watchpoint surface:
//! `set_watchpoint_sized`, `remove_hardware_watchpoint`, the watchpoint rows of
//! `breakpoints()`, `enable_breakpoint`/`disable_breakpoint` on a watchpoint,
//! the four x86 slots DR0-DR3, what happens at the fifth, and re-arming on
//! threads that did not exist when the watchpoint was set.
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::{
    BreakpointKind, Debugger, LaunchOptions, OutputRedirect, ProcessId, StopReason, ThreadId,
};

// ── fixtures ────────────────────────────────────────────────────────────────

fn sh(args: &[&str]) -> LaunchOptions {
    LaunchOptions {
        executable: "/bin/sh".to_string(),
        args: args.iter().map(|s| (*s).to_string()).collect(),
        env: std::collections::HashMap::new(),
        working_dir: None,
        stop_at_entry: false,
        follow_forks: false,
        redirect: OutputRedirect::default(),
    }
}

/// Launch a long-lived, stopped tracee to arm watchpoints on.
async fn launch_sleeper(dbg: &LinuxDebugger) -> ProcessId {
    dbg.launch(sh(&["-c", "sleep 30"]))
        .await
        .expect("launch /bin/sh should succeed")
}

/// A writable, 8-byte-aligned address inside the tracee's own stack.
///
/// x86 refuses a watchpoint whose address is not aligned to its width, so the
/// address a test watches has to be a real, aligned, mapped one — a made-up
/// constant would be rejected by the encoder and the test would prove nothing
/// about the ptrace path.
async fn aligned_stack_slot(dbg: &LinuxDebugger, pid: ProcessId, nth: u64) -> Address {
    let regs = dbg
        .get_registers(ThreadId(pid.0))
        .await
        .expect("get_registers on the stopped tracee");
    Address((regs.sp & !7u64).wrapping_sub(64 + nth * 8))
}

fn dr_name(slot: u8) -> &'static str {
    match slot {
        0 => "dr0",
        1 => "dr1",
        2 => "dr2",
        _ => "dr3",
    }
}

/// Which DR slot, if any, the tracee's registers currently hold `addr` in,
/// counting only slots DR7 says are ENABLED. Read from the live process.
async fn armed_slot_of(dbg: &LinuxDebugger, pid: ProcessId, addr: Address) -> Option<u8> {
    let regs = dbg.get_registers(ThreadId(pid.0)).await.ok()?;
    let dr7 = regs.get("dr7").unwrap_or(0);
    (0u8..4).find(|s| {
        dr7 & (1u64 << (2 * u32::from(*s))) != 0 && regs.get(dr_name(*s)) == Some(addr.as_u64())
    })
}

async fn dr7_of(dbg: &LinuxDebugger, pid: ProcessId) -> u64 {
    dbg.get_registers(ThreadId(pid.0))
        .await
        .expect("get_registers")
        .get("dr7")
        .unwrap_or(0)
}

/// Compile a fixture C program with `cc` into a tempdir and return its path.
/// Built `-no-pie` so the address `nm` reports for a global is the address the
/// process really uses — with PIE we would have to relocate it first, and a
/// watchpoint on the un-relocated address watches nothing.
fn compile_fixture(dir: &std::path::Path, name: &str, source: &str) -> Option<std::path::PathBuf> {
    let src = dir.join(format!("{name}.c"));
    std::fs::write(&src, source).ok()?;
    let exe = dir.join(name);
    let out = std::process::Command::new("cc")
        .args(["-no-pie", "-O0", "-g", "-pthread"])
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

/// Absolute address of a global symbol in a non-PIE executable, via `nm`.
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

// ── tests ───────────────────────────────────────────────────────────────────

/// `set_watchpoint_sized` must PROGRAM the tracee's debug registers, not just
/// return `Ok`. Proven by reading DR0-DR7 back out of the live process: the
/// slot must hold the exact address and DR7 must have that slot's local-enable
/// bit set. A backend that only updated its own bookkeeping would pass every
/// in-memory test and watch nothing.
#[tokio::test]
async fn arming_a_watchpoint_programs_the_real_debug_registers() {
    let dbg = LinuxDebugger::new();
    let pid = launch_sleeper(&dbg).await;
    let addr = aligned_stack_slot(&dbg, pid, 0).await;

    assert_eq!(
        dr7_of(&dbg, pid).await & 0xff,
        0,
        "no slot may be enabled before we arm one"
    );

    dbg.set_watchpoint_sized(addr, BreakpointKind::DataWrite, 8)
        .await
        .expect("arming an aligned 8-byte write watchpoint must succeed");

    let slot = armed_slot_of(&dbg, pid, addr).await;
    assert!(
        slot.is_some(),
        "after set_watchpoint_sized the tracee's own DR0-DR3 must hold {addr:?}, DR7 = {:#x}",
        dr7_of(&dbg, pid).await
    );
    let _ = dbg.kill().await;
}

/// The width the caller asked for must reach the hardware: DR7's LEN field for
/// the slot encodes 1/2/4/8 bytes, and getting it wrong watches the wrong
/// memory while reporting success. Checked for each legal width by decoding
/// LEN back out of the live DR7.
#[tokio::test]
async fn each_legal_width_lands_in_the_len_field() {
    // (requested size, LEN encoding per Intel SDM: 00=1, 01=2, 11=4, 10=8)
    for (size, len_bits) in [(1u8, 0b00u64), (2, 0b01), (4, 0b11), (8, 0b10)] {
        let dbg = LinuxDebugger::new();
        let pid = launch_sleeper(&dbg).await;
        let addr = aligned_stack_slot(&dbg, pid, 0).await;
        dbg.set_watchpoint_sized(addr, BreakpointKind::DataWrite, size)
            .await
            .unwrap_or_else(|e| panic!("a {size}-byte aligned watchpoint must be accepted: {e}"));
        let slot = armed_slot_of(&dbg, pid, addr)
            .await
            .unwrap_or_else(|| panic!("{size}-byte watchpoint was not armed in any slot"));
        let dr7 = dr7_of(&dbg, pid).await;
        let len = (dr7 >> (18 + 4 * u32::from(slot))) & 0b11;
        assert_eq!(
            len, len_bits,
            "a {size}-byte watchpoint must encode LEN={len_bits:#04b} in DR7 ({dr7:#x})"
        );
        let _ = dbg.kill().await;
    }
}

/// x86 has exactly four debug-address registers. Four distinct addresses must
/// all arm, in four DISTINCT slots, and the fifth must be REFUSED — not
/// silently dropped and not silently overwriting one of the four. Saturation
/// that reports success is the worst outcome: the caller believes five
/// addresses are watched and one of them is not.
#[tokio::test]
async fn four_slots_fill_then_the_fifth_is_refused() {
    let dbg = LinuxDebugger::new();
    let pid = launch_sleeper(&dbg).await;

    let mut addrs = Vec::new();
    for n in 0..4u64 {
        let a = aligned_stack_slot(&dbg, pid, n).await;
        dbg.set_watchpoint_sized(a, BreakpointKind::DataWrite, 8)
            .await
            .unwrap_or_else(|e| panic!("watchpoint {n} of 4 must fit in hardware: {e}"));
        addrs.push(a);
    }

    let mut slots = Vec::new();
    for a in &addrs {
        slots.push(
            armed_slot_of(&dbg, pid, *a)
                .await
                .unwrap_or_else(|| panic!("{a:?} is tracked but not armed in any slot")),
        );
    }
    slots.sort_unstable();
    slots.dedup();
    assert_eq!(
        slots.len(),
        4,
        "four watchpoints must occupy four distinct slots, got {slots:?}"
    );

    let fifth = aligned_stack_slot(&dbg, pid, 4).await;
    let err = dbg
        .set_watchpoint_sized(fifth, BreakpointKind::DataWrite, 8)
        .await
        .expect_err("the fifth hardware watchpoint must be refused, not accepted");
    let text = format!("{err}");
    assert!(
        text.contains("DR0-DR3") || text.to_lowercase().contains("in use"),
        "the refusal must say the slots are exhausted, got: {text}"
    );
    // And the refusal must not have disturbed the four that were already armed.
    for a in &addrs {
        assert!(
            armed_slot_of(&dbg, pid, *a).await.is_some(),
            "the refused fifth request must leave {a:?} armed"
        );
    }
    let _ = dbg.kill().await;
}

/// Arming the SAME address twice must re-use its slot. Without the idempotency
/// guard four requests for one address would exhaust the hardware while the
/// caller asked to watch a single word, and the address-keyed bookkeeping would
/// lose track of the extra slots, which then stay armed until detach.
#[tokio::test]
async fn re_arming_one_address_reuses_its_slot() {
    let dbg = LinuxDebugger::new();
    let pid = launch_sleeper(&dbg).await;
    let addr = aligned_stack_slot(&dbg, pid, 0).await;

    for _ in 0..4 {
        dbg.set_watchpoint_sized(addr, BreakpointKind::DataWrite, 8)
            .await
            .expect("re-arming the same address must keep succeeding");
    }
    let dr7 = dr7_of(&dbg, pid).await;
    let enabled = (0u8..4)
        .filter(|s| dr7 & (1u64 << (2 * u32::from(*s))) != 0)
        .count();
    assert_eq!(
        enabled, 1,
        "four requests for ONE address must hold one slot, DR7 = {dr7:#x}"
    );

    // The hardware still has room for three more, which is the point.
    for n in 1..4u64 {
        let a = aligned_stack_slot(&dbg, pid, n).await;
        dbg.set_watchpoint_sized(a, BreakpointKind::DataWrite, 8)
            .await
            .unwrap_or_else(|e| panic!("slot {n} must still be free after the re-arms: {e}"));
    }
    let _ = dbg.kill().await;
}

/// `remove_hardware_watchpoint` must clear the debug register AND free its
/// slot for the next caller. A remove that only forgot the bookkeeping would
/// leave the tracee still trapping on the address with nothing tracking it, and
/// leak one of the four slots per removal.
#[tokio::test]
async fn removing_a_watchpoint_frees_its_hardware_slot() {
    let dbg = LinuxDebugger::new();
    let pid = launch_sleeper(&dbg).await;

    let mut addrs = Vec::new();
    for n in 0..4u64 {
        let a = aligned_stack_slot(&dbg, pid, n).await;
        dbg.set_watchpoint_sized(a, BreakpointKind::DataWrite, 8)
            .await
            .expect("arm");
        addrs.push(a);
    }
    let removed = dbg
        .remove_hardware_watchpoint(addrs[1])
        .await
        .expect("remove_hardware_watchpoint must not error");
    assert!(
        removed,
        "removing an armed watchpoint must report that it found one"
    );
    assert_eq!(
        armed_slot_of(&dbg, pid, addrs[1]).await,
        None,
        "the removed address must no longer be enabled in any debug register"
    );
    // The other three are untouched…
    for a in [addrs[0], addrs[2], addrs[3]] {
        assert!(
            armed_slot_of(&dbg, pid, a).await.is_some(),
            "{a:?} must survive the removal"
        );
    }
    // …and the freed slot is usable again.
    let fresh = aligned_stack_slot(&dbg, pid, 9).await;
    dbg.set_watchpoint_sized(fresh, BreakpointKind::DataWrite, 8)
        .await
        .expect("the slot freed by remove must be re-usable");
    assert!(armed_slot_of(&dbg, pid, fresh).await.is_some());
    let _ = dbg.kill().await;
}

/// Removing an address that was never watched must answer `false`, not invent a
/// removal. A caller retrying a remove needs to be able to tell "there was one
/// and it is gone" from "there never was one".
#[tokio::test]
async fn removing_an_unwatched_address_reports_no_watchpoint() {
    let dbg = LinuxDebugger::new();
    let pid = launch_sleeper(&dbg).await;
    let addr = aligned_stack_slot(&dbg, pid, 0).await;
    assert!(
        !dbg.remove_hardware_watchpoint(addr)
            .await
            .expect("must not error"),
        "an address that was never watched cannot report a removal"
    );
    let _ = dbg.kill().await;
}

/// `breakpoints()` must LIST hardware watchpoints, with the kind and the width
/// they were armed with. The MCP surface serialises exactly this vector, so a
/// watchpoint missing from it is one the operator cannot see or knowingly
/// remove, and a width reported as `None` is the one field needed to arm the
/// same watchpoint again.
#[tokio::test]
async fn breakpoints_lists_the_watchpoint_with_its_kind_and_width() {
    let dbg = LinuxDebugger::new();
    let pid = launch_sleeper(&dbg).await;
    let addr = aligned_stack_slot(&dbg, pid, 0).await;
    dbg.set_watchpoint_sized(addr, BreakpointKind::DataReadWrite, 4)
        .await
        .expect("arm");

    let listed = dbg.breakpoints().await.expect("breakpoints() must not error");
    let row = listed
        .iter()
        .find(|b| b.address == addr)
        .unwrap_or_else(|| panic!("the armed watchpoint at {addr:?} is missing from {listed:?}"));
    assert!(
        matches!(row.kind, BreakpointKind::DataReadWrite),
        "the listed kind must be the one armed, got {:?}",
        row.kind
    );
    assert_eq!(
        row.byte_size,
        Some(4),
        "the listed width must be the width armed"
    );
    assert!(row.enabled, "a freshly armed watchpoint is enabled");
    assert_eq!(
        row.original_byte, None,
        "a watchpoint patches no code, so it has no saved byte"
    );
    let _ = dbg.kill().await;
}

/// `disable_breakpoint` on a watchpoint must stop the hardware trapping while
/// KEEPING the watchpoint tracked, and `enable_breakpoint` must put it back.
/// Disabling by forgetting would make the watchpoint unrestorable; disabling in
/// bookkeeping only would leave it firing after the caller switched it off.
#[tokio::test]
async fn disable_disarms_the_register_and_enable_puts_it_back() {
    let dbg = LinuxDebugger::new();
    let pid = launch_sleeper(&dbg).await;
    let addr = aligned_stack_slot(&dbg, pid, 0).await;
    dbg.set_watchpoint_sized(addr, BreakpointKind::DataWrite, 8)
        .await
        .expect("arm");
    assert!(armed_slot_of(&dbg, pid, addr).await.is_some());

    dbg.disable_breakpoint(addr)
        .await
        .expect("disable_breakpoint on a watchpoint");
    assert_eq!(
        armed_slot_of(&dbg, pid, addr).await,
        None,
        "a disabled watchpoint must not be enabled in the hardware any more"
    );
    let listed = dbg.breakpoints().await.expect("breakpoints()");
    let row = listed
        .iter()
        .find(|b| b.address == addr)
        .expect("a disabled watchpoint must still be LISTED, otherwise it cannot be re-enabled");
    assert!(!row.enabled, "and it must be listed as disabled");

    dbg.enable_breakpoint(addr)
        .await
        .expect("enable_breakpoint on a watchpoint");
    assert!(
        armed_slot_of(&dbg, pid, addr).await.is_some(),
        "re-enabling must program the debug register again"
    );
    assert!(
        dbg.breakpoints()
            .await
            .expect("breakpoints()")
            .iter()
            .any(|b| b.address == addr && b.enabled),
        "and must report the watchpoint as enabled again"
    );
    let _ = dbg.kill().await;
}

/// A width x86 cannot encode (3 bytes) and an address that is not aligned to
/// its width must both be REFUSED, and — the part that matters — must leave
/// every debug register exactly as it was. A half-programmed rejection is worse
/// than a rejection: some threads would watch and the caller was told no.
#[tokio::test]
async fn an_illegal_request_is_refused_and_changes_nothing() {
    let dbg = LinuxDebugger::new();
    let pid = launch_sleeper(&dbg).await;
    let good = aligned_stack_slot(&dbg, pid, 0).await;
    dbg.set_watchpoint_sized(good, BreakpointKind::DataWrite, 8)
        .await
        .expect("arm a good one");
    let before = dr7_of(&dbg, pid).await;

    let odd = aligned_stack_slot(&dbg, pid, 1).await;
    assert!(
        dbg.set_watchpoint_sized(odd, BreakpointKind::DataWrite, 3)
            .await
            .is_err(),
        "x86 covers 1, 2, 4 or 8 bytes — a 3-byte watchpoint must be refused"
    );
    let misaligned = Address(aligned_stack_slot(&dbg, pid, 2).await.as_u64() + 1);
    assert!(
        dbg.set_watchpoint_sized(misaligned, BreakpointKind::DataWrite, 4)
            .await
            .is_err(),
        "a 4-byte watchpoint on an unaligned address must be refused"
    );

    assert_eq!(
        dr7_of(&dbg, pid).await,
        before,
        "two refused requests must leave DR7 byte-identical"
    );
    assert!(
        armed_slot_of(&dbg, pid, good).await.is_some(),
        "and the good watchpoint intact"
    );
    let _ = dbg.kill().await;
}

/// Detaching must leave the debugger with no watchpoint bookkeeping. A leaked
/// entry does not merely describe a watchpoint that is gone: the next session
/// believes those hardware slots are taken and refuses a legitimate
/// `set_watchpoint` with "all four DR slots are in use".
#[tokio::test]
async fn detach_clears_the_watchpoint_bookkeeping() {
    let dbg = LinuxDebugger::new();
    let pid = launch_sleeper(&dbg).await;
    for n in 0..3u64 {
        let a = aligned_stack_slot(&dbg, pid, n).await;
        dbg.set_watchpoint_sized(a, BreakpointKind::DataWrite, 8)
            .await
            .expect("arm");
    }
    dbg.detach().await.expect("detach must succeed");
    assert!(
        dbg.breakpoints().await.map(|v| v.is_empty()).unwrap_or(true),
        "detach must drop the watchpoint bookkeeping"
    );
    // The tracee is no longer ours to inspect; kill it so the test leaves nothing behind.
    let _ = std::process::Command::new("kill")
        .arg("-9")
        .arg(pid.0.to_string())
        .status();
}

/// The end-to-end claim: an armed write watchpoint must actually STOP the
/// process when the watched memory is written. Everything else in this file
/// checks register bits; this one checks the behaviour those bits exist for,
/// against a real compiled program writing a real global.
#[tokio::test]
async fn a_write_watchpoint_stops_the_process_on_the_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(exe) = compile_fixture(
        dir.path(),
        "wp_write",
        "volatile long g_watched = 0;\n\
         int main(void) {\n\
         for (long i = 1; i <= 5; i++) { g_watched = i; }\n\
         return 0;\n\
         }\n",
    ) else {
        eprintln!("skipping: `cc -no-pie` is not usable here");
        return;
    };
    let Some(sym) = symbol_addr(&exe, "g_watched") else {
        eprintln!("skipping: `nm` did not report g_watched");
        return;
    };

    let dbg = LinuxDebugger::new();
    dbg.launch(exe_launch(&exe))
        .await
        .expect("launch the fixture");
    dbg.set_watchpoint_sized(Address(sym), BreakpointKind::DataWrite, 8)
        .await
        .expect("arming a write watchpoint on a real global must succeed");

    let mut stopped_before_exit = false;
    for _ in 0..64 {
        let ev = dbg
            .continue_execution()
            .await
            .expect("continue_execution");
        match ev.reason {
            StopReason::ProcessExit { .. } => break,
            StopReason::Breakpoint { address, .. } if address.as_u64() == sym => {
                stopped_before_exit = true;
                break;
            }
            // Any other stop is fine to run past; we are only interested in
            // whether the watched write ever reports itself.
            _ => {}
        }
    }
    assert!(
        stopped_before_exit,
        "the program writes g_watched ({sym:#x}) five times; an armed 8-byte write watchpoint \
         must report at least one of those writes before the process exits"
    );
    let _ = dbg.kill().await;
}

/// A watchpoint armed BEFORE a thread exists must also watch that thread.
/// The x86 debug registers are per-thread, and a thread created later starts
/// with all four empty — so without re-arming, the watchpoint silently stops
/// covering the very code most likely to race on the address, while the caller
/// was told the address is watched.
///
/// MEASURED RED. Expected: one `StopReason::Breakpoint` at `g_watched`
/// (0x404030 in the fixture). Got: none — the full event sequence observed is
/// `ThreadCreate(worker)`, `ThreadExit(main)`, `ThreadExit(worker)`,
/// `Unknown("waitpid(-1) failed: No child processes")`. The write happens and
/// is never reported.
///
/// Cause, measured rather than guessed: the clone IS observed (the
/// `ThreadCreate` event proves it), but `rearm_watchpoints_on_new_threads`
/// programs a thread through `get_registers`/`set_registers`, and on the new
/// tid `get_registers` answers
/// `RegisterError("reading the register set failed: No such process (os error 3)")`
/// — ESRCH — because this backend never `PTRACE_ATTACH`es threads created after
/// launch (the caveat already documented on `Debugger::threads`). The re-arm
/// loop takes its "registers unreadable" branch, reports the address as
/// UNARMED, and the watchpoint keeps covering only the original thread.
/// Left `#[ignore]` because the fix is a backend change (`PTRACE_SEIZE` /
/// `PTRACE_O_TRACECLONE` so new threads are really traced), not a test bug.
#[tokio::test]
#[ignore = "backend does not attach threads created after launch: the watchpoint never reaches them"]
async fn a_watchpoint_reaches_threads_created_after_it_was_armed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let Some(exe) = compile_fixture(
        dir.path(),
        "wp_thread",
        "#include <pthread.h>
         #include <unistd.h>
         volatile long g_watched = 0;
         static void *worker(void *unused) { (void)unused; g_watched = 42; return 0; }
         int main(void) {
         pthread_t t;
         pthread_create(&t, 0, worker, 0);
         pthread_join(t, 0);
         return 0;
         }
",
    ) else {
        eprintln!("skipping: `cc -pthread -no-pie` is not usable here");
        return;
    };
    let Some(sym) = symbol_addr(&exe, "g_watched") else {
        eprintln!("skipping: `nm` did not report g_watched");
        return;
    };

    let dbg = LinuxDebugger::new();
    dbg.launch(exe_launch(&exe))
        .await
        .expect("launch the threaded fixture");
    dbg.set_watchpoint_sized(Address(sym), BreakpointKind::DataWrite, 8)
        .await
        .expect("arm before any extra thread exists");

    // The ONLY write to `g_watched` in the whole program happens on a thread
    // created after the watchpoint was armed, so a watchpoint that reaches new
    // threads must report it exactly once.
    let mut reported = false;
    for _ in 0..64 {
        // A `NotAttached` here means the tracee is gone, i.e. it ran to exit
        // without the watchpoint ever reporting anything — that is the defect,
        // not a test error, so it ends the loop rather than panicking.
        let Ok(ev) = dbg.continue_execution().await else { break };
        match ev.reason {
            StopReason::ProcessExit { .. } => break,
            StopReason::Breakpoint { address, .. } if address.as_u64() == sym => {
                reported = true;
                break;
            }
            _ => {}
        }
    }
    assert!(
        reported,
        "the worker thread writes g_watched ({sym:#x}); a watchpoint armed before that thread          existed must be re-armed onto it and report the write"
    );
    let _ = dbg.kill().await;
}


// ─────────────────────────────────────────────────────────────────────────────
// Falsification guards — the COUNT of writes, taken unfiltered
// ─────────────────────────────────────────────────────────────────────────────
//
// Everything above this line checks debug-register BITS: the backend writes a
// value through `PTRACE_POKEUSER` and the test reads it back through
// `PTRACE_PEEKUSER`. That is a real round trip through the kernel, but the
// address it round-trips is one the test obtained from the backend itself
// (`get_registers().sp`), so nothing outside the crate says which address ought
// to be there. Measured in the workflow-5 falsification campaign: shifting the
// one external oracle this file used (`nm`) by `0x40` left 10 of the 11 active
// tests green.
//
// The cure is the one that worked in `live_linux_falsification.rs`: stop
// filtering the stop stream on the address the test is about to assert on, and
// count crossings instead. The fixture below writes `g_five` five times,
// `g_three` three times, `g_one` once and `g_never` never. That vector of
// counts is an observable of the PROGRAM: no bookkeeping, no register value and
// no shifted symbol table can reproduce it from the wrong address, because a
// wrong address is written a different number of times.

/// Writes to each global are the ground truth, read off the source and nowhere
/// else. `g_buf` is written only at index 7, which is what makes the LEN field
/// behaviourally observable: a 1-byte watchpoint on `g_buf[0]` must see nothing
/// while an 8-byte watchpoint on the same address must see every write.
const COUNTING_FIXTURE_C: &str = "\
volatile long g_five = 0;\n\
volatile long g_one = 0;\n\
volatile long g_three = 0;\n\
volatile long g_never = 0;\n\
volatile char g_buf[16] __attribute__((aligned(16))) = {0};\n\
int main(void) {\n\
    for (long i = 1; i <= 5; i++) { g_five = i; }\n\
    g_one = 7;\n\
    for (long i = 1; i <= 3; i++) { g_three = i; }\n\
    for (int i = 1; i <= 3; i++) { g_buf[7] = (char)i; }\n\
    return 0;\n\
}\n";

/// How often each global is really written. Ground truth from the source above.
const WRITE_COUNTS: [(&str, usize); 4] =
    [("g_five", 5), ("g_three", 3), ("g_one", 1), ("g_never", 0)];

struct Counting {
    _dir: tempfile::TempDir,
    exe: std::path::PathBuf,
}

impl Counting {
    /// `None` when this machine has no usable `cc`; every guard below then
    /// skips rather than failing for a reason that is not the backend's.
    fn build() -> Option<Self> {
        let dir = tempfile::tempdir().ok()?;
        let exe = compile_fixture(dir.path(), "wpcount", COUNTING_FIXTURE_C)?;
        Some(Self { _dir: dir, exe })
    }

    /// The address `nm` prints for a global. Built `-no-pie`, so it is the
    /// address the process really writes.
    fn addr(&self, name: &str) -> u64 {
        symbol_addr(&self.exe, name)
            .unwrap_or_else(|| panic!("the fixture must export the global `{name}`"))
    }
}

/// Run the fixture to exit with watchpoints armed on `watched`, and return how
/// many breakpoint stops were seen — WITHOUT looking at the address of any of
/// them.
///
/// Not filtering is the whole point. `a_write_watchpoint_stops_the_process_on_the_write`
/// above accepts a stop only when `address == sym` and then concludes the
/// watchpoint works; that assertion is satisfied by the address it already
/// selected on. Here the number comes back blind, so it describes what the
/// program did rather than what the test was looking for.
///
/// The tracee is killed on every path, including the panics, so no fixture can
/// outlive the test.
async fn total_stops_with(fx: &Counting, watched: &[(u64, u8)]) -> usize {
    let dbg = LinuxDebugger::new();
    dbg.launch(exe_launch(&fx.exe)).await.expect("launch the counting fixture");
    for (addr, size) in watched {
        if let Err(e) =
            dbg.set_watchpoint_sized(Address(*addr), BreakpointKind::DataWrite, *size).await
        {
            let _ = dbg.kill().await;
            panic!("arming a {size}-byte write watchpoint at {addr:#x} must succeed: {e}");
        }
    }
    let mut stops = 0usize;
    for _ in 0..96 {
        match dbg.continue_execution().await {
            Ok(ev) => match ev.reason {
                StopReason::Breakpoint { .. } => stops += 1,
                StopReason::ProcessExit { .. } => break,
                _ => {}
            },
            Err(_) => break,
        }
    }
    let _ = dbg.kill().await;
    stops
}

/// Same run, but the stops are TALLIED by the address the backend reports, so a
/// slot programmed with the wrong address shows up as a wrong histogram instead
/// of being invisible inside a total.
async fn stops_per_address(
    fx: &Counting,
    watched: &[(u64, u8)],
) -> std::collections::BTreeMap<u64, usize> {
    let dbg = LinuxDebugger::new();
    dbg.launch(exe_launch(&fx.exe)).await.expect("launch the counting fixture");
    for (addr, size) in watched {
        if let Err(e) =
            dbg.set_watchpoint_sized(Address(*addr), BreakpointKind::DataWrite, *size).await
        {
            let _ = dbg.kill().await;
            panic!("arming a {size}-byte write watchpoint at {addr:#x} must succeed: {e}");
        }
    }
    let mut hist = std::collections::BTreeMap::new();
    for _ in 0..96 {
        match dbg.continue_execution().await {
            Ok(ev) => match ev.reason {
                StopReason::Breakpoint { address, .. } => {
                    *hist.entry(address.as_u64()).or_insert(0usize) += 1;
                }
                StopReason::ProcessExit { .. } => break,
                _ => {}
            },
            Err(_) => break,
        }
    }
    let _ = dbg.kill().await;
    hist
}

macro_rules! counting_fixture {
    () => {
        match Counting::build() {
            Some(f) => f,
            None => {
                eprintln!("skipping: `cc -no-pie` is not usable here");
                return;
            }
        }
    };
}

/// A watchpoint must fire as often as the program writes THAT global.
///
/// The guard against the vacuity measured for this file. `g_five`, `g_three`,
/// `g_one` and `g_never` are written 5, 3, 1 and 0 times; the vector
/// `(5, 3, 1, 0)` is reproduced by exactly one assignment of addresses to names.
/// Shift the symbol table and the counts move with it: point `g_five` at
/// `g_one` and its count falls to 1, point it anywhere unwritten and it falls
/// to 0. No amount of correct-looking DR7 bits can fake a write that did not
/// happen.
#[tokio::test]
async fn the_write_count_pins_each_watchpoint_to_its_own_address() {
    let fx = counting_fixture!();
    let mut got = Vec::new();
    for (name, _) in WRITE_COUNTS {
        got.push((name, total_stops_with(&fx, &[(fx.addr(name), 8)]).await));
    }
    let want: Vec<(&str, usize)> = WRITE_COUNTS.to_vec();
    assert_eq!(
        got, want,
        "an 8-byte write watchpoint fired {got:?} times per global, but the fixture writes \
         {want:?}; a count that does not match the source means the hardware is watching \
         something other than the named global"
    );
}

/// The counting guard above must FAIL when the address underneath it moves.
///
/// Without this, the guard would be one more assertion nobody has ever seen go
/// red. `g_never` is never written and `g_five` is written five times: if
/// swapping one address for the other does not change the number, the count is
/// not a function of the address and everything built on it is worthless. The
/// third case applies the campaign's own mutation — `nm` shifted by `0x40` —
/// directly, and requires silence.
#[tokio::test]
async fn the_write_count_guard_is_itself_falsifiable() {
    let fx = counting_fixture!();
    let five = total_stops_with(&fx, &[(fx.addr("g_five"), 8)]).await;
    let never = total_stops_with(&fx, &[(fx.addr("g_never"), 8)]).await;
    assert_ne!(
        five, never,
        "watching a global written five times and one never written both produced {five} \
         stops; the count does not depend on the address being watched"
    );
    assert_eq!(never, 0, "`g_never` is never written, so it cannot be written {never} times");
    let shifted = total_stops_with(&fx, &[(fx.addr("g_five") + 0x40, 8)]).await;
    assert_eq!(
        shifted, 0,
        "an address 0x40 past `g_five` reported {shifted} writes; if a shifted address still \
         fires, shifting the symbol oracle cannot make this file go red"
    );
}

/// Four watchpoints armed at once must each watch their OWN address.
///
/// The register-level test above proves four addresses occupy four distinct
/// slots; it cannot tell whether slot 2 was programmed with slot 3's address,
/// because it looks each address up rather than checking the assignment. Here
/// the four globals have four DIFFERENT write counts, so the histogram of
/// reported stops is a fingerprint of the assignment: cross two slots and two
/// counts swap.
#[tokio::test]
async fn four_simultaneous_watchpoints_each_report_their_own_writes() {
    let fx = counting_fixture!();
    let watched: Vec<(u64, u8)> = WRITE_COUNTS.iter().map(|(n, _)| (fx.addr(n), 8u8)).collect();
    let hist = stops_per_address(&fx, &watched).await;
    let want: std::collections::BTreeMap<u64, usize> =
        WRITE_COUNTS.iter().filter(|(_, c)| *c > 0).map(|(n, c)| (fx.addr(n), *c)).collect();
    let named = |a: u64| {
        WRITE_COUNTS.iter().find(|(n, _)| fx.addr(n) == a).map(|(n, _)| *n).unwrap_or("?")
    };
    assert_eq!(
        hist,
        want,
        "with all four globals watched at once the reported writes were {:?}, the source says \
         {:?}",
        hist.iter().map(|(a, c)| (named(*a), *c)).collect::<Vec<_>>(),
        WRITE_COUNTS.iter().filter(|(_, c)| *c > 0).collect::<Vec<_>>()
    );
}

/// The width asked for must reach the hardware, proved by what the program can
/// and cannot be seen doing.
///
/// `each_legal_width_lands_in_the_len_field` decodes LEN out of DR7 — a value
/// the backend itself wrote. This asks the CPU instead. The fixture writes
/// `g_buf[7]` and nothing else in that array, so the SAME base address must be
/// silent when the watchpoint is too narrow to cover byte 7 and must fire three
/// times when it is wide enough. A backend that encoded every request as one
/// byte can pass the DR7 test by lying consistently; it cannot pass this one.
#[tokio::test]
async fn the_watched_width_decides_what_the_hardware_can_see() {
    let fx = counting_fixture!();
    let buf = fx.addr("g_buf");
    // (width, offset into g_buf, writes seen) — byte 7 is the only one written.
    let cases: [(u8, u64, usize); 6] = [
        (1, 0, 0), // one byte at [0]: byte 7 is outside it
        (1, 7, 3), // one byte at [7]: exactly the written byte
        (2, 0, 0), // [0..2)
        (2, 6, 3), // [6..8)
        (4, 0, 0), // [0..4)
        (8, 0, 3), // [0..8) covers byte 7
    ];
    let mut got = Vec::new();
    for (width, off, _) in cases {
        got.push((width, off, total_stops_with(&fx, &[(buf + off, width)]).await));
    }
    let want: Vec<(u8, u64, usize)> = cases.to_vec();
    assert_eq!(
        got, want,
        "(width, offset into g_buf, writes seen) came back {got:?} but the fixture writes only \
         g_buf[7]; a width that does not reach the hardware makes a watchpoint cover the wrong \
         bytes while reporting the width it was asked for"
    );
}

/// `remove_hardware_watchpoint` must stop the TRAPPING, not merely the
/// bookkeeping.
///
/// `removing_a_watchpoint_frees_its_hardware_slot` checks that no debug
/// register still holds the address — again a value the backend wrote. The
/// behavioural claim is different and stronger: after the removal the program
/// must run to completion without stopping once, though it writes the removed
/// address five times.
#[tokio::test]
async fn a_removed_watchpoint_stops_firing() {
    let fx = counting_fixture!();
    let five = fx.addr("g_five");
    let armed = total_stops_with(&fx, &[(five, 8)]).await;
    assert_eq!(armed, 5, "precondition: an armed watchpoint on `g_five` must see all five writes");

    let dbg = LinuxDebugger::new();
    dbg.launch(exe_launch(&fx.exe)).await.expect("launch");
    dbg.set_watchpoint_sized(Address(five), BreakpointKind::DataWrite, 8).await.expect("arm");
    let removed =
        dbg.remove_hardware_watchpoint(Address(five)).await.expect("remove must not error");
    assert!(removed, "removing an armed watchpoint must report that it found one");
    let mut stops = 0usize;
    for _ in 0..96 {
        match dbg.continue_execution().await {
            Ok(ev) => match ev.reason {
                StopReason::Breakpoint { .. } => stops += 1,
                StopReason::ProcessExit { .. } => break,
                _ => {}
            },
            Err(_) => break,
        }
    }
    let _ = dbg.kill().await;
    assert_eq!(
        stops, 0,
        "after remove_hardware_watchpoint the program still trapped {stops} times on writes to \
         `g_five`; the removal cleared the bookkeeping but not the hardware"
    );
}

/// `disable_breakpoint` must silence the hardware and `enable_breakpoint` must
/// bring it back, judged by whether the program actually stops.
///
/// The register-level sibling above reads DR7 back; a backend that disabled by
/// forgetting the entry while leaving the enable bit set would fail that test
/// and this one, but a backend that cleared the bit and lost the ability to
/// re-arm would fail only this one, on its second half.
#[tokio::test]
async fn a_disabled_watchpoint_is_silent_and_re_enabling_restores_every_write() {
    let fx = counting_fixture!();
    let five = fx.addr("g_five");

    for (leave_disabled, expect) in [(true, 0usize), (false, 5usize)] {
        let dbg = LinuxDebugger::new();
        dbg.launch(exe_launch(&fx.exe)).await.expect("launch");
        dbg.set_watchpoint_sized(Address(five), BreakpointKind::DataWrite, 8).await.expect("arm");
        dbg.disable_breakpoint(Address(five)).await.expect("disable_breakpoint on a watchpoint");
        if !leave_disabled {
            dbg.enable_breakpoint(Address(five)).await.expect("enable_breakpoint on a watchpoint");
        }
        let mut stops = 0usize;
        for _ in 0..96 {
            match dbg.continue_execution().await {
                Ok(ev) => match ev.reason {
                    StopReason::Breakpoint { .. } => stops += 1,
                    StopReason::ProcessExit { .. } => break,
                    _ => {}
                },
                Err(_) => break,
            }
        }
        let _ = dbg.kill().await;
        let state = if leave_disabled { "disabled" } else { "disabled then re-enabled" };
        assert_eq!(
            stops, expect,
            "a {state} watchpoint on `g_five` reported {stops} of the five writes, expected \
             {expect}"
        );
    }
}

/// No fixture process may outlive this suite.
///
/// Named `zz_` so it runs last under `--test-threads=1`. `-x` matches the
/// process NAME exactly: `-f` was measured in `live_linux_falsification.rs` to
/// match cargo's own `live_linux_watchpoints-<hash>` binary, so a check written
/// that way reports the thing looking for orphans as an orphan.
#[tokio::test]
async fn zz_no_orphan_watchpoint_fixture_survives() {
    for name in ["wpcount", "wp_write", "wp_thread"] {
        let Ok(out) = std::process::Command::new("pgrep").args(["-x", name]).output() else {
            eprintln!("[test] pgrep is unavailable; the orphan check cannot run");
            return;
        };
        let listed: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        assert!(
            listed.is_empty(),
            "the suite left {} `{name}` process(es) behind: {listed:?}",
            listed.len()
        );
    }
}
