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
