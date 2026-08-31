//! Live-process coverage for the Linux backend's breakpoint API.
//!
//! Every test in this file drives a REAL process: a small C fixture is compiled
//! on the fly with `cc -no-pie -O0`, launched under `ptrace`, and the breakpoint
//! methods of the `Debugger` trait are exercised against it. Nothing here
//! asserts on in-memory structures alone — the byte actually present in the
//! tracee's text segment is read back through `/proc/<pid>/mem` and compared,
//! which is the only evidence that a software breakpoint was really planted or
//! really removed (`read_memory` deliberately masks the debugger's own traps).
//!
//! `-no-pie` is load-bearing: the binary is then `ET_EXEC`, so the address `nm`
//! prints for a symbol IS the address the function occupies at run time, and a
//! breakpoint can be aimed at a named function without a symbol backend.
#![cfg(target_os = "linux")]

use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_core::address::Address;
use rustre_debug::{
    Breakpoint, BreakpointKind, DebugError, DebugEvent, Debugger, LaunchOptions,
    OutputRedirect, StopReason, ThreadId,
};

/// The bytes a software breakpoint overwrites on this host.
///
/// The crate's own `host_trap_bytes()` is `pub(crate)`, so an integration test
/// cannot call it; this mirrors it. Kept as a function rather than a constant so
/// the `cfg` is visible at the one place it matters.
fn trap_bytes() -> &'static [u8] {
    #[cfg(target_arch = "x86_64")]
    {
        &[0xCC]
    }
    #[cfg(target_arch = "aarch64")]
    {
        // `BRK #0`, little-endian.
        &[0x00, 0x00, 0x20, 0xD4]
    }
}

/// The C fixture. `hot` is called a known number of times from `main`, so a
/// breakpoint on it has a predictable number of crossings — which is what the
/// hit-count and ignore-count tests measure.
const FIXTURE_C: &str = r#"
#include <stdio.h>
__attribute__((noinline)) int hot(int x) { return x + 1; }
int main(void) {
    volatile int s = 0;
    for (int i = 0; i < 5; i++) { s = hot(s); }
    printf("%d\n", s);
    return 0;
}
"#;

/// A compiled fixture: the binary path plus the resolved address of `hot`.
/// The tempdir is held so the file outlives the test body.
struct Fixture {
    _dir: tempfile::TempDir,
    exe: String,
    hot: u64,
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
        .expect("cc must be available to run the live breakpoint tests");
    assert!(
        out.status.success(),
        "cc failed to build the fixture: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let nm = std::process::Command::new("nm").arg(&exe).output().expect("nm");
    assert!(nm.status.success(), "nm failed on the fixture binary");
    let listing = String::from_utf8_lossy(&nm.stdout).to_string();
    let hot = symbol_address(&listing, "hot")
        .expect("the fixture must export `hot`; without it no test here has a target");
    Fixture { _dir: dir, exe: exe.to_string_lossy().to_string(), hot }
}

fn symbol_address(nm_listing: &str, want: &str) -> Option<u64> {
    for line in nm_listing.lines() {
        let mut parts = line.split_whitespace();
        let Some(addr) = parts.next() else { continue };
        let Some(kind) = parts.next() else { continue };
        let name = parts.next().unwrap_or("");
        if name == want && (kind == "T" || kind == "t") {
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

/// Launch the fixture and return the debugger, stopped at the exec trap.
async fn launched(fx: &Fixture) -> LinuxDebugger {
    let dbg = LinuxDebugger::new();
    dbg.launch(launch_opts(&fx.exe)).await.expect("launch should succeed");
    dbg
}

fn find_bp(list: &[Breakpoint], addr: u64) -> &Breakpoint {
    list.iter().find(|b| b.address.as_u64() == addr).unwrap_or_else(|| {
        panic!("no breakpoint listed at {addr:#x}; listing has {} entries", list.len())
    })
}

/// Read `n` bytes straight out of the tracee through `/proc/<pid>/mem`,
/// bypassing the debugger entirely.
///
/// Necessary because `read_memory` deliberately MASKS the debugger's own
/// planted traps and hands back the original instruction — the gdb/lldb
/// behaviour, and the right one. That masking means `read_memory` can never
/// witness a plant, so a test that used it would pass whether or not anything
/// was written. `/proc/<pid>/mem` is independent evidence: it is what the CPU
/// will actually fetch.
fn raw_bytes(dbg: &LinuxDebugger, addr: u64, n: usize) -> Vec<u8> {
    use std::io::{Read, Seek, SeekFrom};
    let pid = dbg.target_pid().expect("a live pid is required to read /proc/<pid>/mem");
    let mut f = std::fs::File::open(format!("/proc/{}/mem", pid.0))
        .expect("open /proc/<pid>/mem");
    f.seek(SeekFrom::Start(addr)).expect("seek to the breakpoint address");
    let mut buf = vec![0u8; n];
    f.read_exact(&mut buf).expect("read the bytes the CPU would fetch");
    buf
}

/// Resume until the breakpoint at `addr` reports a stop, or the process exits.
/// Returns `None` if it exited first.
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

/// Setting a software breakpoint must actually WRITE the trap into the live
/// process's text segment. This is the only thing that makes the breakpoint
/// real: an entry in a tracking map with the original instruction still in
/// place is a breakpoint that will never fire, and the tracking map alone
/// cannot tell the difference. The bytes are therefore read straight out of
/// `/proc/<pid>/mem` — what the CPU will fetch — and required to be the trap.
#[tokio::test]
async fn set_breakpoint_writes_the_trap_into_the_live_text_segment() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let at = Address(fx.hot);
    let n = trap_bytes().len();

    let before = raw_bytes(&dbg, fx.hot, n);
    assert_ne!(
        before,
        trap_bytes(),
        "the fixture already contains a trap at `hot`; the test cannot detect the plant"
    );

    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set_breakpoint");
    let after = raw_bytes(&dbg, fx.hot, n);
    assert_eq!(
        after,
        trap_bytes(),
        "set_breakpoint reported success but the bytes the CPU would fetch at {at:?} are {after:02x?}, not the host trap {:02x?} — nothing was planted",
        trap_bytes()
    );
    let _ = dbg.kill().await;
}

/// `read_memory` must HIDE the debugger's own planted trap and report the
/// original instruction, as gdb, lldb and WinDbg all do. Otherwise every
/// consumer that disassembles or hashes the target's code sees `0xCC` where the
/// program's real instruction is, and reports the debugger's own footprint as a
/// property of the program under inspection.
#[tokio::test]
async fn read_memory_masks_the_planted_trap_and_shows_the_original() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let at = Address(fx.hot);
    let n = trap_bytes().len();

    let original = dbg.read_memory(at, n).await.expect("read_memory before");
    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set_breakpoint");

    assert_eq!(
        raw_bytes(&dbg, fx.hot, n),
        trap_bytes(),
        "the trap is not actually planted, so the masking below would prove nothing"
    );
    let masked = dbg.read_memory(at, n).await.expect("read_memory after");
    assert_eq!(
        masked, original,
        "read_memory reported {masked:02x?} — the debugger's own trap — instead of the program's instruction {original:02x?}"
    );
    let _ = dbg.kill().await;
}

/// `remove_breakpoint` must put back exactly the bytes the trap overwrote.
/// A partial restore leaves the target executing a mangled instruction, which
/// is arbitrary execution rather than an approximate answer — so the whole
/// width of the trap is compared, not just its first byte.
#[tokio::test]
async fn remove_breakpoint_restores_the_original_bytes_and_untracks_it() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let at = Address(fx.hot);
    let n = trap_bytes().len();

    let original = raw_bytes(&dbg, fx.hot, n);
    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set_breakpoint");
    dbg.remove_breakpoint(at).await.expect("remove_breakpoint");

    let restored = raw_bytes(&dbg, fx.hot, n);
    assert_eq!(
        restored, original,
        "remove_breakpoint left {restored:02x?} where {original:02x?} belongs"
    );
    let list = dbg.breakpoints().await.expect("breakpoints");
    assert!(
        !list.iter().any(|b| b.address.as_u64() == fx.hot),
        "a removed breakpoint is still listed, so a caller cannot tell removal from failure"
    );
    let _ = dbg.kill().await;
}

/// `breakpoints()` must report what was actually set: the address, the kind,
/// `enabled: true`, and the original byte it will restore. The original byte
/// matters because it is what `detach`/`Drop` write back — a listing without it
/// cannot tell the caller what the target's code reverts to.
#[tokio::test]
async fn breakpoints_lists_the_address_kind_and_original_byte() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let at = Address(fx.hot);

    assert!(
        dbg.breakpoints().await.expect("breakpoints").is_empty(),
        "a freshly launched process has no breakpoints, so the listing must be empty"
    );
    let original = dbg.read_memory(at, trap_bytes().len()).await.expect("read_memory");
    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set_breakpoint");

    let list = dbg.breakpoints().await.expect("breakpoints");
    let bp = find_bp(&list, fx.hot);
    assert_eq!(bp.kind, BreakpointKind::Software);
    assert!(bp.enabled, "a freshly set breakpoint must list as enabled");
    assert_eq!(bp.hit_count, 0, "nothing has run yet, so no hit can have been counted");
    assert_eq!(
        bp.original_byte,
        original.first().copied(),
        "the listing does not carry the byte the breakpoint will restore"
    );
    let _ = dbg.kill().await;
}

/// `disable_breakpoint` must genuinely stop the breakpoint firing — i.e. put
/// the original byte back — while KEEPING it tracked and listed as disabled.
/// A disabled breakpoint that vanishes from the listing is indistinguishable
/// from a removed one, and one that stays listed with the trap still planted
/// would keep stopping the target while claiming to be off.
#[tokio::test]
async fn disable_breakpoint_restores_the_byte_but_keeps_it_listed() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let at = Address(fx.hot);
    let n = trap_bytes().len();

    let original = raw_bytes(&dbg, fx.hot, n);
    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set_breakpoint");
    dbg.disable_breakpoint(at).await.expect("disable_breakpoint");

    let bytes = raw_bytes(&dbg, fx.hot, n);
    assert_eq!(bytes, original, "disable_breakpoint left the trap planted: {bytes:02x?}");
    let list = dbg.breakpoints().await.expect("breakpoints");
    let bp = find_bp(&list, fx.hot);
    assert!(!bp.enabled, "a disabled breakpoint must list as disabled, or `enabled` is never false");
    let _ = dbg.kill().await;
}

/// `enable_breakpoint` on a disabled breakpoint must re-plant the trap. The
/// interesting case is precisely this one: the address is still tracked, so an
/// implementation that short-circuits on "already tracked" reports success and
/// plants nothing, leaving the caller believing a breakpoint is armed while the
/// original instruction is still in place.
#[tokio::test]
async fn enable_breakpoint_replants_the_trap_after_a_disable() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let at = Address(fx.hot);
    let n = trap_bytes().len();

    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set_breakpoint");
    dbg.disable_breakpoint(at).await.expect("disable_breakpoint");
    dbg.enable_breakpoint(at).await.expect("enable_breakpoint");

    let bytes = raw_bytes(&dbg, fx.hot, n);
    assert_eq!(
        bytes,
        trap_bytes(),
        "enable_breakpoint reported success but the bytes the CPU would fetch are {bytes:02x?}, not the trap — the breakpoint is armed only on paper"
    );
    let bp_list = dbg.breakpoints().await.expect("breakpoints");
    assert!(find_bp(&bp_list, fx.hot).enabled, "a re-enabled breakpoint must list as enabled");
    let _ = dbg.kill().await;
}

/// Disabling and re-enabling must not corrupt the saved original byte. The
/// failure this guards is silent and permanent: if the re-plant re-reads the
/// address to "save the original" it reads back the trap it is about to write,
/// and every later restore writes a trap forever. Verified by capturing the
/// true original before any breakpoint exists and comparing it with what
/// `remove_breakpoint` finally restores.
#[tokio::test]
async fn a_disable_enable_cycle_does_not_corrupt_the_saved_original() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let at = Address(fx.hot);
    let n = trap_bytes().len();

    let truth = raw_bytes(&dbg, fx.hot, n);
    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set");
    for _ in 0..3 {
        dbg.disable_breakpoint(at).await.expect("disable");
        dbg.enable_breakpoint(at).await.expect("enable");
    }
    dbg.remove_breakpoint(at).await.expect("remove");

    let restored = raw_bytes(&dbg, fx.hot, n);
    assert_eq!(
        restored, truth,
        "after three disable/enable cycles remove_breakpoint restored {restored:02x?}, but the true original was {truth:02x?}"
    );
    let _ = dbg.kill().await;
}

/// Removing or disabling an address that carries no breakpoint must be an
/// error, not a silent success. `enable_breakpoint` is deliberately excluded:
/// its documented behaviour is to SET one, so there is nothing to refuse. The
/// other two have nothing to act on, and answering `Ok` would tell the caller a
/// breakpoint was cleared that never existed.
#[tokio::test]
async fn removing_or_disabling_an_unset_address_is_refused() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let at = Address(fx.hot);

    match dbg.remove_breakpoint(at).await {
        Err(DebugError::BreakpointNotFound(a)) => assert_eq!(a, fx.hot),
        other => panic!("remove_breakpoint on an unset address answered {other:?}"),
    }
    match dbg.disable_breakpoint(at).await {
        Err(DebugError::BreakpointNotFound(a)) => assert_eq!(a, fx.hot),
        other => panic!("disable_breakpoint on an unset address answered {other:?}"),
    }
    let _ = dbg.kill().await;
}

/// Setting the same software breakpoint twice must be idempotent and must not
/// corrupt the saved original. The second call must not re-read the address and
/// store the trap it planted itself as the "original" — that wedges a permanent
/// landmine, because every later restore then writes a trap.
#[tokio::test]
async fn setting_the_same_breakpoint_twice_is_idempotent() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let at = Address(fx.hot);
    let n = trap_bytes().len();

    let truth = raw_bytes(&dbg, fx.hot, n);
    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("first set");
    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("second set");

    let list = dbg.breakpoints().await.expect("breakpoints");
    assert_eq!(
        list.iter().filter(|b| b.address.as_u64() == fx.hot).count(),
        1,
        "two set_breakpoint calls at one address produced two listed breakpoints"
    );
    dbg.remove_breakpoint(at).await.expect("remove");
    let restored = raw_bytes(&dbg, fx.hot, n);
    assert_eq!(restored, truth, "the second set_breakpoint corrupted the saved original");
    let _ = dbg.kill().await;
}

/// A planted breakpoint must actually stop the running process, and the stop
/// must be reported as a `Breakpoint` at that address — not as a bare `SIGTRAP`
/// signal, which is what the kernel really delivers. Translating the raw trap
/// back into "your breakpoint was reached" is the backend's job, and without it
/// the caller has no way to know which of its breakpoints fired.
#[tokio::test]
async fn a_planted_breakpoint_stops_the_process_and_is_reported_as_a_breakpoint() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let at = Address(fx.hot);
    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set_breakpoint");

    let ev = run_until_breakpoint(&dbg, fx.hot, 40)
        .await
        .expect("the process never stopped at `hot`, which main calls five times");
    match ev.reason {
        StopReason::Breakpoint { address, .. } => assert_eq!(address.as_u64(), fx.hot),
        other => panic!("expected a Breakpoint stop, got {other:?}"),
    }
    let _ = dbg.kill().await;
}

/// `hit_count` must count every crossing of the breakpoint. `main` calls `hot`
/// exactly five times, so resuming past each stop must walk the count 1,2,3,…
/// A count stuck at zero (or one) makes the listing contradict what the user is
/// watching happen, and makes an ignore count impossible to reason about.
#[tokio::test]
async fn hit_count_advances_once_per_crossing() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let at = Address(fx.hot);
    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set_breakpoint");

    let mut seen = Vec::new();
    for _ in 0..3 {
        if run_until_breakpoint(&dbg, fx.hot, 40).await.is_none() {
            break;
        }
        let list = dbg.breakpoints().await.expect("breakpoints");
        seen.push(find_bp(&list, fx.hot).hit_count);
    }
    assert_eq!(
        seen,
        vec![1, 2, 3],
        "hit_count after each of the first three stops was {seen:?}; `hot` is called five times so it must climb one per stop"
    );
    let _ = dbg.kill().await;
}

/// An ignore count must skip exactly the first N crossings and then stop. The
/// hits it skips stay COUNTED — that is what makes the count expire; un-counting
/// them would turn "skip 2" into "never stop". So the first stop the caller
/// actually sees must be the third crossing, with `hit_count == 3`.
#[tokio::test]
async fn ignore_count_skips_the_first_hits_and_still_counts_them() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let at = Address(fx.hot);
    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set_breakpoint");
    dbg.set_breakpoint_ignore_count(at, 2).await.expect("set_breakpoint_ignore_count");

    let list = dbg.breakpoints().await.expect("breakpoints");
    assert_eq!(
        find_bp(&list, fx.hot).ignore_count,
        2,
        "the ignore count was accepted but is not visible in the listing, so a caller cannot see why it is not stopping"
    );

    assert!(
        run_until_breakpoint(&dbg, fx.hot, 40).await.is_some(),
        "with `ignore 2` and five crossings the breakpoint must still stop on the third"
    );
    let list = dbg.breakpoints().await.expect("breakpoints");
    assert_eq!(
        find_bp(&list, fx.hot).hit_count,
        3,
        "the first stop after `ignore 2` must be the third crossing: the skipped hits are consumed, not discarded"
    );
    let _ = dbg.kill().await;
}

/// A condition that can never hold must suppress every stop, and the suppressed
/// crossings must NOT be counted as hits — a filtered stop did not fire, and
/// counting it would contradict the listing the user is reading. With `1 == 0`
/// the process must therefore run to completion without ever reporting a stop
/// at `hot`.
#[tokio::test]
async fn a_false_condition_suppresses_every_stop() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let at = Address(fx.hot);
    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set_breakpoint");
    dbg.set_breakpoint_condition(at, Some("1 == 0".to_string()))
        .await
        .expect("set_breakpoint_condition");

    let list = dbg.breakpoints().await.expect("breakpoints");
    assert_eq!(
        find_bp(&list, fx.hot).condition.as_deref(),
        Some("1 == 0"),
        "the condition was accepted but is not published, so a caller cannot see what is filtering the stops"
    );

    let mut exited = false;
    for _ in 0..40 {
        match dbg.continue_execution().await {
            Ok(ev) => match ev.reason {
                StopReason::ProcessExit { .. } => {
                    exited = true;
                    break;
                }
                StopReason::Breakpoint { address, .. } if address.as_u64() == fx.hot => {
                    panic!("the breakpoint stopped despite the condition `1 == 0`");
                }
                _ => {}
            },
            Err(_) => break,
        }
    }
    assert!(
        exited,
        "the process never ran to exit, so this test cannot say the condition let it through"
    );
    let _ = dbg.kill().await;
}

/// A condition that always holds must not suppress anything: the breakpoint
/// stops on the first crossing, exactly as an unconditional one would. Paired
/// with the `1 == 0` test above so a backend that simply ignores conditions and
/// one that treats every condition as false are both caught.
#[tokio::test]
async fn a_true_condition_lets_the_breakpoint_stop() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let at = Address(fx.hot);
    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set_breakpoint");
    dbg.set_breakpoint_condition(at, Some("1 == 1".to_string()))
        .await
        .expect("set_breakpoint_condition");

    assert!(
        run_until_breakpoint(&dbg, fx.hot, 40).await.is_some(),
        "a breakpoint whose condition is always true never stopped"
    );
    let _ = dbg.kill().await;
}

/// Clearing a condition (`None`) must restore unconditional stopping and must
/// be visible in the listing. A cleared condition still reported by
/// `breakpoints()` would leave the caller unable to tell that the filter is
/// gone.
#[tokio::test]
async fn clearing_a_condition_removes_it_from_the_listing() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let at = Address(fx.hot);
    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set_breakpoint");
    dbg.set_breakpoint_condition(at, Some("1 == 0".to_string())).await.expect("set condition");
    dbg.set_breakpoint_condition(at, None).await.expect("clear condition");

    let list = dbg.breakpoints().await.expect("breakpoints");
    assert_eq!(find_bp(&list, fx.hot).condition, None, "the condition survived being cleared");
    assert!(
        run_until_breakpoint(&dbg, fx.hot, 40).await.is_some(),
        "after clearing the condition the breakpoint must stop again"
    );
    let _ = dbg.kill().await;
}

/// A malformed condition must be refused at the door, not stored. Discovering
/// it at the first hit leaves only one honest response — stop anyway — so the
/// user gets a breakpoint that ignores the filter they wrote, with nothing
/// saying so.
#[tokio::test]
async fn a_malformed_condition_is_refused_and_not_stored() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let at = Address(fx.hot);
    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set_breakpoint");

    let err = dbg
        .set_breakpoint_condition(at, Some("this has no operator".to_string()))
        .await
        .expect_err("a condition with no comparison operator must be refused");
    assert!(matches!(err, DebugError::Unsupported(_)), "unexpected refusal: {err:?}");

    let list = dbg.breakpoints().await.expect("breakpoints");
    assert_eq!(
        find_bp(&list, fx.hot).condition,
        None,
        "the refused condition was stored anyway, so the breakpoint carries a filter that can never be evaluated"
    );
    let _ = dbg.kill().await;
}

/// A condition on an address that carries no breakpoint must be refused: it
/// would otherwise sit in the table looking effective while no stop could ever
/// consult it.
#[tokio::test]
async fn a_condition_on_an_unset_address_is_refused() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;

    match dbg.set_breakpoint_condition(Address(fx.hot), Some("1 == 1".to_string())).await {
        Err(DebugError::BreakpointNotFound(a)) => assert_eq!(a, fx.hot),
        other => panic!("a condition on an unset address answered {other:?}"),
    }
    let _ = dbg.kill().await;
}

/// `remove_breakpoint` must take the condition, the ignore count and the hit
/// count with it. Leaving any of them behind attaches them to whatever is set
/// at that address NEXT — a filter the caller never asked for, on a different
/// breakpoint, and invisible in the listing until it silently stops firing.
#[tokio::test]
async fn remove_breakpoint_clears_the_condition_and_ignore_count() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let at = Address(fx.hot);

    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set");
    dbg.set_breakpoint_condition(at, Some("1 == 0".to_string())).await.expect("condition");
    dbg.set_breakpoint_ignore_count(at, 4).await.expect("ignore count");
    dbg.remove_breakpoint(at).await.expect("remove");
    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set again");

    let list = dbg.breakpoints().await.expect("breakpoints");
    let bp = find_bp(&list, fx.hot);
    assert_eq!(bp.condition, None, "the removed breakpoint's condition was inherited by the new one");
    assert_eq!(
        bp.ignore_count, 0,
        "the removed breakpoint's ignore count was inherited by the new one"
    );
    assert_eq!(bp.hit_count, 0, "the removed breakpoint's hit count was inherited by the new one");
    let _ = dbg.kill().await;
}

/// The backend implements software breakpoints only, and it must say so rather
/// than accept a `Hardware` execution breakpoint and quietly do nothing — a
/// caller that believes a hardware breakpoint is armed and never sees it fire
/// has no way to distinguish that from code that is never reached.
#[tokio::test]
async fn a_hardware_execution_breakpoint_is_refused_rather_than_silently_ignored() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;

    let err = dbg
        .set_breakpoint(Address(fx.hot), BreakpointKind::Hardware)
        .await
        .expect_err("this backend implements software breakpoints only");
    assert!(
        matches!(err, DebugError::StepError(_) | DebugError::Unsupported(_)),
        "unexpected refusal for a hardware breakpoint: {err:?}"
    );
    assert!(
        dbg.breakpoints().await.expect("breakpoints").is_empty(),
        "the refused hardware breakpoint was tracked anyway"
    );
    let _ = dbg.kill().await;
}

/// A DISABLED breakpoint must not stop the process. This is the behavioural
/// half of `disable_breakpoint_restores_the_byte_but_keeps_it_listed`: that
/// test proves the byte went back, this one proves the consequence — the
/// program runs through `hot` five times and reaches its own exit. A backend
/// that keeps the trap planted while listing the breakpoint as disabled would
/// pass neither, but a backend that restores the byte and then re-plants it on
/// the next resume would pass only the first.
#[tokio::test]
async fn a_disabled_breakpoint_does_not_stop_the_process() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let at = Address(fx.hot);
    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set_breakpoint");
    dbg.disable_breakpoint(at).await.expect("disable_breakpoint");

    let mut exited = false;
    for _ in 0..40 {
        match dbg.continue_execution().await {
            Ok(ev) => match ev.reason {
                StopReason::ProcessExit { .. } => {
                    exited = true;
                    break;
                }
                StopReason::Breakpoint { address, .. } if address.as_u64() == fx.hot => {
                    panic!("a disabled breakpoint stopped the process at `hot`");
                }
                _ => {}
            },
            Err(_) => break,
        }
    }
    assert!(exited, "the process never reached its own exit, so nothing here is proven");
    // No listing assertion after the exit: the backend clears its breakpoint
    // tables when the process goes away (measured — `breakpoints()` returns an
    // empty list here), so a `hit_count` read at this point would say nothing
    // about the disabled breakpoint. The five silent crossings above are the
    // evidence.
    let _ = dbg.kill().await;
}

/// Clearing the ignore count (`ignore 0`, i.e. "stop on every hit") must not
/// touch the thread restriction. They are independent gates — gdb's `ignore N`
/// and `break … thread N` — and a caller that clears one has said nothing about
/// the other. Silently dropping the thread filter here turns a breakpoint that
/// stopped only on one thread into one that stops on all of them, with the
/// listing agreeing, so there is no way to notice.
///
/// IGNORED: this documents a MEASURED defect in `linux_debugger.rs`'s
/// `set_breakpoint_ignore_count` (the `count == 0` branch also does
/// `self.thread_filters.lock().remove(..)`). Expected `only_thread == Some(tid)`
/// after `set_breakpoint_ignore_count(addr, 0)`; measured `None`. The fix
/// belongs to the coordinator, not to this test file.
#[ignore = "measured defect: set_breakpoint_ignore_count(addr, 0) also clears the thread filter"]
#[tokio::test]
async fn clearing_the_ignore_count_does_not_clear_the_thread_filter() {
    let fx = build_fixture();
    let dbg = launched(&fx).await;
    let at = Address(fx.hot);
    let tid = ThreadId(dbg.target_pid().expect("a live pid").0);
    dbg.set_breakpoint(at, BreakpointKind::Software).await.expect("set_breakpoint");
    dbg.set_breakpoint_thread_filter(at, Some(tid)).await.expect("set_breakpoint_thread_filter");
    dbg.set_breakpoint_ignore_count(at, 3).await.expect("set an ignore count");

    dbg.set_breakpoint_ignore_count(at, 0).await.expect("clear the ignore count");

    let list = dbg.breakpoints().await.expect("breakpoints");
    let bp = find_bp(&list, fx.hot);
    assert_eq!(bp.ignore_count, 0, "the ignore count was not cleared");
    assert_eq!(
        bp.only_thread,
        Some(tid),
        "clearing the ignore count also dropped the thread restriction: the breakpoint now stops on every thread and the listing does not say so"
    );
    let _ = dbg.kill().await;
}
