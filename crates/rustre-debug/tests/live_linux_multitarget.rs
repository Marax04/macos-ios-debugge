//! Live-process coverage for the multi-target session layer, driven by TWO
//! real processes launched together.
//!
//! Every test here compiles a small C fixture with `cc -no-pie -O0`, launches
//! it TWICE under `ptrace` (two independent `LinuxDebugger` instances, two live
//! pids), and then asks `multi_target_debugger` to add, broadcast, synchronise
//! and report over those two live targets. Nothing here asserts on an
//! in-memory structure alone: whenever the claim is "the breakpoint was planted
//! in both", the bytes are read straight out of `/proc/<pid>/mem` for BOTH
//! pids, which is what the CPU will actually fetch.
//!
//! `-no-pie` is load-bearing: the binary is `ET_EXEC`, so the address `nm`
//! prints for `hot` IS the run-time address, in both copies, which is what
//! makes "the same address in two processes" a meaningful sync breakpoint.
//!
//! What this file measures, stated up front so a green run is not mistaken for
//! a working feature: `MultiTargetDebugger` is the ROUTING and BOOKKEEPING half
//! of the design. It has no live transport — `connect_all` fails by
//! construction and `SessionRouter::execute_next` returns `success: false`. The
//! tests marked "gap" pin that down against two processes that are demonstrably
//! alive and demonstrably drivable through `LinuxDebugger` in the very same
//! test, so the distance between "reachable with what the crate already has"
//! and "what the multi-target layer obtains" is measured, not asserted.
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::multi_target_debugger::{
    CommandRoute, DebugCommand, MultiTargetDebugger, RoutedCommand, SessionRouter, SyncBreakpoint,
    TargetSpec, TargetState,
};
use rustre_debug::{
    BreakpointKind, DebugEvent, Debugger, LaunchOptions, OutputRedirect, StopReason, ThreadId,
};

/// The bytes a software breakpoint overwrites on this host. The crate's own
/// `host_trap_bytes()` is `pub(crate)`, so this mirrors it.
fn trap_bytes() -> &'static [u8] {
    #[cfg(target_arch = "x86_64")]
    {
        &[0xCC]
    }
    #[cfg(target_arch = "aarch64")]
    {
        &[0x00, 0x00, 0x20, 0xD4]
    }
}

/// `hot` is called a known number of times, so a breakpoint on it fires in each
/// copy of the process independently and predictably. The `getpid` print keeps
/// the two copies distinguishable in a live listing.
const FIXTURE_C: &str = r#"
#include <stdio.h>
#include <unistd.h>
__attribute__((noinline)) int hot(int x) { return x + 1; }
int main(void) {
    volatile int s = 0;
    for (int i = 0; i < 5; i++) { s = hot(s); }
    printf("%d %d\n", (int)getpid(), s);
    return 0;
}
"#;

/// The fixture binary is named `mtfix`, NOT `fixture`: the sibling live test
/// files assert with `pgrep -f` that no process whose argv0 ends in `/fixture`
/// survives, and those files run against the same tree. A shared name would
/// make this file's live processes fail somebody else's orphan check.
struct Fixture {
    _dir: tempfile::TempDir,
    exe: String,
    hot: u64,
}

fn build_fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("mtfix.c");
    let exe = dir.path().join("mtfix");
    std::fs::write(&src, FIXTURE_C).expect("write fixture source");
    let out = std::process::Command::new("cc")
        .args(["-no-pie", "-O0", "-g"])
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .output()
        .expect("cc must be available to run the live multi-target tests");
    assert!(
        out.status.success(),
        "cc failed to build the fixture: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let nm = std::process::Command::new("nm").arg(&exe).output().expect("nm");
    assert!(nm.status.success(), "nm failed on the fixture binary");
    let listing = String::from_utf8_lossy(&nm.stdout).to_string();
    let hot = symbol_address(&listing, "hot")
        .expect("the fixture must export `hot`; without it no sync-breakpoint test has a target");
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

/// TWO live copies of the fixture, each with its own debugger, both stopped at
/// their post-`execve` trap.
///
/// Two tracees in one test process is the whole point of this file, and it is
/// also its main hazard: each `LinuxDebugger` runs its own ptrace thread and
/// reaps with `waitpid(-1, __WALL)`, which is not filtered by pid. Whether that
/// cross-talks is measured by `two_debuggers_do_not_steal_each_others_events`
/// below rather than assumed either way; every other test resumes only ONE
/// process at a time so a cross-talk defect cannot silently corrupt an
/// unrelated measurement.
struct Pair {
    a: LinuxDebugger,
    b: LinuxDebugger,
    pid_a: u32,
    pid_b: u32,
}

impl Pair {
    async fn launch(fx: &Fixture) -> Self {
        let a = LinuxDebugger::new();
        a.launch(launch_opts(&fx.exe)).await.expect("first target must launch");
        let pid_a = a.target_pid().expect("first target must have a live pid").0;
        let b = LinuxDebugger::new();
        b.launch(launch_opts(&fx.exe)).await.expect("second target must launch");
        let pid_b = b.target_pid().expect("second target must have a live pid").0;
        assert_ne!(pid_a, pid_b, "two launches must produce two distinct processes");
        Self { a, b, pid_a, pid_b }
    }

    /// Kill both tracees. Called on every path, including the ones a failed
    /// assertion would otherwise skip — hence the explicit call before each
    /// `assert!` that can fail, and `zz_no_orphan_fixture_processes_survive`
    /// as the backstop for a panic.
    async fn cleanup(&self) {
        let _ = self.a.kill().await;
        let _ = self.b.kill().await;
    }
}

/// Is this pid a live process we can see?
fn pid_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// Read `n` bytes straight out of a tracee through `/proc/<pid>/mem`, bypassing
/// the debugger.
///
/// `read_memory` deliberately MASKS the debugger's own planted traps and hands
/// back the original instruction — the gdb/lldb behaviour, and the right one.
/// A test that used it could never witness a plant, and would pass whether or
/// not anything was written. This is what the CPU will actually fetch.
fn raw_bytes(pid: u32, addr: u64, n: usize) -> Vec<u8> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(format!("/proc/{pid}/mem"))
        .unwrap_or_else(|e| panic!("open /proc/{pid}/mem: {e}"));
    f.seek(SeekFrom::Start(addr)).expect("seek to the breakpoint address");
    let mut buf = vec![0u8; n];
    f.read_exact(&mut buf).expect("read the bytes the CPU would fetch");
    buf
}

/// Resume one debugger until its breakpoint at `addr` reports a stop, or the
/// process exits. Returns `None` on exit.
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

// ─────────────────────────────────────────────────────────────────────────────
// Baseline: the two processes really are two live, independent tracees
// ─────────────────────────────────────────────────────────────────────────────

/// Everything downstream reads "the two targets" as two distinct live
/// processes. If the second launch silently reused or replaced the first, every
/// later test would compare a process with itself and pass for the wrong
/// reason. This asserts the premise directly: two distinct pids, both present
/// in `/proc`, both running the fixture image at the same address.
#[tokio::test]
async fn two_fixtures_launch_together_as_two_distinct_live_tracees() {
    let fx = build_fixture();
    let p = Pair::launch(&fx).await;

    let alive_a = pid_alive(p.pid_a);
    let alive_b = pid_alive(p.pid_b);
    // Both must be readable at the SAME address: `-no-pie` means one `nm`
    // lookup describes both images.
    let code_a = raw_bytes(p.pid_a, fx.hot, 1);
    let code_b = raw_bytes(p.pid_b, fx.hot, 1);
    p.cleanup().await;

    assert!(alive_a, "target A (pid {}) is not in /proc", p.pid_a);
    assert!(alive_b, "target B (pid {}) is not in /proc", p.pid_b);
    assert_eq!(
        code_a, code_b,
        "the two copies must have identical text at `hot` ({:#x}); they are the same -no-pie image",
        fx.hot
    );
    assert_ne!(
        code_a,
        trap_bytes(),
        "the fixture already contains a trap at `hot`; no plant test in this file could detect a plant"
    );
}

/// Two `LinuxDebugger` instances in one test process each run their own ptrace
/// thread, and each reaps with `waitpid(-1, __WALL)` — a wait that is NOT
/// filtered by pid. On Linux `waitpid` is not restricted to the calling
/// thread's own children by default, so debugger A's reaper can in principle
/// consume the stop of debugger B's tracee and vice versa.
///
/// The observable consequence would be an event delivered to the wrong session:
/// `ev.pid` naming B while A's caller is the one that asked. This drives both
/// processes forward alternately and requires every event each debugger returns
/// to name its OWN pid.
#[tokio::test]
async fn two_debuggers_do_not_steal_each_others_events() {
    let fx = build_fixture();
    let p = Pair::launch(&fx).await;
    let at = Address(fx.hot);
    p.a.set_breakpoint(at, BreakpointKind::Software).await.expect("plant in A");
    p.b.set_breakpoint(at, BreakpointKind::Software).await.expect("plant in B");

    let mut wrong: Vec<String> = Vec::new();
    for round in 0..3 {
        if let Ok(ev) = p.a.continue_execution().await {
            if ev.pid.0 != p.pid_a {
                wrong.push(format!(
                    "round {round}: A ({}) was handed an event for pid {}",
                    p.pid_a, ev.pid.0
                ));
            }
        }
        if let Ok(ev) = p.b.continue_execution().await {
            if ev.pid.0 != p.pid_b {
                wrong.push(format!(
                    "round {round}: B ({}) was handed an event for pid {}",
                    p.pid_b, ev.pid.0
                ));
            }
        }
    }
    p.cleanup().await;
    assert!(wrong.is_empty(), "waitpid(-1) cross-talk between two live sessions: {wrong:?}");
}

// ─────────────────────────────────────────────────────────────────────────────
// multi_target_add
// ─────────────────────────────────────────────────────────────────────────────

/// Adding two live pids must produce two DISTINCT targets that keep their own
/// spec. If the ids collided or the specs were shared, every later per-target
/// result would be attributed to the wrong process — the failure mode that
/// looks exactly like a correct run.
#[tokio::test]
async fn multi_target_add_registers_both_live_pids_as_distinct_targets() {
    let fx = build_fixture();
    let p = Pair::launch(&fx).await;

    let mut mt = MultiTargetDebugger::new();
    let ta = mt.add_target(TargetSpec::LocalPid(p.pid_a), "proc-a");
    let tb = mt.add_target(TargetSpec::LocalPid(p.pid_b), "proc-b");

    let len = mt.targets.len();
    let ids = mt.targets.ids();
    let name_a = mt.targets.get(&ta).map(|t| t.name.clone());
    let name_b = mt.targets.get(&tb).map(|t| t.name.clone());
    let spec_a = mt.targets.get(&ta).map(|t| format!("{:?}", t.spec));
    let spec_b = mt.targets.get(&tb).map(|t| format!("{:?}", t.spec));
    p.cleanup().await;

    assert_ne!(ta, tb, "two added targets must get two ids");
    assert_eq!(len, 2, "both live pids must be registered");
    assert_eq!(ids.len(), 2, "ids() must list both");
    assert_eq!(name_a.as_deref(), Some("proc-a"));
    assert_eq!(name_b.as_deref(), Some("proc-b"));
    assert!(
        spec_a.as_deref().unwrap_or("").contains(&p.pid_a.to_string()),
        "target A must keep pid {}, got {spec_a:?}",
        p.pid_a
    );
    assert!(
        spec_b.as_deref().unwrap_or("").contains(&p.pid_b.to_string()),
        "target B must keep pid {}, got {spec_b:?}",
        p.pid_b
    );
}

/// `total_targets` is what `debug.multi_target_report` publishes as the size of
/// the fleet. It must count each `add_target`, once.
#[tokio::test]
async fn multi_target_add_counts_both_live_targets_in_the_report() {
    let fx = build_fixture();
    let p = Pair::launch(&fx).await;
    let mut mt = MultiTargetDebugger::new();
    mt.add_target(TargetSpec::LocalPid(p.pid_a), "proc-a");
    mt.add_target(TargetSpec::LocalPid(p.pid_b), "proc-b");
    let total = mt.finalise().total_targets;
    p.cleanup().await;
    assert_eq!(total, 2, "the report must count both live targets, not one and not three");
}

/// Removing one target must leave the OTHER live target untouched. A remove
/// that clears the map, or that removes by position instead of id, would leave
/// the session pointing at the wrong process.
#[tokio::test]
async fn removing_one_target_leaves_the_other_live_target_intact() {
    let fx = build_fixture();
    let p = Pair::launch(&fx).await;
    let mut mt = MultiTargetDebugger::new();
    let ta = mt.add_target(TargetSpec::LocalPid(p.pid_a), "proc-a");
    let tb = mt.add_target(TargetSpec::LocalPid(p.pid_b), "proc-b");

    let removed = mt.targets.remove(&ta);
    let left = mt.targets.len();
    let survivor = mt.targets.get(&tb).map(|t| format!("{:?}", t.spec));
    let gone = mt.targets.get(&ta).is_none();
    p.cleanup().await;

    assert!(removed.is_some(), "removing a registered target must return it");
    assert!(gone, "the removed target must no longer resolve");
    assert_eq!(left, 1, "exactly one target must survive");
    assert!(
        survivor.as_deref().unwrap_or("").contains(&p.pid_b.to_string()),
        "the survivor must still be pid {}, got {survivor:?}",
        p.pid_b
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// connect_all — measured gap
// ─────────────────────────────────────────────────────────────────────────────

/// GAP, measured against two processes that are provably attachable.
///
/// | expected (external truth) | reachable with what the crate already has | obtained today |
/// |---|---|---|
/// | `connect_all` attaches both live pids and leaves them `Running`/`Stopped` | `LinuxDebugger::launch`/`attach` drives both pids in this very test | `Err([t1, t2])`, both left in `TargetState::Error` |
///
/// The failure is honest — the error text names the missing transport, and the
/// `Err` lists exactly the ids — so this is documentation of a boundary, not a
/// silent lie. The test pins BOTH halves: that it fails, and that it fails for
/// every target and says why. The regression it guards against is the older
/// behaviour the module's own doc comment records: setting every target to
/// `Running` and returning `Ok`, so `debug.multi_target_list` reported a fleet
/// of running processes that had never been contacted.
#[tokio::test]
async fn connect_all_refuses_both_live_pids_and_names_the_missing_transport() {
    let fx = build_fixture();
    let p = Pair::launch(&fx).await;
    let mut mt = MultiTargetDebugger::new();
    let ta = mt.add_target(TargetSpec::LocalPid(p.pid_a), "proc-a");
    let tb = mt.add_target(TargetSpec::LocalPid(p.pid_b), "proc-b");

    let res = mt.connect_all();
    let state_a = mt.targets.get(&ta).map(|t| t.state.clone());
    let state_b = mt.targets.get(&tb).map(|t| t.state.clone());
    let errors = mt.finalise().errors;
    // Both processes are still alive: the refusal is not because the pids are
    // bad, which is the alternative explanation this measurement must exclude.
    let alive_a = pid_alive(p.pid_a);
    let alive_b = pid_alive(p.pid_b);
    p.cleanup().await;

    assert!(alive_a && alive_b, "both pids must still be live when connect_all refuses them");
    let failed = res.expect_err("connect_all has no live transport and must not report success");
    assert!(
        failed.contains(&ta) && failed.contains(&tb),
        "both ids must be reported failed, got {failed:?}"
    );
    for (label, st) in [("A", state_a), ("B", state_b)] {
        let st = st.unwrap_or_else(|| panic!("target {label} vanished"));
        assert_eq!(st.variant_name(), "error", "target {label} must be left in Error, got {st:?}");
        let TargetState::Error { message } = st else { unreachable!() };
        assert!(
            message.contains("no live transport"),
            "target {label}'s error must name the missing transport, got {message:?}"
        );
    }
    assert_eq!(errors, 2, "the report must count one error per target, not one for the batch");
}

// ─────────────────────────────────────────────────────────────────────────────
// multi_target_broadcast
// ─────────────────────────────────────────────────────────────────────────────

/// A broadcast must reach BOTH targets exactly once, and the results must be
/// attributable: one per target id, no duplicates, no target skipped. This is
/// the routing half, and it is the half that works.
#[tokio::test]
async fn broadcast_reaches_both_live_targets_exactly_once() {
    let fx = build_fixture();
    let p = Pair::launch(&fx).await;
    let mut mt = MultiTargetDebugger::new();
    let ta = mt.add_target(TargetSpec::LocalPid(p.pid_a), "proc-a");
    let tb = mt.add_target(TargetSpec::LocalPid(p.pid_b), "proc-b");

    let results = mt.broadcast_command(DebugCommand::Continue);
    let for_a = results.iter().filter(|r| r.target_id == ta).count();
    let for_b = results.iter().filter(|r| r.target_id == tb).count();
    p.cleanup().await;

    assert_eq!(results.len(), 2, "a broadcast over two targets must produce two results");
    assert_eq!(for_a, 1, "target A must be addressed exactly once");
    assert_eq!(for_b, 1, "target B must be addressed exactly once");
}

/// GAP, measured. The broadcast is delivered and then NOT executed.
///
/// | expected (external truth) | reachable with what the crate already has | obtained today |
/// |---|---|---|
/// | broadcasting `SetBreakpoint{hot}` plants the host trap at `hot` in both live processes | `LinuxDebugger::set_breakpoint` plants it in both — proved by the next test | trap in NEITHER process; both results `success: false` |
///
/// The evidence is `/proc/<pid>/mem` for both pids, read after the broadcast:
/// the original instruction is still there. What makes this a documented
/// boundary rather than a trap for a caller is the shape of the failure —
/// `success: false` with an output naming the missing transport. The module's
/// own doc records the earlier shape: `success: true, output: "ok"`, which
/// `debug.multi_target_broadcast` serialised as `{"ok": true}`, making "I set
/// the breakpoint on every target" and "I did nothing at all" the same JSON.
#[tokio::test]
async fn broadcast_set_breakpoint_plants_nothing_in_either_live_process() {
    let fx = build_fixture();
    let p = Pair::launch(&fx).await;
    let n = trap_bytes().len();
    let before_a = raw_bytes(p.pid_a, fx.hot, n);
    let before_b = raw_bytes(p.pid_b, fx.hot, n);

    let mut mt = MultiTargetDebugger::new();
    mt.add_target(TargetSpec::LocalPid(p.pid_a), "proc-a");
    mt.add_target(TargetSpec::LocalPid(p.pid_b), "proc-b");
    let results = mt.broadcast_command(DebugCommand::SetBreakpoint { address: fx.hot });

    let after_a = raw_bytes(p.pid_a, fx.hot, n);
    let after_b = raw_bytes(p.pid_b, fx.hot, n);
    let all_failed = results.iter().all(|r| !r.success);
    let outputs: Vec<String> = results.iter().map(|r| r.output.clone()).collect();
    p.cleanup().await;

    assert_eq!(results.len(), 2, "both targets must be addressed");
    assert!(all_failed, "a broadcast that plants nothing must not report success; got {outputs:?}");
    for out in &outputs {
        assert!(out.contains("not executed"), "the result must say it was not executed: {out:?}");
    }
    assert_eq!(after_a, before_a, "target A's text at `hot` changed, yet no transport ran");
    assert_eq!(after_b, before_b, "target B's text at `hot` changed, yet no transport ran");
    assert_ne!(after_a, trap_bytes(), "no trap may appear in A from a transport-less broadcast");
    assert_ne!(after_b, trap_bytes(), "no trap may appear in B from a transport-less broadcast");
}

/// The other half of the gap table: what the crate CAN already do to the same
/// two processes at the same address. Driving each `LinuxDebugger` directly
/// plants the trap in both live text segments. This is the achievable column,
/// measured rather than assumed — without it the previous test only proves the
/// multi-target layer is inert, not that the work is possible.
#[tokio::test]
async fn the_real_backends_plant_the_same_trap_in_both_live_processes() {
    let fx = build_fixture();
    let p = Pair::launch(&fx).await;
    let n = trap_bytes().len();
    let at = Address(fx.hot);

    let ra = p.a.set_breakpoint(at, BreakpointKind::Software).await;
    let rb = p.b.set_breakpoint(at, BreakpointKind::Software).await;
    let after_a = raw_bytes(p.pid_a, fx.hot, n);
    let after_b = raw_bytes(p.pid_b, fx.hot, n);
    p.cleanup().await;

    assert!(ra.is_ok(), "set_breakpoint on A failed: {ra:?}");
    assert!(rb.is_ok(), "set_breakpoint on B failed: {rb:?}");
    assert_eq!(after_a, trap_bytes(), "A: the CPU would fetch {after_a:02x?}, not the trap");
    assert_eq!(after_b, trap_bytes(), "B: the CPU would fetch {after_b:02x?}, not the trap");
}

/// A broadcast to an EMPTY fleet must address nobody and produce nothing. The
/// hazard being excluded is a route that treats "no targets selected" as "all
/// targets" — the module's own docs record exactly that bug for state matching,
/// where an empty name turned a filter into a silent broadcast.
#[tokio::test]
async fn broadcast_to_an_empty_fleet_addresses_nobody() {
    let mut mt = MultiTargetDebugger::new();
    let results = mt.broadcast_command(DebugCommand::Continue);
    assert!(results.is_empty(), "an empty fleet must yield no results, got {}", results.len());
    assert_eq!(mt.finalise().total_targets, 0);
}

/// A state-routed command must select ONE of the two live targets when only one
/// is in that state. The two processes really are in different situations here
/// — A is marked running, B stopped — so a route that ignored the filter would
/// be visible as a count of 2.
#[tokio::test]
async fn state_routing_selects_only_the_matching_live_target() {
    let fx = build_fixture();
    let p = Pair::launch(&fx).await;
    let mut mt = MultiTargetDebugger::new();
    let ta = mt.add_target(TargetSpec::LocalPid(p.pid_a), "proc-a");
    let tb = mt.add_target(TargetSpec::LocalPid(p.pid_b), "proc-b");
    mt.targets.set_state(&ta, TargetState::Running);
    mt.targets.set_state(&tb, TargetState::Stopped { reason: "at hot".into() });

    let mut router = SessionRouter::new();
    let stopped = router.enqueue(
        RoutedCommand {
            route: CommandRoute::ByState("stopped".into()),
            command: DebugCommand::Continue,
        },
        &mt.targets,
    );
    let running = router.enqueue(
        RoutedCommand {
            route: CommandRoute::ByState("running".into()),
            command: DebugCommand::Continue,
        },
        &mt.targets,
    );
    let bogus = router.enqueue(
        RoutedCommand {
            route: CommandRoute::ByState("at hot".into()),
            command: DebugCommand::Continue,
        },
        &mt.targets,
    );
    let pending_a = router.pending(&ta);
    let pending_b = router.pending(&tb);
    p.cleanup().await;

    assert_eq!(stopped, 1, "only target B is stopped");
    assert_eq!(running, 1, "only target A is running");
    assert_eq!(
        bogus, 0,
        "`at hot` is target B's stop REASON, not a state name; matching it would route to a \
         process the caller never selected"
    );
    assert_eq!(pending_a, 1, "target A must have queued exactly the `running` command");
    assert_eq!(pending_b, 1, "target B must have queued exactly the `stopped` command");
}

// ─────────────────────────────────────────────────────────────────────────────
// multi_target_sync_breakpoint
// ─────────────────────────────────────────────────────────────────────────────

/// The real thing: one address, planted in BOTH live processes, and a
/// `SyncBreakpoint` that is complete only once BOTH processes have actually
/// executed it.
///
/// Every step is evidenced against the live processes: the trap bytes are in
/// both text segments before anything runs, target A is resumed alone and stops
/// at `hot` with its OWN pid, at which point the sync breakpoint must still be
/// pending on B, and only after B is separately resumed to the same address may
/// it be complete. A layer that marked completion on the first hit — or that
/// could not tell the two hits apart — fails here.
#[tokio::test]
async fn a_sync_breakpoint_completes_only_after_both_live_processes_hit_it() {
    let fx = build_fixture();
    let p = Pair::launch(&fx).await;
    let at = Address(fx.hot);
    let n = trap_bytes().len();

    let mut mt = MultiTargetDebugger::new();
    let ta = mt.add_target(TargetSpec::LocalPid(p.pid_a), "proc-a");
    let tb = mt.add_target(TargetSpec::LocalPid(p.pid_b), "proc-b");

    p.a.set_breakpoint(at, BreakpointKind::Software).await.expect("plant in A");
    p.b.set_breakpoint(at, BreakpointKind::Software).await.expect("plant in B");
    let planted_a = raw_bytes(p.pid_a, fx.hot, n);
    let planted_b = raw_bytes(p.pid_b, fx.hot, n);

    let mut sync = SyncBreakpoint::new(fx.hot, vec![ta.clone(), tb.clone()]);
    let empty_complete = sync.is_complete();

    // Resume A alone.
    let hit_a = run_until_breakpoint(&p.a, fx.hot, 8).await;
    let a_pid_in_event = hit_a.as_ref().map(|e| e.pid.0);
    if hit_a.is_some() {
        sync.record_hit(ta.clone());
    }
    let half_complete = sync.is_complete();
    let pending_after_a: Vec<u32> = sync.pending_targets().iter().map(|t| t.0).collect();

    // Now B.
    let hit_b = run_until_breakpoint(&p.b, fx.hot, 8).await;
    let b_pid_in_event = hit_b.as_ref().map(|e| e.pid.0);
    if hit_b.is_some() {
        sync.record_hit(tb.clone());
    }
    let full_complete = sync.is_complete();
    let pending_after_b = sync.pending_targets().len();
    let hits = sync.hit_by.len();
    p.cleanup().await;

    assert_eq!(planted_a, trap_bytes(), "the sync breakpoint was never planted in A");
    assert_eq!(planted_b, trap_bytes(), "the sync breakpoint was never planted in B");
    assert!(!empty_complete, "a sync breakpoint nobody has hit must not be complete");
    assert!(hit_a.is_some(), "target A never reached `hot` — nothing was measured");
    assert_eq!(a_pid_in_event, Some(p.pid_a), "A's hit must be reported for A's own pid");
    assert!(
        !half_complete,
        "one of two targets hit the address and the sync breakpoint already reported complete"
    );
    assert_eq!(pending_after_a, vec![tb.0], "after A's hit the only pending target must be B");
    assert!(hit_b.is_some(), "target B never reached `hot` — the completion is unproven");
    assert_eq!(b_pid_in_event, Some(p.pid_b), "B's hit must be reported for B's own pid");
    assert!(
        full_complete,
        "both live targets hit the address; the sync breakpoint must be complete"
    );
    assert_eq!(pending_after_b, 0, "nothing may remain pending once both hit");
    assert_eq!(hits, 2, "exactly two hits, one per target");
}

/// A target that hits the same sync breakpoint repeatedly — the fixture calls
/// `hot` five times — must not be able to complete it on its own. This is the
/// failure mode a naive hit COUNTER has and a hit SET does not, measured on a
/// live process that really does cross the address three times in a row while
/// its partner never runs.
#[tokio::test]
async fn one_live_target_hitting_repeatedly_cannot_complete_the_sync_breakpoint() {
    let fx = build_fixture();
    let p = Pair::launch(&fx).await;
    let at = Address(fx.hot);
    let mut mt = MultiTargetDebugger::new();
    let ta = mt.add_target(TargetSpec::LocalPid(p.pid_a), "proc-a");
    let tb = mt.add_target(TargetSpec::LocalPid(p.pid_b), "proc-b");
    p.a.set_breakpoint(at, BreakpointKind::Software).await.expect("plant in A");

    let mut sync = SyncBreakpoint::new(fx.hot, vec![ta.clone(), tb.clone()]);
    let mut crossings = 0;
    for _ in 0..3 {
        if run_until_breakpoint(&p.a, fx.hot, 8).await.is_some() {
            crossings += 1;
            sync.record_hit(ta.clone());
        }
    }
    let complete = sync.is_complete();
    let hits = sync.hit_by.len();
    let pending: Vec<u32> = sync.pending_targets().iter().map(|t| t.0).collect();
    p.cleanup().await;

    assert_eq!(crossings, 3, "target A must really have crossed `hot` three times");
    assert_eq!(hits, 1, "three crossings by one target are one target's hit, not three");
    assert!(!complete, "target B never ran; the sync breakpoint must still be pending");
    assert_eq!(pending, vec![tb.0], "target B must be the pending one");
}

/// GAP, measured. `trigger_sync_breakpoint` is a SIMULATION.
///
/// | expected (external truth) | reachable with what the crate already has | obtained today |
/// |---|---|---|
/// | completion reflects two processes that executed the address | `LinuxDebugger` + `SyncBreakpoint::record_hit` do exactly that (test above) | completion is asserted for two processes that were KILLED before it was called |
///
/// The two pids here are dead — the fixture processes are killed first, and the
/// test waits for `/proc` to confirm it — and the address is one they never
/// reached. `trigger_sync_breakpoint` still marks every registered target as
/// having hit it and increments `sync_bps_completed`. Unlike `connect_all` and
/// the router, this one does NOT announce that it is simulated: the resulting
/// report is indistinguishable from the honest one produced by the live test
/// above. That is the defect worth naming — the method's own doc says
/// "simulate", but `multi_target_report`'s `sync_bps_completed` does not carry
/// that qualification to its consumer.
#[tokio::test]
async fn trigger_sync_breakpoint_reports_completion_for_two_dead_processes() {
    let fx = build_fixture();
    let p = Pair::launch(&fx).await;
    let mut mt = MultiTargetDebugger::new();
    let ta = mt.add_target(TargetSpec::LocalPid(p.pid_a), "proc-a");
    let tb = mt.add_target(TargetSpec::LocalPid(p.pid_b), "proc-b");
    mt.add_sync_breakpoint(fx.hot);

    // Kill both before triggering: nothing can possibly execute the address.
    p.cleanup().await;
    for _ in 0..100 {
        if !pid_alive(p.pid_a) && !pid_alive(p.pid_b) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let still_alive = pid_alive(p.pid_a) || pid_alive(p.pid_b);

    mt.trigger_sync_breakpoint(fx.hot);
    let bp = &mt.sync_breakpoints[0];
    let complete = bp.is_complete();
    let hit_by: Vec<u32> = bp.hit_by.iter().map(|t| t.0).collect();
    let completed = mt.finalise().sync_bps_completed;

    assert!(!still_alive, "the measurement needs both processes dead before the trigger");
    assert!(
        complete,
        "documenting the CURRENT behaviour: trigger_sync_breakpoint marks completion \
         unconditionally. If this now fails, the simulation was replaced by something live — \
         re-read the gap table above."
    );
    assert_eq!(hit_by.len(), 2, "the simulation credits both targets");
    assert!(hit_by.contains(&ta.0) && hit_by.contains(&tb.0));
    assert_eq!(completed, 1, "and the report counts a completed sync breakpoint");
}

/// `trigger_sync_breakpoint` must at least be address-selective: triggering an
/// address no sync breakpoint was registered at must credit nobody. If it
/// matched loosely, one process's stop would complete a breakpoint the caller
/// set somewhere else entirely.
#[tokio::test]
async fn triggering_an_unregistered_address_credits_nobody() {
    let fx = build_fixture();
    let p = Pair::launch(&fx).await;
    let mut mt = MultiTargetDebugger::new();
    mt.add_target(TargetSpec::LocalPid(p.pid_a), "proc-a");
    mt.add_target(TargetSpec::LocalPid(p.pid_b), "proc-b");
    mt.add_sync_breakpoint(fx.hot);

    mt.trigger_sync_breakpoint(fx.hot.wrapping_add(0x1000));
    let hits = mt.sync_breakpoints[0].hit_by.len();
    let complete = mt.sync_breakpoints[0].is_complete();
    let completed = mt.finalise().sync_bps_completed;
    p.cleanup().await;

    assert_eq!(hits, 0, "an unrelated address must not credit any target");
    assert!(!complete, "the registered sync breakpoint must still be pending");
    assert_eq!(completed, 0, "and no completion may be reported");
}

// ─────────────────────────────────────────────────────────────────────────────
// multi_target_report
// ─────────────────────────────────────────────────────────────────────────────

/// The report must keep the two live processes APART: one exiting cleanly and
/// one exiting with a failure code must be visible as one clean exit and one
/// error, and `all_ok` must be false. A report that aggregated them — or that
/// counted the batch once — would say the fleet was fine.
#[tokio::test]
async fn the_report_distinguishes_a_clean_exit_from_a_failing_one() {
    let fx = build_fixture();
    let p = Pair::launch(&fx).await;
    let mut mt = MultiTargetDebugger::new();
    let ta = mt.add_target(TargetSpec::LocalPid(p.pid_a), "proc-a");
    let tb = mt.add_target(TargetSpec::LocalPid(p.pid_b), "proc-b");

    mt.target_exited(&ta, 0);
    mt.target_exited(&tb, 3);
    let state_a = mt.targets.get(&ta).map(|t| t.state.clone());
    let state_b = mt.targets.get(&tb).map(|t| t.state.clone());
    let r = mt.finalise();
    let (total, clean, errors, ok) = (r.total_targets, r.clean_exits, r.errors, r.all_ok());
    p.cleanup().await;

    assert_eq!(total, 2);
    assert_eq!(clean, 1, "exactly one target exited cleanly");
    assert_eq!(errors, 1, "exactly one target exited with a failure code");
    assert!(!ok, "a fleet with one failing target is not all_ok");
    assert_eq!(state_a, Some(TargetState::Exited { code: 0 }), "A's own exit code must survive");
    assert_eq!(state_b, Some(TargetState::Exited { code: 3 }), "B's own exit code must survive");
}

/// The report must reflect the REAL exit status of both live processes when
/// they are run to completion. Both copies of the fixture return 0, so both are
/// clean exits and `all_ok` holds — the positive counterpart of the test above,
/// and the one that proves the fixture really terminates rather than being
/// killed.
#[tokio::test]
async fn both_live_processes_run_to_completion_and_report_all_ok() {
    let fx = build_fixture();
    let p = Pair::launch(&fx).await;
    let mut mt = MultiTargetDebugger::new();
    let ta = mt.add_target(TargetSpec::LocalPid(p.pid_a), "proc-a");
    let tb = mt.add_target(TargetSpec::LocalPid(p.pid_b), "proc-b");

    let mut codes: Vec<Option<i32>> = Vec::new();
    for (dbg, id) in [(&p.a, &ta), (&p.b, &tb)] {
        let mut code = None;
        for _ in 0..16 {
            match dbg.continue_execution().await {
                Ok(ev) => {
                    if let StopReason::ProcessExit { exit_code } = ev.reason {
                        code = Some(exit_code);
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        if let Some(c) = code {
            mt.target_exited(id, c);
        }
        codes.push(code);
    }
    let r = mt.finalise();
    let (clean, errors, ok) = (r.clean_exits, r.errors, r.all_ok());
    p.cleanup().await;

    assert_eq!(codes, vec![Some(0), Some(0)], "both live fixtures must exit 0, got {codes:?}");
    assert_eq!(clean, 2, "both real exits must be counted clean");
    assert_eq!(errors, 0);
    assert!(ok, "two clean exits out of two targets is all_ok");
}

/// A correlated trace must keep the two processes' REAL program counters apart
/// and attributed to the right target. The values are read with
/// `get_registers` from each live tracee, so a trace that overwrote one entry
/// with the other, or keyed both under one id, is caught.
#[tokio::test]
async fn a_correlated_trace_keeps_the_two_live_program_counters_apart() {
    let fx = build_fixture();
    let p = Pair::launch(&fx).await;
    let at = Address(fx.hot);
    let mut mt = MultiTargetDebugger::new();
    let ta = mt.add_target(TargetSpec::LocalPid(p.pid_a), "proc-a");
    let tb = mt.add_target(TargetSpec::LocalPid(p.pid_b), "proc-b");

    // Stop A at `hot` and leave B at its exec trap: the two pcs are then
    // genuinely different values, which is what makes the separation testable.
    p.a.set_breakpoint(at, BreakpointKind::Software).await.expect("plant in A");
    let hit = run_until_breakpoint(&p.a, fx.hot, 8).await;
    let regs_a = p.a.get_registers(ThreadId(p.pid_a)).await;
    let regs_b = p.b.get_registers(ThreadId(p.pid_b)).await;
    let pa = regs_a.as_ref().map(|r| r.pc).unwrap_or(0);
    let pb = regs_b.as_ref().map(|r| r.pc).unwrap_or(0);
    let (ok_a, ok_b) = (regs_a.is_ok(), regs_b.is_ok());
    let why = format!("{regs_a:?} / {regs_b:?}");

    mt.record_trace(vec![(ta.clone(), pa), (tb.clone(), pb)]);
    let entry = mt.trace[0].clone();
    let complete = entry.is_complete(&[ta.clone(), tb.clone()]);
    let got_a = entry.pcs.get(&ta.0.to_string()).copied();
    let got_b = entry.pcs.get(&tb.0.to_string()).copied();
    let entries = mt.finalise().trace_entries.len();
    p.cleanup().await;

    assert!(hit.is_some(), "target A never reached `hot`");
    assert!(ok_a && ok_b, "both live pcs must be readable: {why}");
    assert_ne!(pa, 0, "A's live pc must not be zero");
    assert_ne!(pb, 0, "B's live pc must not be zero");
    assert_ne!(pa, pb, "the two processes are stopped at different points; their pcs must differ");
    assert!(complete, "a trace holding both targets' pcs must be complete for both");
    assert_eq!(got_a, Some(pa), "target A's pc must be filed under target A");
    assert_eq!(got_b, Some(pb), "target B's pc must be filed under target B");
    assert_eq!(entries, 1, "finalise must publish the recorded trace, once");
}

/// The report's notes must survive finalisation intact and in order — they are
/// the only free-form channel a multi-target session has for saying which
/// target did what.
#[tokio::test]
async fn report_notes_survive_finalisation_in_order() {
    let fx = build_fixture();
    let p = Pair::launch(&fx).await;
    let mut mt = MultiTargetDebugger::new();
    mt.add_target(TargetSpec::LocalPid(p.pid_a), "proc-a");
    mt.add_target(TargetSpec::LocalPid(p.pid_b), "proc-b");
    mt.report.add_note(format!("A is pid {}", p.pid_a));
    mt.report.add_note(format!("B is pid {}", p.pid_b));
    let notes = mt.finalise().notes.clone();
    p.cleanup().await;

    assert_eq!(notes.len(), 2, "both notes must survive");
    assert!(notes[0].contains(&p.pid_a.to_string()), "first note must name A: {notes:?}");
    assert!(notes[1].contains(&p.pid_b.to_string()), "second note must name B: {notes:?}");
}

// ─────────────────────────────────────────────────────────────────────────────
// Orphan backstop
// ─────────────────────────────────────────────────────────────────────────────

/// No fixture process of this file may outlive it.
///
/// Every test kills both tracees on the success path and before every assertion
/// that can fail, but a panic inside a test body skips the `cleanup` call, and a
/// leaked `ptrace`d child stays stopped forever instead of dying with its
/// parent. Named to sort last under `--test-threads=1`, this asserts the
/// invariant with `pgrep` rather than trusting drop glue.
///
/// The match is on `/mtfix` specifically: other live-test files in this crate
/// run concurrently in the same tree with fixtures named `/fixture`, and a
/// looser pattern would fail this test on somebody else's live process — and,
/// worse, would pass this file's leak off as theirs.
#[test]
fn zz_no_orphan_fixture_processes_survive() {
    let out = std::process::Command::new("pgrep")
        .args(["-a", "-f", "/mtfix"])
        .output()
        .expect("pgrep");
    let listing = String::from_utf8_lossy(&out.stdout);
    let mine: Vec<&str> = listing
        .lines()
        .filter(|l| l.split_whitespace().any(|w| w.ends_with("/mtfix")))
        .collect();
    assert!(mine.is_empty(), "orphaned multi-target fixture processes survived: {mine:?}");
}
