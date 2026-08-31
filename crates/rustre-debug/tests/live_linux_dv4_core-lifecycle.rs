//! dv4 / `core-lifecycle`: the assertions `live_linux_core.rs` and
//! `live_linux_lifecycle.rs` were measured NOT to make.
//!
//! Each test here exists because a coherent mutation left the original file
//! green. The mutation that must kill each test is named in its doc comment,
//! so the claim "this bites" is falsifiable by re-running that mutation rather
//! than by reading the assertion.
//!
//! Four gaps are closed:
//!
//! 1. **No oracle pins a POSITION.** Shifting every symbol address the core
//!    file uses by +8 -- coherently, all four oracles at once -- left all 11
//!    tests green. The symbols `crash_a`/`crash_b`/`crash_c`/`main` span 0x9c
//!    bytes in total while every containment check uses a blanket `+0x200`
//!    window, so the four `covers()` calls in
//!    `the_backtrace_at_the_fault_reaches_main_through_the_crash_chain` are one
//!    assertion written four times. Measured: a backtrace reduced to a SINGLE
//!    frame inside `main` passes that test. Closed here by
//!    `the_crash_backtrace_is_an_ordered_quadruple_of_distinct_functions` and
//!    by `the_entry_of_hot_is_distinguished_from_its_prologue_by_the_stack`,
//!    which uses the method the position gap actually needs: at a function's
//!    ENTRY `[rsp]` is a return address inside ANOTHER symbol, and eight bytes
//!    later (past `endbr64; push %rbp; mov %rsp,%rbp`) it is a stack address.
//! 2. **The unwinder is its own witness.** Nothing checked that a reported
//!    frame pc is actually written in the target's memory.
//!    `every_outer_frame_pc_is_a_word_present_in_the_crashed_stack` reads the
//!    bytes and looks for them.
//! 3. **Loose oracles.** `<= 9` refused registers, and `Ok(empty) or Err` for
//!    `memory_maps` on a corpse, are pinned to the exact set / the exact arm.
//! 4. **Session identity.** `launch` was only asked for a live pid, never for
//!    the pid of the image we asked to run; and events from an earlier session
//!    arrive stamped with the current target's pid (measured red, `#[ignore]`).
#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::path::PathBuf;

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::{
    BreakpointKind, DebugError, DebugEvent, Debugger, LaunchOptions, OutputRedirect, StopReason,
    ThreadId,
};

/// The crash fixture: same shape as `live_linux_core.rs`'s, kept independent so
/// this file measures the backend and not that file.
const CRASH_C: &str = r#"
volatile int sink;
__attribute__((noinline)) void crash_a(char *m) { sink = *(volatile int *)0; (void)m; }
__attribute__((noinline)) void crash_b(char *m) { crash_a(m); }
__attribute__((noinline)) void crash_c(char *m) { crash_b(m); }
int main(void) { volatile char pad[64]; crash_c((char *)pad); return 0; }
"#;

/// The lifecycle fixture. `hot` is called from `main`, which is what makes the
/// entry/prologue discrimination possible: the return address on the stack at
/// `hot`'s entry belongs to a DIFFERENT symbol.
const HOT_C: &str = r#"
#include <unistd.h>
__attribute__((noinline)) int hot(int x) { return x + 1; }
int main(void) { volatile int s = 0; for (int i = 0; i < 5; i++) { s = hot(s); } usleep(300000); return 0; }
"#;

/// A symbol's EXACT extent, from `nm -S`. The blanket `+0x200` window used by
/// the files under test is wider than the whole set of fixture functions, which
/// is precisely why it cannot tell them apart.
#[derive(Clone, Copy, Debug)]
struct Sym {
    start: u64,
    size: u64,
}

impl Sym {
    fn contains(self, pc: u64) -> bool {
        pc >= self.start && pc < self.start + self.size
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    dir: PathBuf,
    exe: String,
    syms: HashMap<String, Sym>,
}

impl Fixture {
    fn sym(&self, n: &str) -> Sym {
        *self.syms.get(n).unwrap_or_else(|| panic!("fixture must export `{n}` with a size"))
    }

    /// Which of the named symbols contains `pc`, if any. A NAME, not a bool:
    /// an ordered list of names is the tuple a single wrong assignment cannot
    /// reproduce, while a count of "frames that matched something" can.
    fn name_of(&self, pc: u64, names: &[&'static str]) -> Option<&'static str> {
        names.iter().copied().find(|n| self.sym(n).contains(pc))
    }
}

/// Build with a stem unique to this file: the tree is shared with other agents
/// running their own `fixture` binaries, so `pgrep` hygiene and `/proc/<pid>/exe`
/// comparisons both need a name only this file uses.
fn build(source: &str) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("dv4cl.c");
    let exe = dir.path().join("dv4cl_fixture");
    std::fs::write(&src, source).expect("write source");
    let out = std::process::Command::new("cc")
        .args(["-no-pie", "-O0", "-g"])
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .output()
        .expect("cc must be available");
    assert!(out.status.success(), "cc failed: {}", String::from_utf8_lossy(&out.stderr));

    // `nm -S` prints "<addr> <size> <kind> <name>"; symbols without a size
    // print three fields and are skipped, which is what we want -- a symbol with
    // no size cannot bound anything.
    let nm = std::process::Command::new("nm")
        .arg("-S")
        .arg(&exe)
        .output()
        .expect("nm must be available: it is the external ground truth here");
    let mut syms = HashMap::new();
    for line in String::from_utf8_lossy(&nm.stdout).lines() {
        let p: Vec<&str> = line.split_whitespace().collect();
        if p.len() != 4 || !(p[2] == "T" || p[2] == "t") {
            continue;
        }
        let (Ok(start), Ok(size)) = (u64::from_str_radix(p[0], 16), u64::from_str_radix(p[1], 16))
        else {
            continue;
        };
        syms.insert(p[3].to_string(), Sym { start, size });
    }
    Fixture {
        dir: dir.path().to_path_buf(),
        exe: exe.to_string_lossy().to_string(),
        syms,
        _dir: dir,
    }
}

fn opts(fx: &Fixture) -> LaunchOptions {
    LaunchOptions {
        executable: fx.exe.clone(),
        args: vec![],
        env: HashMap::new(),
        working_dir: Some(fx.dir.to_string_lossy().to_string()),
        stop_at_entry: false,
        follow_forks: false,
        redirect: OutputRedirect::default(),
    }
}

/// Resume until a stop that belongs to OUR session and is not loader/thread
/// housekeeping.
///
/// Filtering on `ev.pid` alone -- which is what `live_linux_core.rs` does, with
/// a comment explaining why -- is NOT enough on this backend: see
/// `an_exit_of_a_foreign_process_is_stamped_with_the_current_targets_pid`. A
/// `ThreadExit` naming a tid that never belonged to this session is therefore
/// dropped here too, by tid.
async fn run_until_interesting(dbg: &LinuxDebugger, mine: u32, budget: usize) -> DebugEvent {
    for _ in 0..budget {
        let ev = dbg.continue_execution().await.expect("continue_execution");
        if ev.pid.0 != mine {
            continue;
        }
        match &ev.reason {
            StopReason::LibraryLoad { .. }
            | StopReason::LibraryUnload { .. }
            | StopReason::ThreadCreate { .. } => {}
            StopReason::ThreadExit { tid, .. } if tid.0 != mine => {}
            _ => return ev,
        }
    }
    panic!("the tracee never reached an interesting stop within the budget");
}

fn u64_at(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("8 bytes"))
}

// ---------------------------------------------------------------------------
// 1. Position, not merely function
// ---------------------------------------------------------------------------

/// A breakpoint stop at the ENTRY of `hot` is distinguished from a stop eight
/// bytes later, by evidence that is EXTERNAL to the address itself.
///
/// This is the hole the `+8` mutation exposed: `run_to(X)` plants a trap at `X`
/// and then asserts the stop is at `X`, which is true for every `X`. The
/// discriminator used here is the stack, not the pc:
///
/// * at `hot` (before the prologue) `[rsp]` is the RETURN ADDRESS, and it lies
///   inside `main` -- a different symbol, whose extent comes from `nm -S`;
/// * eight bytes later, past `endbr64; push %rbp; mov %rsp,%rbp` (measured with
///   `objdump -d`: `hot+0=endbr64`, `hot+4=push %rbp`, `hot+5=mov`,
///   `hot+8=mov %edi,-4(%rbp)`), `[rsp]` is the SAVED RBP -- a stack address,
///   inside the `[stack]` mapping and outside every function.
///
/// So the two positions are told apart by what the process itself holds, and a
/// backend that stopped at the wrong one cannot pass by coincidence.
///
/// Measured green: `rip=0x401136 [rsp]=0x40116f (main=0x401149+0x44)`, then
/// after three steps `rip=0x40113e [rsp]=0x7ffe1b1d6200`.
///
/// **Falsified by**: planting the breakpoint at `hot + 8` instead of `hot`.
#[tokio::test]
async fn the_entry_of_hot_is_distinguished_from_its_prologue_by_the_stack() {
    let fx = build(HOT_C);
    let hot = fx.sym("hot");
    let main = fx.sym("main");
    assert!(hot.size >= 8, "the prologue discrimination needs at least 8 bytes of `hot`");

    let dbg = LinuxDebugger::new();
    let pid = dbg.launch(opts(&fx)).await.expect("launch");
    dbg.set_breakpoint(Address(hot.start), BreakpointKind::Software).await.expect("plant");
    let ev = run_until_interesting(&dbg, pid.0, 16).await;
    assert!(
        matches!(ev.reason, StopReason::Breakpoint { .. }),
        "expected the breakpoint at hot, got {:?}",
        ev.reason
    );
    let tid = ev.tid;

    let rip = dbg.get_register(tid, "rip").await.expect("rip");
    let rsp = dbg.get_register(tid, "rsp").await.expect("rsp");
    let at_entry = u64_at(&dbg.read_memory(Address(rsp), 8).await.expect("[rsp] at entry"));
    let maps = dbg.memory_maps().await.expect("memory_maps");
    let stack = maps
        .iter()
        .find(|m| m.name.as_deref() == Some("[stack]"))
        .expect("a [stack] mapping")
        .clone();
    let in_stack = |a: u64| a >= stack.base.as_u64() && a < stack.base.as_u64() + stack.size;

    println!(
        "at hot entry: rip={rip:#x} rsp={rsp:#x} [rsp]={at_entry:#x} (main={:#x}+{:#x})",
        main.start, main.size
    );
    assert_eq!(rip, hot.start, "the stop must be AT the entry, not near it");
    assert!(
        main.contains(at_entry),
        "at the ENTRY of hot, [rsp] must be the return address inside main \
         ({:#x}..{:#x}); got {at_entry:#x}",
        main.start,
        main.start + main.size
    );
    assert!(!in_stack(at_entry), "a return address must not be a stack address");

    // Step past the prologue: endbr64, push %rbp, mov %rsp,%rbp.
    for _ in 0..3 {
        dbg.single_step(tid).await.expect("single_step through the prologue");
    }
    let rip2 = dbg.get_register(tid, "rip").await.expect("rip after prologue");
    let rsp2 = dbg.get_register(tid, "rsp").await.expect("rsp after prologue");
    let after = u64_at(&dbg.read_memory(Address(rsp2), 8).await.expect("[rsp] after prologue"));
    println!("after prologue: rip={rip2:#x} rsp={rsp2:#x} [rsp]={after:#x}");
    let _ = dbg.kill().await;

    assert_eq!(
        rip2,
        hot.start + 8,
        "three steps from the entry must land on hot+8 (endbr64/push/mov)"
    );
    assert!(
        !main.contains(after),
        "eight bytes in, [rsp] is the SAVED RBP and must NOT look like a return address \
         into main; got {after:#x} -- if this passes the two positions are indistinguishable"
    );
    assert!(
        in_stack(after),
        "the saved rbp must be a stack address inside [stack] ({:#x}..{:#x}); got {after:#x}",
        stack.base.as_u64(),
        stack.base.as_u64() + stack.size
    );
    assert_ne!(rsp, rsp2, "the prologue pushed rbp, so rsp must have moved");
}

/// The crash backtrace must be an ORDERED QUADRUPLE of DISTINCT functions:
/// frame 0 in `crash_a`, then `crash_b`, `crash_c`, `main`, each bounded by its
/// own `nm -S` size.
///
/// The file under test asserts "some frame is within 0x200 of each of the four
/// symbols". The four symbols occupy 0x9c bytes in total, so a single frame in
/// `main` satisfies all four -- measured: truncating the frame list to that one
/// frame leaves `the_backtrace_at_the_fault_reaches_main_through_the_crash_chain`
/// green. A tuple of names in order is what a single wrong assignment cannot
/// reproduce.
///
/// Measured green: `[0x401147, 0x40116e, 0x40118d, 0x4011b7, ...]` classified
/// `[crash_a, crash_b, crash_c, main]`.
///
/// **Falsified by**: the same truncation (`frames.retain(pc in main)`), by
/// reversing the expected order, and by widening the ranges back to `+0x200`.
#[tokio::test]
async fn the_crash_backtrace_is_an_ordered_quadruple_of_distinct_functions() {
    const CHAIN: [&str; 4] = ["crash_a", "crash_b", "crash_c", "main"];
    let fx = build(CRASH_C);
    // The premise of the whole measurement: the four functions are packed far
    // closer together than the 0x200 window the file under test uses.
    let span = fx.sym("main").start + fx.sym("main").size - fx.sym("crash_a").start;
    println!("crash_a..main spans {span:#x} bytes; the file under test uses a 0x200 window");
    assert!(span < 0x200, "premise: the chain must fit inside one 0x200 window ({span:#x})");

    let dbg = LinuxDebugger::new();
    let pid = dbg.launch(opts(&fx)).await.expect("launch");
    let ev = run_until_interesting(&dbg, pid.0, 32).await;
    let StopReason::Signal { signum, .. } = ev.reason else {
        let _ = dbg.kill().await;
        panic!("expected a SIGSEGV stop, got {:?}", ev.reason);
    };
    let frames = dbg.backtrace(ev.tid).await.expect("backtrace at the fault");
    let _ = dbg.kill().await;

    assert_eq!(signum, libc::SIGSEGV, "the fixture must fault");
    let named: Vec<Option<&str>> =
        frames.iter().map(|f| fx.name_of(f.pc.as_u64(), &CHAIN)).collect();
    println!(
        "frames: {:#x?}\nclassified: {named:?}",
        frames.iter().map(|f| f.pc.as_u64()).collect::<Vec<_>>()
    );
    let chain: Vec<&str> = named.iter().flatten().copied().collect();
    assert_eq!(
        chain,
        CHAIN.to_vec(),
        "the unwind must produce crash_a, crash_b, crash_c, main -- each frame in a \
         DIFFERENT function bounded by its own nm size; got {chain:?}"
    );
    for (i, want) in CHAIN.iter().enumerate() {
        let f = &frames[i];
        assert_eq!(f.index, i, "frame {i} must carry index {i}");
        assert!(
            fx.sym(want).contains(f.pc.as_u64()),
            "frame {i} must be in {want} ({:#x}+{:#x}), got {:#x}",
            fx.sym(want).start,
            fx.sym(want).size,
            f.pc.as_u64()
        );
    }
}

/// Every OUTER frame's pc must be a 64-bit word actually present in the bytes
/// of the crashed stack.
///
/// The files under test take the unwinder's word for the frame list; the only
/// cross-check they make is against `nm`, which the unwinder could satisfy by
/// scanning the same symbol table. Here the ground truth is the target's own
/// memory: a return address is on the stack because the `call` put it there, so
/// if the unwinder invented or mis-adjusted a frame the word will not be found.
///
/// Frame 0 is excluded on purpose -- its pc is `rip`, which is not a stack word.
///
/// **Falsified by**: adding 1 to each outer frame's pc before the search (the
/// exact off-by-one a return-address adjustment bug produces), and by searching
/// a window that does not cover the frame's own `sp`.
#[tokio::test]
async fn every_outer_frame_pc_is_a_word_present_in_the_crashed_stack() {
    let fx = build(CRASH_C);
    let dbg = LinuxDebugger::new();
    let pid = dbg.launch(opts(&fx)).await.expect("launch");
    let ev = run_until_interesting(&dbg, pid.0, 32).await;
    assert!(
        matches!(ev.reason, StopReason::Signal { .. }),
        "expected the fault, got {:?}",
        ev.reason
    );
    let frames = dbg.backtrace(ev.tid).await.expect("backtrace");
    let rsp = dbg.get_register(ev.tid, "rsp").await.expect("rsp");
    let maps = dbg.memory_maps().await.expect("maps");
    let stack =
        maps.iter().find(|m| m.name.as_deref() == Some("[stack]")).expect("[stack]").clone();
    let top = stack.base.as_u64() + stack.size;
    let len = usize::try_from(top.saturating_sub(rsp)).expect("window fits");
    let bytes = dbg.read_memory(Address(rsp), len).await.expect("read the live stack");
    let _ = dbg.kill().await;

    assert!(frames.len() >= 2, "need at least one outer frame, got {}", frames.len());
    let words: Vec<u64> = bytes.chunks_exact(8).map(u64_at).collect();
    println!("stack window {rsp:#x}..{top:#x} = {} words", words.len());
    for f in frames.iter().skip(1) {
        let pc = f.pc.as_u64();
        assert!(
            words.contains(&pc),
            "frame {} pc {pc:#x} is NOT any 8-byte word of the {}-byte stack the process \
             actually holds -- the unwinder is the only witness for it",
            f.index,
            bytes.len()
        );
        assert!(
            f.sp.as_u64() >= rsp && f.sp.as_u64() <= top,
            "frame {} sp {:#x} must be inside the live stack {rsp:#x}..{top:#x}",
            f.index,
            f.sp.as_u64()
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Loose oracles, pinned
// ---------------------------------------------------------------------------

/// The set of `NT_PRSTATUS` slots the backend REFUSES is exactly these nine --
/// as a SET OF NAMES, not as a count.
///
/// `live_linux_core.rs` asserts `unavailable.len() <= 9`. That passes if the
/// backend starts refusing `rip` and gains `gs` in exchange, which is a
/// catastrophe scored as a tie; and it passes silently if the refusals drop to
/// zero, which is the fix nobody would be told about. Both directions are
/// pinned here.
///
/// Measured on 2026-08-31: `["cs", "ds", "es", "fs", "fs_base", "gs",
/// "gs_base", "orig_rax", "ss"]`. All nine are fields of the SAME
/// `user_regs_struct` the backend already reads, so this is a naming table that
/// stops short, not missing data.
///
/// **Falsified by**: removing any one name from `EXPECTED_REFUSED`, and by
/// adding one.
#[tokio::test]
async fn the_prstatus_refusal_set_is_exactly_nine_named_slots() {
    const PRSTATUS_GREGS: [&str; 27] = [
        "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx",
        "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds",
        "es", "fs", "gs",
    ];
    const EXPECTED_REFUSED: [&str; 9] =
        ["cs", "ds", "es", "fs", "fs_base", "gs", "gs_base", "orig_rax", "ss"];

    let fx = build(CRASH_C);
    let dbg = LinuxDebugger::new();
    let pid = dbg.launch(opts(&fx)).await.expect("launch");
    let ev = run_until_interesting(&dbg, pid.0, 32).await;
    assert!(
        matches!(ev.reason, StopReason::Signal { .. }),
        "expected the fault, got {:?}",
        ev.reason
    );
    let mut refused: Vec<&str> = Vec::new();
    for name in PRSTATUS_GREGS {
        if dbg.get_register(ev.tid, name).await.is_err() {
            refused.push(name);
        }
    }
    let _ = dbg.kill().await;
    refused.sort_unstable();
    println!("REFUSED set: {refused:?}");
    assert_eq!(
        refused,
        EXPECTED_REFUSED.to_vec(),
        "the refusal set changed. If it SHRANK the naming table in `to_register_set` was \
         extended and this expectation must shrink with it; if it GREW a slot a core file \
         needs was lost"
    );
}

/// On a corpse, `memory_maps` REFUSES; it does not return an empty list.
///
/// `live_linux_core.rs` accepts either (`maps.map_or(true, Vec::is_empty)`), so
/// a backend that silently degraded from `Err(NotAttached)` to `Ok(vec![])`
/// would not be noticed -- and the two are very different to a caller: one is an
/// error to handle, the other is "this process has no mappings", which is a
/// statement no live process can make. Measured today: `Err(NotAttached)`.
///
/// **Falsified by**: relaxing the assertion to accept `Ok(empty)` (it then
/// survives a backend that returns either), which is the point.
#[tokio::test]
async fn on_a_corpse_memory_maps_refuses_rather_than_answering_empty() {
    let fx = build(HOT_C);
    let dbg = LinuxDebugger::new();
    let pid = dbg.launch(opts(&fx)).await.expect("launch");
    dbg.kill().await.expect("kill");
    std::thread::sleep(std::time::Duration::from_millis(150));
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid.0));
    assert!(
        stat.as_ref().map_or(true, |s| s.rsplit(')').next().unwrap_or("").contains(" Z ")),
        "the premise: the process must be gone or a zombie, /proc says {stat:?}"
    );

    let maps = dbg.memory_maps().await;
    println!("memory_maps on a corpse -> {:?}", maps.as_ref().map(Vec::len));
    match maps {
        Err(e) => assert!(
            matches!(e, DebugError::NotAttached),
            "the refusal must be NotAttached, got {e:?}"
        ),
        Ok(v) => panic!(
            "memory_maps answered Ok({} entries) for a dead session; an empty map list is a \
             statement no process can truthfully make, and the caller cannot tell it from a \
             real answer",
            v.len()
        ),
    }
}

// ---------------------------------------------------------------------------
// 3. Session identity
// ---------------------------------------------------------------------------

/// `launch` must hand back the pid of THE FIXTURE -- not merely of some live
/// process.
///
/// `launch_reports_a_pid_that_is_a_live_process` reads `/proc/<pid>/stat` and
/// stops there, so a backend that returned the pid of its own helper, of the
/// shell, or of a recycled neighbour would pass. `/proc/<pid>/exe` is a kernel
/// link to the executed image, and comparing it to the path we asked to launch
/// is a triple (pid, image, name) a single wrong assignment cannot reproduce.
/// The fixture stem is unique to this file, so a concurrent agent's `fixture`
/// cannot satisfy it either.
///
/// **Falsified by**: comparing against a different fixture's path, and by
/// asserting only that the pid is alive (which is the status quo).
#[tokio::test]
async fn launch_reports_the_pid_of_the_fixture_not_merely_of_a_live_process() {
    let fx = build(HOT_C);
    let dbg = LinuxDebugger::new();
    let pid = dbg.launch(opts(&fx)).await.expect("launch");

    let exe_link = std::fs::read_link(format!("/proc/{}/exe", pid.0))
        .expect("/proc/<pid>/exe must resolve for a live tracee");
    let want = std::fs::canonicalize(&fx.exe).expect("canonicalize the fixture path");
    println!("/proc/{}/exe -> {exe_link:?}; asked for {want:?}", pid.0);
    let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid.0)).unwrap_or_default();
    let _ = dbg.kill().await;

    assert_eq!(exe_link, want, "the pid launch returned must be running the image we asked for");
    assert_eq!(comm.trim(), "dv4cl_fixture", "and /proc/<pid>/comm must name it too");
}

/// `current_thread` is retired by BOTH teardown paths.
///
/// `live_linux_lifecycle.rs::current_thread_does_not_outlive_the_session` is
/// still marked `#[ignore]` as a measured backend defect, but on 2026-08-31 it
/// PASSES when run with `--ignored`: the defect has been fixed and the
/// `#[ignore]` is now hiding a green assertion, so the file has lost the
/// coverage the attribute was documenting. That test also only covers `kill()`;
/// its doc comment blames `kill()` AND `detach()`, so `detach()` is asserted
/// here too. Measured: `Err(NotAttached)` after both.
///
/// **Falsified by**: reverting the backend fix (the assertion is the same one
/// the ignored test makes), and -- for the `detach` half -- by dropping the
/// second iteration of the loop.
#[tokio::test]
async fn current_thread_is_retired_by_kill_and_by_detach() {
    for teardown in ["kill", "detach"] {
        let fx = build(HOT_C);
        let dbg = LinuxDebugger::new();
        let pid = dbg.launch(opts(&fx)).await.expect("launch");
        assert_eq!(
            dbg.current_thread().await.expect("current_thread while live"),
            ThreadId(pid.0),
            "the live session must know its main thread"
        );

        if teardown == "kill" {
            dbg.kill().await.expect("kill");
        } else {
            dbg.detach().await.expect("detach");
        }

        let got = dbg.current_thread().await;
        println!("after {teardown}: current_thread -> {got:?}");
        match got {
            Err(e) => assert!(
                matches!(e, DebugError::NotAttached),
                "after {teardown} current_thread must say NotAttached, got {e:?}"
            ),
            Ok(tid) => panic!(
                "after {teardown} current_thread answered {tid:?}; is_attached()={} -- the \
                 instance contradicts itself, and this tid is the default of every register \
                 and stepping call",
                dbg.is_attached()
            ),
        }
        if teardown == "detach" {
            let _ =
                std::process::Command::new("kill").arg("-9").arg(pid.0.to_string()).status();
        }
    }
}

/// **MEASURED DEFECT -- an exit belonging to a process of an EARLIER session is
/// delivered stamped with the CURRENT target's pid.**
///
/// Ignored because it asserts the behaviour that should exist; today it is red.
/// The red, reproduced three runs out of three under `--test-threads=1`:
///
/// ```text
/// EVENT pid=29125 tid=29115 mine=29125 reason=ThreadExit { tid: ThreadId(29115), exit_code: -9 }
/// ```
///
/// `29125` is the pid `launch` had just returned for THIS session; `29115` is
/// the process of the PREVIOUS test, which had been detached from and then
/// `kill -9`'d. The backend reaps with `waitpid(-1)`, picks up the stray, and
/// labels the event with the pid of the target it currently holds instead of
/// the pid the wait actually reported.
///
/// | datum | expected (external truth) | obtained today |
/// |---|---|---|
/// | `ev.pid` for the death of 29115 | 29115 -- `waitpid` returned it | 29125, the live target |
/// | `ev.tid` | 29115 | 29115 (correct, which is how the mismatch is visible) |
/// | consequence | a pid filter separates the sessions | it does not; `ev.tid != ev.pid` is the only surviving clue |
///
/// This matters beyond tidiness: `live_linux_core.rs::run_until_interesting`
/// documents the pid filter as its defence against exactly this cross-talk, and
/// the defence is measured here to be ineffective -- it cost this file one
/// spurious red before `run_until_interesting` above was taught to filter by
/// tid as well. A single-threaded tracee can never legitimately report a
/// `ThreadExit` for a tid other than its own pid, which is what this asserts.
#[tokio::test]
async fn an_exit_of_a_foreign_process_is_stamped_with_the_current_targets_pid() {
    // Session 1: detach, then kill from outside, so its death is unreaped by
    // the debugger and waiting for it falls to whoever calls waitpid(-1) next.
    let fx = build(HOT_C);
    let first = LinuxDebugger::new();
    let stray = first.launch(opts(&fx)).await.expect("first launch");
    first.detach().await.expect("detach");
    let _ = std::process::Command::new("kill").arg("-9").arg(stray.0.to_string()).status();

    // Session 2, on a fresh instance: nothing it reports may name session 1.
    let dbg = LinuxDebugger::new();
    let mine = dbg.launch(opts(&fx)).await.expect("second launch").0;
    let mut seen: Vec<(u32, u32, String)> = Vec::new();
    for _ in 0..8 {
        let ev = dbg.continue_execution().await.expect("continue_execution");
        seen.push((ev.pid.0, ev.tid.0, format!("{:?}", ev.reason)));
        if matches!(ev.reason, StopReason::ProcessExit { .. }) {
            break;
        }
    }
    let _ = dbg.kill().await;
    println!("stray={} mine={mine}; events: {seen:#?}", stray.0);

    for (pid, tid, reason) in &seen {
        assert_ne!(
            *tid, stray.0,
            "session 2 reported an event about session 1's process {}: {reason}",
            stray.0
        );
        assert!(
            *pid != mine || *tid == mine,
            "an event stamped pid={mine} carried tid={tid}: a single-threaded tracee cannot \
             report a thread that is not itself -- {reason}"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Hygiene
// ---------------------------------------------------------------------------

/// No fixture of THIS file may outlive it.
///
/// The stem is `dv4cl_fixture`, unique to this file on purpose: the shared tree
/// runs several agents at once, and
/// `live_linux_core.rs::zz_no_orphan_fixture_processes_survive` matches any
/// path ending in `/fixture`, which made it fail twice in three runs on a
/// neighbour's live process (see the report). A hygiene test another agent can
/// turn red is not measuring hygiene.
#[test]
fn zz_no_orphan_dv4cl_fixture_survives() {
    let out = std::process::Command::new("pgrep")
        .args(["-a", "-f", "dv4cl_fixture"])
        .output()
        .expect("pgrep");
    let listing = String::from_utf8_lossy(&out.stdout);
    let mine: Vec<&str> = listing
        .lines()
        .filter(|l| l.split_whitespace().any(|w| w.ends_with("/dv4cl_fixture")))
        .collect();
    assert!(mine.is_empty(), "orphaned dv4cl_fixture processes survived: {mine:?}");
}
