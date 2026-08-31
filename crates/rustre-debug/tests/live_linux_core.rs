//! Live-process coverage for POST-MORTEM analysis on Linux: what this crate can
//! say about a program AFTER it has crashed.
//!
//! Every test drives a REAL process. A C fixture is compiled on the fly with
//! `cc -no-pie -O0 -g` (so the address `nm` prints is the address the function
//! occupies at run time), launched under `ptrace`, and made to die of a genuine
//! SIGSEGV three frames deep. Nothing here asserts on a structure built in
//! memory.
//!
//! The file is organised around one question the other `live_linux_*` files do
//! not ask: a crash report is usually read from a CORE FILE, minutes or days
//! after the process is gone. So it measures three things separately, and
//! refuses to conflate them:
//!
//! 1. **The ingredients.** While the tracee is still stopped at the fault, the
//!    backend can read the registers, walk the stack, list the mappings and
//!    read the crashed stack's bytes. Those are exactly the contents of a core
//!    file, and they are covered here as the prerequisites they are.
//! 2. **The corpse.** Once the SIGSEGV is forwarded and the process dies, the
//!    same calls must answer "gone", not answer with data from the session that
//!    ended. A stale answer is worse than an error.
//! 3. **The missing layer.** There is no ELF-core reader in the crate, and no
//!    API that takes a path to one. That is MEASURED here rather than supposed:
//!    the tests build a genuine `ET_CORE` file out of what the backend already
//!    reads live, prove it is a real core by handing it to `readelf`, and then
//!    show that nothing in the crate can read it back. The gap table lives in
//!    the doc comment of `an_elf_core_file_has_no_reader_in_this_crate`.
//!
//! ## Why the kernel does not write the core here
//!
//! `ulimit -c unlimited` is not sufficient on this host. Measured:
//! `/proc/sys/kernel/core_pattern` is `|/wsl-capture-crash %t %E %p %s`, a pipe
//! to a helper that does not exist on the filesystem, so the kernel hands the
//! core to a program it cannot execute and NOTHING lands on disk. The sysctl is
//! not writable without root and is not namespaced, so `unshare -r` does not
//! help either (`sysctl: permission denied on key "kernel.core_pattern"`).
//! `the_host_cannot_write_a_kernel_core_and_that_is_measured` records this as a
//! fact of the host rather than a property of the crate, and the synthesis path
//! exists so the rest of the file has a real core to work on regardless.
#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rustre_core::address::Address;
use rustre_debug::coredump_triage::{CrashDump, triage};
use rustre_debug::debug_session_manager::{DebugSessionManager, DebugTarget as SessionTarget};
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::{
    DebugEvent, Debugger, LaunchOptions, OutputRedirect, StackFrame, StopReason, ThreadId,
};

/// A string planted in `main`'s stack frame. It is ground truth from the
/// source: any byte range that claims to be the crashed stack must contain it.
const MAGIC: &str = "RUSTRE-CORE-MAGIC-4f21";

/// The fixture. It raises its own `RLIMIT_CORE` (so "would the kernel dump a
/// core" is answered by the kernel's policy rather than by an inherited limit
/// of zero), plants [`MAGIC`] in `main`'s frame, and dies of a NULL dereference
/// three calls deep so the backtrace has something to walk.
const FIXTURE_C: &str = r#"
#include <string.h>
#include <sys/resource.h>
volatile int sink;
__attribute__((noinline)) void crash_a(char *m) { sink = *(volatile int *)0; (void)m; }
__attribute__((noinline)) void crash_b(char *m) { crash_a(m); }
__attribute__((noinline)) void crash_c(char *m) { crash_b(m); }
int main(void) {
    struct rlimit rl;
    rl.rlim_cur = RLIM_INFINITY;
    rl.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &rl);
    volatile char magic[64];
    memset((void *)magic, 0, sizeof magic);
    memcpy((void *)magic, "RUSTRE-CORE-MAGIC-4f21", 22);
    crash_c((char *)magic);
    return 0;
}
"#;

struct Fixture {
    _dir: tempfile::TempDir,
    dir: PathBuf,
    exe: String,
    crash_a: u64,
    crash_b: u64,
    crash_c: u64,
    main: u64,
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
        .expect("cc must be available to run the live post-mortem tests");
    assert!(
        out.status.success(),
        "cc failed to build the fixture: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let nm = std::process::Command::new("nm").arg(&exe).output().expect("nm");
    let listing = String::from_utf8_lossy(&nm.stdout).to_string();
    let sym = |n: &str| {
        symbol_address(&listing, n).unwrap_or_else(|| panic!("fixture must export `{n}`"))
    };
    Fixture {
        dir: dir.path().to_path_buf(),
        exe: exe.to_string_lossy().to_string(),
        crash_a: sym("crash_a"),
        crash_b: sym("crash_b"),
        crash_c: sym("crash_c"),
        main: sym("main"),
        _dir: dir,
    }
}

fn symbol_address(nm_listing: &str, want: &str) -> Option<u64> {
    for line in nm_listing.lines() {
        let mut parts = line.split_whitespace();
        let Some(addr) = parts.next() else { continue };
        let Some(kind) = parts.next() else { continue };
        if parts.next().unwrap_or("") == want && (kind == "T" || kind == "t") {
            return u64::from_str_radix(addr, 16).ok();
        }
    }
    None
}

fn launch_opts(fx: &Fixture) -> LaunchOptions {
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

/// Resume until a stop that is neither a library event nor a thread birth, with
/// a hard budget so a misbehaving backend fails instead of hanging.
///
/// Events belonging to some OTHER process are skipped: the backend reaps with
/// `waitpid(-1)` and every test in this file shares one test binary, so a child
/// left behind by an earlier test can be handed to a later one's debugger.
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
            _ => return ev,
        }
    }
    panic!("the tracee never reached an interesting stop within the budget");
}

/// The state a post-mortem consumer needs, captured at the fault.
struct CrashState {
    tid: ThreadId,
    signum: i32,
    fault_addr: Option<u64>,
    regs: Vec<(&'static str, u64)>,
    /// The slots `get_register` REFUSED, by name. Kept apart from the slots
    /// that merely hold zero: a register that is genuinely 0 at the fault and a
    /// register the backend cannot produce look identical in the value, and
    /// only the second one is a gap in the core-writing path.
    unavailable: Vec<&'static str>,
    frames: Vec<StackFrame>,
    stack_base: u64,
    stack_bytes: Vec<u8>,
}

/// The 27 slots of `elf_gregset_t` on x86-64, in the order the kernel writes
/// them into `NT_PRSTATUS`. Named here because the interesting number is not
/// "does `get_register` work" but "how many of the slots a core file REQUIRES
/// can this backend actually supply" — see the gap table.
const PRSTATUS_GREGS: [&str; 27] = [
    "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi",
    "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs",
    "gs",
];

/// Launch the fixture, run it into its SIGSEGV, and harvest everything the
/// backend can tell us while the tracee is still stopped at the fault.
async fn crash_and_capture(fx: &Fixture) -> (LinuxDebugger, CrashState) {
    let dbg = LinuxDebugger::new();
    let pid = dbg.launch(launch_opts(fx)).await.expect("launch");
    let ev = run_until_interesting(&dbg, pid.0, 32).await;
    let (signum, fault_addr) = match &ev.reason {
        StopReason::Signal { signum, address, .. } => (*signum, address.map(Address::as_u64)),
        other => panic!("expected the fixture to stop with a signal, got {other:?}"),
    };
    let tid = ev.tid;

    let mut regs = Vec::new();
    let mut unavailable = Vec::new();
    for name in PRSTATUS_GREGS {
        match dbg.get_register(tid, name).await {
            Ok(v) => regs.push((name, v)),
            Err(_) => {
                unavailable.push(name);
                regs.push((name, 0));
            }
        }
    }
    let frames = dbg.backtrace(tid).await.expect("backtrace at the fault");
    let maps = dbg.memory_maps().await.expect("memory_maps at the fault");
    let stack = maps
        .iter()
        .find(|m| m.name.as_deref() == Some("[stack]"))
        .expect("a crashed process must still have a [stack] mapping")
        .clone();

    // Capture from one page below rsp up to the top of the stack region, capped
    // so the synthesised core stays small. `main`'s frame — and therefore MAGIC
    // — lives above rsp, so this window contains it.
    let rsp = regs.iter().find(|(n, _)| *n == "rsp").map_or(0, |(_, v)| *v);
    let top = stack.base.as_u64() + stack.size;
    let lo = rsp.saturating_sub(0x1000).max(stack.base.as_u64()) & !0xfff;
    let len = usize::try_from((top.saturating_sub(lo)).min(256 * 1024)).expect("window fits usize");
    let stack_bytes = dbg
        .read_memory(Address::new(lo), len)
        .await
        .expect("the crashed stack must be readable while the tracee is stopped");

    (
        dbg,
        CrashState {
            tid,
            signum,
            fault_addr,
            regs,
            unavailable,
            frames,
            stack_base: lo,
            stack_bytes,
        },
    )
}

/// Kill the tracee no matter which path the test took out of the body.
async fn cleanup(dbg: &LinuxDebugger) {
    let _ = dbg.kill().await;
}

// ── ELF core synthesis ───────────────────────────────────────────────────────

/// Build a genuine `ET_CORE` ELF64 file out of a [`CrashState`].
///
/// This is the "reachable with what the crate already has" column of the gap
/// table, expressed as code: the register set, the mapping list and the memory
/// reads a core file is made of are all things the backend already answers.
/// What is missing is only the file-format layer, and this function is a
/// test-local, deliberately minimal stand-in for it (one `PT_NOTE` carrying
/// `NT_PRSTATUS`, one `PT_LOAD` carrying the crashed stack). It is validated
/// against `readelf`, so "genuine" is not a claim of this comment.
fn synthesise_core(st: &CrashState, out: &Path) {
    // elf_prstatus, x86-64: 112 bytes of prologue, then 27 * 8 gregs, then
    // pr_fpvalid plus padding = 336 bytes total.
    let mut desc = vec![0u8; 336];
    #[allow(clippy::cast_possible_truncation)]
    let cursig = st.signum as i16;
    desc[12..14].copy_from_slice(&cursig.to_le_bytes()); // pr_cursig
    for (i, (_, v)) in st.regs.iter().enumerate() {
        let at = 112 + i * 8;
        desc[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    let mut note = Vec::new();
    note.extend_from_slice(&5u32.to_le_bytes()); // namesz, "CORE\0"
    note.extend_from_slice(&u32::try_from(desc.len()).unwrap().to_le_bytes());
    note.extend_from_slice(&1u32.to_le_bytes()); // NT_PRSTATUS
    note.extend_from_slice(b"CORE\0\0\0\0"); // name, padded to 4
    note.extend_from_slice(&desc);

    const EHSIZE: u64 = 64;
    const PHENTSIZE: u64 = 56;
    let phnum: u64 = 2;
    let note_off = EHSIZE + PHENTSIZE * phnum;
    let load_off = (note_off + note.len() as u64).next_multiple_of(0x1000);

    let mut f = Vec::new();
    f.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    f.extend_from_slice(&4u16.to_le_bytes()); // ET_CORE
    f.extend_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    f.extend_from_slice(&1u32.to_le_bytes());
    f.extend_from_slice(&0u64.to_le_bytes()); // e_entry
    f.extend_from_slice(&EHSIZE.to_le_bytes()); // e_phoff
    f.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    f.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    f.extend_from_slice(&u16::try_from(EHSIZE).unwrap().to_le_bytes());
    f.extend_from_slice(&u16::try_from(PHENTSIZE).unwrap().to_le_bytes());
    f.extend_from_slice(&u16::try_from(phnum).unwrap().to_le_bytes());
    f.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    f.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    f.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx

    let mut phdr = |ptype: u32, flags: u32, off: u64, vaddr: u64, sz: u64, align: u64| {
        f.extend_from_slice(&ptype.to_le_bytes());
        f.extend_from_slice(&flags.to_le_bytes());
        f.extend_from_slice(&off.to_le_bytes());
        f.extend_from_slice(&vaddr.to_le_bytes());
        f.extend_from_slice(&0u64.to_le_bytes()); // p_paddr
        f.extend_from_slice(&sz.to_le_bytes()); // p_filesz
        f.extend_from_slice(&sz.to_le_bytes()); // p_memsz
        f.extend_from_slice(&align.to_le_bytes());
    };
    phdr(4, 0, note_off, 0, note.len() as u64, 4); // PT_NOTE
    phdr(1, 6, load_off, st.stack_base, st.stack_bytes.len() as u64, 0x1000); // PT_LOAD, rw

    f.extend_from_slice(&note);
    f.resize(usize::try_from(load_off).unwrap(), 0);
    f.extend_from_slice(&st.stack_bytes);
    std::fs::write(out, &f).expect("write synthesised core");
}

fn readelf(args: &[&str], path: &Path) -> String {
    let out = std::process::Command::new("readelf")
        .args(args)
        .arg(path)
        .output()
        .expect("readelf must be available: it is the external ground truth here");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. The host
// ─────────────────────────────────────────────────────────────────────────────

/// A kernel-written core dump is NOT obtainable on this host, and the reason is
/// a property of the host, not of the crate. Measured rather than assumed,
/// because "core dump support is untested" and "core dumps cannot be produced
/// here" are different facts and only the second one is true.
///
/// The fixture raises its own `RLIMIT_CORE` to infinity and then dies of a real
/// SIGSEGV outside ptrace. The test asserts the death (that part is the
/// kernel's), reads `/proc/sys/kernel/core_pattern`, and reports whether
/// anything landed. When `core_pattern` is a pipe (`|…`) to a helper that is not
/// on the filesystem — which is what WSL2 ships — the kernel hands the core to a
/// program it cannot execute and no file is written anywhere.
#[test]
fn the_host_cannot_write_a_kernel_core_and_that_is_measured() {
    let fx = build_fixture();
    let pattern = std::fs::read_to_string("/proc/sys/kernel/core_pattern")
        .expect("core_pattern must be readable")
        .trim()
        .to_string();
    assert!(!pattern.is_empty(), "core_pattern must not be empty");

    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg("ulimit -c unlimited; exec ./fixture")
        .current_dir(&fx.dir)
        .status()
        .expect("run the fixture outside ptrace");
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(
        status.signal(),
        Some(libc::SIGSEGV),
        "the fixture must die of a real SIGSEGV outside ptrace"
    );

    let produced: Vec<String> = std::fs::read_dir(&fx.dir)
        .expect("read tempdir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with("core"))
        .collect();

    if let Some(helper) = pattern.strip_prefix('|') {
        let prog = helper.split_whitespace().next().unwrap_or("");
        let exists = Path::new(prog).exists();
        println!(
            "core_pattern is a PIPE to {prog:?} (exists={exists}); files matching core*: {produced:?}"
        );
        assert!(
            !exists || !produced.is_empty(),
            "the pipe helper exists, so it should be consuming the core, yet nothing \
             was written — investigate before trusting this host's core policy"
        );
    } else {
        println!("core_pattern is a PATH {pattern:?}; files matching core*: {produced:?}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. The ingredients, read at the fault
// ─────────────────────────────────────────────────────────────────────────────

/// The registers AT the crash must be the crash's registers: `rip` inside
/// `crash_a` (the function that dereferences NULL), and the faulting address
/// reported as 0.
///
/// This is the first row of any crash report, and the one thing a debugger
/// cannot recover later without a core file. `-no-pie` makes `nm`'s address the
/// run-time address, so the containment check is exact rather than approximate.
#[tokio::test]
async fn the_registers_at_the_fault_point_into_the_crashing_function() {
    let fx = build_fixture();
    let (dbg, st) = crash_and_capture(&fx).await;
    let rip = st.regs.iter().find(|(n, _)| *n == "rip").map_or(0, |(_, v)| *v);
    let rsp = st.regs.iter().find(|(n, _)| *n == "rsp").map_or(0, |(_, v)| *v);
    cleanup(&dbg).await;

    assert_eq!(st.signum, libc::SIGSEGV, "the fixture must fault, not exit");
    assert_eq!(st.fault_addr, Some(0), "the NULL dereference must report address 0");
    assert!(
        rip >= fx.crash_a && rip < fx.crash_a + 0x200,
        "rip {rip:#x} must be inside crash_a ({:#x}..{:#x})",
        fx.crash_a,
        fx.crash_a + 0x200
    );
    assert!(rsp != 0, "rsp must be non-zero at the fault");
}

/// The backtrace at the fault must walk out of the crashing function all the
/// way to `main`, through both intermediate frames.
///
/// A crash report whose stack stops at frame 0 tells the reader where the
/// program died and not why. The assertion is on PROGRAM COUNTERS, not on
/// names: no symbol resolver is installed here, so `function_name` is
/// legitimately `None` and asserting on it would be testing the test.
#[tokio::test]
async fn the_backtrace_at_the_fault_reaches_main_through_the_crash_chain() {
    let fx = build_fixture();
    let (dbg, st) = crash_and_capture(&fx).await;
    cleanup(&dbg).await;

    let pcs: Vec<u64> = st.frames.iter().map(|f| f.pc.as_u64()).collect();
    let covers = |sym: u64| pcs.iter().any(|&pc| pc >= sym && pc < sym + 0x200);
    println!("frames at the fault: {pcs:#x?}");
    assert!(!st.frames.is_empty(), "the unwind produced no frames at all");
    assert_eq!(st.frames[0].index, 0, "frame indices must start at 0");
    assert!(covers(fx.crash_a), "frame 0 must be in crash_a; got {pcs:#x?}");
    for (name, sym) in [("crash_b", fx.crash_b), ("crash_c", fx.crash_c), ("main", fx.main)] {
        assert!(covers(sym), "the unwind must reach {name} ({sym:#x}); got {pcs:#x?}");
    }
}

/// The mapping list at the fault must contain the executable and the stack.
///
/// These are the `PT_LOAD` headers of a core file and the module list of a
/// crash report; without them a stack address in a backtrace cannot even be
/// classified as a stack address.
#[tokio::test]
async fn the_memory_maps_at_the_fault_carry_the_stack_and_the_executable() {
    let fx = build_fixture();
    let dbg = LinuxDebugger::new();
    let pid = dbg.launch(launch_opts(&fx)).await.expect("launch");
    let ev = run_until_interesting(&dbg, pid.0, 32).await;
    assert!(
        matches!(ev.reason, StopReason::Signal { .. }),
        "expected the fault, got {:?}",
        ev.reason
    );
    let maps = dbg.memory_maps().await.expect("memory_maps");
    cleanup(&dbg).await;

    assert!(maps.len() > 3, "a crashed C program has more than {} mappings", maps.len());
    let stack = maps.iter().find(|m| m.name.as_deref() == Some("[stack]"));
    assert!(stack.is_some(), "the crashed process must expose a [stack] mapping");
    let stack = stack.unwrap();
    assert!(stack.readable && stack.writable, "[stack] must be readable and writable");
    let text = maps
        .iter()
        .find(|m| m.executable && m.file_path.as_deref().is_some_and(|p| p.ends_with("fixture")));
    assert!(
        text.is_some(),
        "the executable's own text mapping must be listed; got {:?}",
        maps.iter().map(|m| (m.name.clone(), m.executable)).collect::<Vec<_>>()
    );
    assert!(text.unwrap().base.as_u64() <= fx.crash_a, "the text mapping must contain crash_a");
}

/// The crashed stack must be READABLE, and its bytes must be the program's
/// actual stack: they contain the magic string the fixture planted in `main`'s
/// frame.
///
/// This closes the circle on the ingredient list. Ground truth is the source
/// constant, not another call to the same backend, so a backend that returned
/// plausible-looking garbage would fail here.
#[tokio::test]
async fn the_crashed_stack_bytes_contain_the_string_the_fixture_planted() {
    let fx = build_fixture();
    let (dbg, st) = crash_and_capture(&fx).await;
    cleanup(&dbg).await;

    assert!(!st.stack_bytes.is_empty(), "the stack window must not be empty");
    let found = st.stack_bytes.windows(MAGIC.len()).any(|w| w == MAGIC.as_bytes());
    assert!(
        found,
        "the {} bytes read from {:#x} must contain {MAGIC:?}",
        st.stack_bytes.len(),
        st.stack_base
    );
}

/// How many of the 27 `NT_PRSTATUS` register slots the backend can actually
/// supply, measured slot by slot.
///
/// A core file's register block is not "the general-purpose registers": it is a
/// fixed 27-slot `elf_gregset_t` that also carries `orig_rax`, the segment
/// selectors and `fs_base`/`gs_base`. A writer that can fill only some of them
/// produces a core a consumer reads as a crash with a null `fs_base` — wrong,
/// not merely incomplete. So the roster is printed and the slots a backtrace
/// depends on are asserted present.
///
/// **MEASURED DEFECT (partial) — 9 of the 27 slots are REFUSED.** Measured
/// output: `NT_PRSTATUS slots the backend answered: 18/27; REFUSED:
/// ["orig_rax", "cs", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs"]`.
/// The test is green because 18 is enough for the rows below that matter most,
/// and the assertion is pinned at `<= 9` so a regression is caught; the gap is
/// recorded here rather than hidden behind the green.
///
/// | slot group | expected (external truth) | reachable with what the crate already has | obtained today |
/// |---|---|---|---|
/// | `rip`/`rsp`/`rbp`/GPRs (18) | the kernel's `user_regs_struct` has all 27 fields | yes — `read_regs` (`linux_debugger.rs:2480`) already returns the WHOLE struct | 18/27 answered |
/// | `fs_base`/`gs_base` | same single `user_regs_struct`, offsets 21-22 | yes — the bytes are ALREADY in the buffer the backend read | `get_register` returns an error |
/// | `cs`/`ss`/`ds`/`es`/`fs`/`gs`, `orig_rax` | same buffer, offsets 15, 17, 20, 23-26 | yes — same buffer | `get_register` returns an error |
///
/// Command that produces the external truth: `readelf -n <core>` shows the
/// 336-byte `NT_PRSTATUS` descriptor, whose 27 `elf_gregset_t` slots start at
/// descriptor offset 112. The cure is not a new ptrace call: the backend
/// already reads the whole `user_regs_struct` (`PTRACE_GETREGS` on x86-64, which
/// fills the very structure `NT_PRSTATUS` carries), and `to_register_set`
/// (`linux_debugger.rs:2560`) names exactly 18 of its fields and stops. The nine
/// missing slots are a naming table that stops short, not data the crate lacks. Without them a
/// core written from this state reports `fs_base = 0`, which a consumer reads
/// as a valid TLS base of zero — wrong, not absent.
#[tokio::test]
async fn the_prstatus_register_roster_is_measured_slot_by_slot() {
    let fx = build_fixture();
    let (dbg, st) = crash_and_capture(&fx).await;
    cleanup(&dbg).await;

    let zeroed: Vec<&str> = st.regs.iter().filter(|(_, v)| *v == 0).map(|(n, _)| *n).collect();
    println!(
        "NT_PRSTATUS slots the backend answered: {}/27; REFUSED: {:?}; zero-valued (refused OR genuinely zero): {zeroed:?}",
        27 - st.unavailable.len(),
        st.unavailable
    );
    for must in ["rip", "rsp", "rbp", "rax", "rbx", "rdi", "rsi", "eflags"] {
        assert!(
            st.regs.iter().any(|(n, _)| *n == must),
            "slot {must} must be present in the roster"
        );
    }
    assert!(
        st.unavailable.len() <= 9,
        "the backend REFUSED {} of the 27 NT_PRSTATUS slots ({:?}) - a core written from          this state would be missing register CONTENT, not merely precision",
        st.unavailable.len(),
        st.unavailable
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. The corpse
// ─────────────────────────────────────────────────────────────────────────────

/// Once the SIGSEGV is FORWARDED and the process actually dies, the same calls
/// that answered at the fault must answer "gone" — not answer with the values
/// they held a moment ago.
///
/// This is the exact moment a post-mortem story begins, and the exact moment a
/// debugger without core support has nothing left to offer. A stale answer here
/// is worse than an error: the caller cannot tell it apart from a live one, and
/// would publish a crash report about a process that no longer exists.
#[tokio::test]
async fn after_the_crash_kills_the_tracee_every_reader_says_gone_not_stale() {
    let fx = build_fixture();
    let (dbg, st) = crash_and_capture(&fx).await;
    let pid = dbg.target_pid().expect("a live pid").0;

    // Resuming delivers the pending SIGSEGV; the default action kills the tracee.
    let mut exited = false;
    for _ in 0..8 {
        match dbg.continue_execution().await {
            Ok(ev) => {
                if ev.pid.0 == pid && matches!(ev.reason, StopReason::ProcessExit { .. }) {
                    exited = true;
                    break;
                }
            }
            Err(_) => {
                exited = true;
                break;
            }
        }
    }
    assert!(exited, "forwarding SIGSEGV must kill the tracee");
    assert!(
        !Path::new(&format!("/proc/{pid}/stat")).exists(),
        "/proc/{pid} must be gone once the tracee died of SIGSEGV"
    );

    let regs = dbg.get_registers(st.tid).await;
    let bt = dbg.backtrace(st.tid).await;
    let maps = dbg.memory_maps().await;
    let mem = dbg.read_memory(Address::new(st.stack_base), 16).await;
    cleanup(&dbg).await;
    println!(
        "after the tracee died: get_registers={:?}, backtrace={:?}, read_memory={:?}, memory_maps={:?}",
        regs.as_ref().err(),
        bt.as_ref().map(Vec::len),
        mem.as_ref().err(),
        maps.as_ref().map(Vec::len)
    );

    assert!(regs.is_err(), "get_registers on a dead tracee must fail, got {regs:?}");
    assert!(bt.is_err(), "backtrace on a dead tracee must fail, got {:?}", bt.map(|f| f.len()));
    assert!(mem.is_err(), "read_memory on a dead tracee must fail, got {mem:?}");
    assert!(
        maps.as_ref().map_or(true, Vec::is_empty),
        "memory_maps on a dead tracee must not return the mappings it had while alive, got {} entries",
        maps.map_or(0, |m| m.len())
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. The missing layer
// ─────────────────────────────────────────────────────────────────────────────

/// A core file assembled from what the backend reads live is a REAL `ET_CORE`
/// file, and `readelf` — not this test — says so.
///
/// The point is not the synthesiser (it is test-local and deliberately
/// minimal). The point is the measurement it makes possible: every input to it
/// came out of `LinuxDebugger`, so the crate demonstrably HOLDS the contents of
/// a core dump at the moment of the crash. What it lacks is the layer that
/// writes them down or reads them back. That distinction is what makes the cure
/// writable instead of guessable.
#[tokio::test]
async fn a_core_synthesised_from_live_state_is_a_real_et_core_to_readelf() {
    let fx = build_fixture();
    let (dbg, st) = crash_and_capture(&fx).await;
    cleanup(&dbg).await;

    let core = fx.dir.join("synth.core");
    synthesise_core(&st, &core);

    let hdr = readelf(&["-h"], &core);
    assert!(hdr.contains("CORE (Core file)"), "readelf -h must call it a core file:\n{hdr}");
    assert!(hdr.contains("X86-64"), "machine must be x86-64:\n{hdr}");
    assert!(!hdr.contains("Error"), "readelf -h must be clean:\n{hdr}");

    let phdrs = readelf(&["-l"], &core);
    assert!(phdrs.contains("NOTE"), "a core needs a PT_NOTE:\n{phdrs}");
    assert!(phdrs.contains("LOAD"), "a core needs at least one PT_LOAD:\n{phdrs}");
    assert!(!phdrs.contains("Error"), "readelf -l must be clean:\n{phdrs}");

    let notes = readelf(&["-n"], &core);
    assert!(
        notes.contains("NT_PRSTATUS"),
        "the note must be recognised as NT_PRSTATUS by readelf:\n{notes}"
    );
    assert!(!notes.contains("Error"), "readelf -n must be clean:\n{notes}");
}

/// The synthesised core carries the two things a post-mortem reader actually
/// wants: the crash `rip` in its `NT_PRSTATUS` block, and the crashed stack in
/// its `PT_LOAD`.
///
/// Read back straight out of the FILE — not from the debugger — so this is a
/// round trip, not a restatement. Ground truth for `rip` is `nm`'s address for
/// `crash_a`; ground truth for the stack content is the source constant.
#[tokio::test]
async fn the_synthesised_core_round_trips_the_crash_rip_and_the_stack() {
    let fx = build_fixture();
    let (dbg, st) = crash_and_capture(&fx).await;
    cleanup(&dbg).await;

    let core = fx.dir.join("synth.core");
    synthesise_core(&st, &core);
    let bytes = std::fs::read(&core).expect("read back the synthesised core");

    // e_phoff is fixed at 64 by the writer, and the PT_NOTE phdr is the first.
    let note_off =
        usize::try_from(u64::from_le_bytes(bytes[72..80].try_into().unwrap())).unwrap();
    // note header: namesz/descsz/type (12 bytes) + "CORE\0" padded to 8 = 20.
    let desc = note_off + 20;
    let rip_in_file =
        u64::from_le_bytes(bytes[desc + 112 + 16 * 8..desc + 112 + 17 * 8].try_into().unwrap());
    assert!(
        rip_in_file >= fx.crash_a && rip_in_file < fx.crash_a + 0x200,
        "the rip stored in NT_PRSTATUS ({rip_in_file:#x}) must be inside crash_a ({:#x})",
        fx.crash_a
    );
    let cursig = i16::from_le_bytes(bytes[desc + 12..desc + 14].try_into().unwrap());
    assert_eq!(i32::from(cursig), libc::SIGSEGV, "pr_cursig must record the killing signal");
    assert!(
        bytes.windows(MAGIC.len()).any(|w| w == MAGIC.as_bytes()),
        "the PT_LOAD must carry the crashed stack, magic string included"
    );
}

/// **MEASURED DEFECT — no ELF core reader exists in this crate.**
///
/// Ignored because it asserts the behaviour that SHOULD exist; today it is red.
/// The red, obtained by running it with `--ignored`, is that the only dump-file
/// parser in the crate is `minidump_analysis` — a Windows `.dmp` reader — and it
/// rejects an ELF core at the signature check (`invalid signature: expected
/// MDMP`). There is no other entry point: no method of `Debugger` or
/// `LinuxDebugger` takes a path to a dump, and `coredump_triage` states in its
/// own module docs that it "does not itself parse dump file formats".
///
/// ## The gap
///
/// | datum | expected (external truth) | reachable with what the crate already has | obtained today |
/// |---|---|---|---|
/// | file is a core | `readelf -h core` → `Type: CORE (Core file)` | yes — proven by `a_core_synthesised_from_live_state_is_a_real_et_core_to_readelf` | nothing in the crate parses it |
/// | crash registers | `readelf -n core` → `NT_PRSTATUS`; `rip` at desc+112+16*8 | yes — `get_register` supplies the 27-slot roster at the fault | `minidump_analysis::parse` → `BadSignature` |
/// | backtrace | unwind `rip`/`rsp`/`rbp` from `NT_PRSTATUS` against the `PT_LOAD`s | yes — `backtrace()` already walks the stopped tracee | no API accepts a core path |
/// | mappings | `readelf -l core` → `PT_LOAD` list; `NT_FILE` note → backing paths | partly — `memory_maps()` gives base/size/perms/path LIVE; the writer here emits `PT_LOAD` but no `NT_FILE` | no API accepts a core path |
///
/// Commands that produce the external truth:
/// `readelf -h <core>`, `readelf -l <core>`, `readelf -n <core>`.
/// `gdb` is NOT installed on this host, so `gdb -c <core>` is not the oracle
/// used here; `readelf` is, and it settles every row above.
///
/// The shape of the cure the table implies: a `parse_elf_core(&[u8])` beside
/// `minidump_analysis::parse`, returning the same `ThreadContext`-shaped view,
/// plus a `DebugTarget::CoreFile` path in `debug_session_manager` that actually
/// opens the file (see `a_core_file_session_is_opened_without_opening_the_file`).
#[tokio::test]
#[ignore = "measured red: no ELF-core reader exists; see the gap table in the doc comment"]
async fn an_elf_core_file_has_no_reader_in_this_crate() {
    let fx = build_fixture();
    let (dbg, st) = crash_and_capture(&fx).await;
    cleanup(&dbg).await;
    let core = fx.dir.join("synth.core");
    synthesise_core(&st, &core);
    let bytes = std::fs::read(&core).expect("read core");

    let via_minidump = rustre_debug::minidump_analysis::parse(&bytes);
    println!("minidump_analysis::parse(ET_CORE) -> {:?}", via_minidump.as_ref().err());
    let view = via_minidump.expect("a dump parser in a debugger crate must read a Linux ELF core");
    assert_eq!(
        view.crash_pc().map(|pc| pc & !0x1ff),
        Some(fx.crash_a & !0x1ff),
        "the crash pc read from the core must land inside crash_a"
    );
}

/// **MEASURED DEFECT — `DebugTarget::CoreFile` is inert data.**
///
/// Ignored because it asserts the behaviour that SHOULD exist. The red,
/// obtained with `--ignored`: `DebugSessionManager::open_session` accepts a
/// `CoreFile` target pointing at a path that DOES NOT EXIST, returns `Ok`, and
/// registers the session. `open_session` only calls `DebugSession::new` and
/// `pool.add`; nothing in that chain touches the filesystem.
///
/// | datum | expected (external truth) | reachable with what the crate already has | obtained today |
/// |---|---|---|---|
/// | opening a missing core | `test -f /nonexistent/…/core` → false, so the open must fail | trivially — one `Path::exists` in `open_session` | `Ok(SessionId)`, session registered |
/// | opening a real core | a session whose registers/backtrace come from the file | not yet — needs the reader in the table above | the same `Ok`, still no file read |
///
/// The rows are ordered on purpose: the first is a one-line fix that stops the
/// manager reporting a session over a file that is not there; the second needs
/// `parse_elf_core` and is the real work.
#[test]
#[ignore = "measured red: open_session never opens the core file; see the gap table"]
fn a_core_file_session_is_opened_without_opening_the_file() {
    let mut mgr = DebugSessionManager::new(4);
    let missing = "/nonexistent/definitely/not/a/core.1234";
    assert!(!Path::new(missing).exists(), "the premise: the path must not exist");
    let res = mgr.open_session(
        SessionTarget::CoreFile { path: missing.to_string(), arch: "x86_64".into() },
        "x86_64",
    );
    println!("open_session(CoreFile{{{missing}}}) -> {res:?}");
    assert!(
        res.is_err(),
        "opening a session over a core file that does not exist must fail, got {res:?}"
    );
}

/// `coredump_triage` DOES work on a real crash — but only once someone else has
/// produced the backtrace, and its signature quality depends on symbols the live
/// path does not supply.
///
/// Fed the genuine frames captured at the fault it clusters them (one crash, one
/// cluster) and reports `signature_is_aslr_stable() == false`, because with no
/// symbol resolver installed every frame is identified by a raw `pc:0x…`. That is
/// the module's own documented failure mode, reproduced against a real process
/// instead of a hand-built `StackFrame`: a crash farm fed backtraces of this
/// quality would be told there is no recurring crash.
#[tokio::test]
async fn triage_clusters_a_real_crash_but_its_signature_is_not_aslr_stable() {
    let fx = build_fixture();
    let (dbg, st) = crash_and_capture(&fx).await;
    cleanup(&dbg).await;

    let dump =
        CrashDump { id: "fixture-segv".into(), frames: st.frames.clone(), signal: Some(st.signum) };
    let clusters = triage(std::slice::from_ref(&dump), 4);
    assert_eq!(clusters.len(), 1, "one crash must yield one cluster");
    assert_eq!(clusters[0].count(), 1);
    assert!(
        !clusters[0].signature_frames.is_empty(),
        "a real backtrace must produce signature frames"
    );
    let unnamed = st.frames.iter().filter(|f| f.function_name.is_none()).count();
    println!(
        "signature frames: {:?}; frames without a name: {unnamed}/{}",
        clusters[0].signature_frames,
        st.frames.len()
    );
    assert!(
        !clusters[0].signature_is_aslr_stable(),
        "with no symbol resolver installed the signature cannot be ASLR-stable; if this \
         now passes, the live backtrace gained names and the triage quality gap has closed"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Hygiene
// ─────────────────────────────────────────────────────────────────────────────

/// No fixture process may outlive this file.
///
/// Every test kills its tracee on both the success and the error path, but a
/// panic inside a test body skips the `cleanup` call, and a leaked `ptrace`d
/// child stays stopped forever instead of dying with its parent. Named to sort
/// last under `--test-threads=1`, this asserts the invariant with `pgrep`
/// rather than trusting drop glue.
#[test]
fn zz_no_orphan_fixture_processes_survive() {
    let out = std::process::Command::new("pgrep")
        .args(["-a", "-f", "/fixture"])
        .output()
        .expect("pgrep");
    let listing = String::from_utf8_lossy(&out.stdout);
    // Match only THIS file's fixture: other agents run concurrently in the same
    // tree with names like `load_fixture`, and a substring match on "/fixture"
    // would fail this test on somebody else's live process.
    let mine: Vec<&str> = listing
        .lines()
        .filter(|l| l.split_whitespace().any(|w| w.ends_with("/fixture")))
        .collect();
    assert!(mine.is_empty(), "orphaned fixture processes survived: {mine:?}");
}
