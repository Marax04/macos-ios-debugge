//! dv4-invariants — tests that bite where `live_linux_invariants.rs` does not.
//!
//! Measured gaps in that file (numbers in `status_parts/dv4-invariants.md`):
//!  * (a) if `cc` cannot compile the fixture, all six of its tests print a
//!    `skipping:` line on a stdout libtest hides and report **ok**. The whole
//!    file self-exempts in silence.
//!  * (b) it fixes a FUNCTION but not a POSITION for the writing instruction:
//!    the only code-address oracle is `store <= pc < store + 256`, so shifting
//!    the oracle by 8 bytes leaves the file green.
//!  * its bound (100) is not discriminated: every bound in 41..=999 gives the
//!    same verdict on the fixture, so the engine could compare against any of
//!    them and the file would not notice.
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::live_invariant::{InvariantEngine, InvariantOp, InvariantSpec};
use rustre_debug::{BreakpointKind, Debugger, LaunchOptions, OutputRedirect, StopReason};

const FIXTURE: &str = "volatile long g_counter = 0;\n\
     __attribute__((noinline)) static void store(long v) { g_counter = v; }\n\
     int main(void) {\n\
     store(10); store(20); store(30); store(40);\n\
     store(1000);\n\
     store(50);\n\
     return 0;\n\
     }\n";
const EXPECTED_VALUES: [u64; 6] = [10, 20, 30, 40, 1000, 50];

fn compile(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    let src = dir.join(format!("{name}.c"));
    std::fs::write(&src, FIXTURE).expect("write the fixture source");
    let exe = dir.join(name);
    let out = std::process::Command::new("cc")
        .args(["-no-pie", "-O0", "-g"])
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .output()
        .expect("`cc` must be runnable: without it this whole file is vacuous");
    assert!(
        out.status.success(),
        "the fixture must compile; cc said: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    exe
}

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

/// EXTERNAL, POSITIONAL oracle: disassemble the binary, find the single
/// instruction inside `store` whose operand is `g_counter`, and return the
/// address of the instruction that FOLLOWS it — the pc a write watchpoint must
/// report, because the trap is taken after the storing instruction retires.
///
/// This is what `live_linux_invariants.rs` does not have: it distinguishes the
/// storing instruction from the five others in the same function, so an engine
/// that reported the function entry, the `nop`, or the `ret` would be caught.
fn pc_after_the_store(exe: &std::path::Path) -> (u64, u64) {
    let out = std::process::Command::new("objdump")
        .args(["-d", "--no-show-raw-insn"])
        .arg(exe)
        .output()
        .expect("`objdump` must be runnable");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut in_store = false;
    let mut storing: Option<u64> = None;
    for line in text.lines() {
        if line.contains("<store>:") {
            in_store = true;
            continue;
        }
        if !in_store {
            continue;
        }
        let Some((addr_s, rest)) = line.split_once(':') else {
            break;
        };
        let Ok(addr) = u64::from_str_radix(addr_s.trim(), 16) else {
            break;
        };
        if let Some(s) = storing {
            return (s, addr);
        }
        if rest.contains("<g_counter>") && rest.trim_start().starts_with("mov") {
            storing = Some(addr);
        }
    }
    panic!("no instruction inside `store` writes `g_counter`; the fixture changed");
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

/// (value read from the tracee, pc of the stopped thread) for every hit.
async fn trace(dir: &std::path::Path, name: &str) -> (u64, std::path::PathBuf, Vec<(u64, u64)>) {
    let exe = compile(dir, name);
    let sym = symbol_addr(&exe, "g_counter").expect("nm must resolve g_counter");
    let dbg = LinuxDebugger::new();
    dbg.launch(exe_launch(&exe)).await.expect("launch");
    dbg.set_watchpoint_sized(Address(sym), BreakpointKind::DataWrite, 8)
        .await
        .expect("arm the write watchpoint");
    let mut hits = Vec::new();
    for _ in 0..256 {
        let Ok(ev) = dbg.continue_execution().await else {
            break;
        };
        match ev.reason {
            StopReason::ProcessExit { .. } => break,
            StopReason::Breakpoint { address, .. } if address.as_u64() == sym => {
                let bytes = dbg
                    .read_memory(Address(sym), 8)
                    .await
                    .expect("read g_counter");
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes[..8]);
                let pc = dbg.get_registers(ev.tid).await.map(|r| r.pc).unwrap_or(0);
                hits.push((u64::from_le_bytes(buf), pc));
            }
            _ => {}
        }
    }
    let _ = dbg.kill().await;
    (sym, exe, hits)
}

// ── (a) the self-exemption ──────────────────────────────────────────────────

/// `live_linux_invariants.rs` turns a missing/broken toolchain into six silent
/// greens. This test refuses to: if `cc`, `nm` or `objdump` cannot do their job
/// here, the suite is RED, not quietly absent. A skip is a measurement that was
/// not taken.
#[tokio::test]
async fn the_toolchain_is_present_so_no_test_here_can_self_exempt() {
    let dir = tempfile::tempdir().expect("tempdir");
    let exe = compile(dir.path(), "dv4_selfexempt");
    assert!(
        symbol_addr(&exe, "g_counter").is_some(),
        "`nm` must resolve the watched global"
    );
    assert!(
        symbol_addr(&exe, "store").is_some(),
        "`nm` must resolve the writing function"
    );
    let (storing, next) = pc_after_the_store(&exe);
    assert!(next > storing, "objdump must yield two consecutive addresses");
}

// ── (b) the position, not just the function ─────────────────────────────────

/// The pc a violation carries must be EXACTLY the address after the storing
/// instruction — not merely "somewhere in `store`". `store` is 26 bytes of six
/// instructions at -O0; the 256-byte window the existing file asserts accepts
/// all six, plus everything after the function.
#[tokio::test]
async fn the_reported_pc_is_exactly_the_instruction_after_the_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_sym, exe, hits) = trace(dir.path(), "dv4_pc").await;
    let (storing, expected_pc) = pc_after_the_store(&exe);
    assert_eq!(hits.len(), EXPECTED_VALUES.len(), "six writes: {hits:x?}");
    let bad: Vec<(usize, u64)> = hits
        .iter()
        .enumerate()
        .filter(|(_, (_, pc))| *pc != expected_pc)
        .map(|(i, (_, pc))| (i, *pc))
        .collect();
    assert!(
        bad.is_empty(),
        "the storing instruction is at {storing:#x}, so every stop must report \
         {expected_pc:#x}; these did not: {bad:x?}"
    );
}

// ── a triple, not a count ───────────────────────────────────────────────────

/// One assignment reproduces the whole table: sequence, value, and pc.
/// A backend that dropped a write, reordered two, or reported the wrong
/// instruction moves exactly one cell of it.
#[tokio::test]
async fn the_live_trace_matches_the_expected_triples_exactly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_sym, exe, hits) = trace(dir.path(), "dv4_triples").await;
    let (_storing, pc) = pc_after_the_store(&exe);
    let got: Vec<(usize, u64, u64)> = hits
        .iter()
        .enumerate()
        .map(|(i, (v, p))| (i + 1, *v, *p))
        .collect();
    let want: Vec<(usize, u64, u64)> = EXPECTED_VALUES
        .iter()
        .enumerate()
        .map(|(i, v)| (i + 1, *v, pc))
        .collect();
    assert_eq!(got, want, "the (sequence, value, writer_pc) table must match");
}

// ── the bound the existing file cannot discriminate ─────────────────────────

/// On this fixture every bound in `41..=999` yields the same verdict, so the
/// existing `BOUND = 100` proves nothing about the comparison the engine
/// performs. These probes pin it at its own boundaries: `Le 999` must fire only
/// at the 1000, `Le 1000` must fire nowhere, and `Le 39` must fire at exactly
/// the three writes above 39.
#[tokio::test]
async fn the_comparison_is_pinned_at_the_boundary_not_merely_somewhere_between() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (sym, _exe, hits) = trace(dir.path(), "dv4_bound").await;
    let values: Vec<u64> = hits.iter().map(|(v, _)| *v).collect();
    assert_eq!(
        values,
        EXPECTED_VALUES.to_vec(),
        "the trace must be the fixture's"
    );

    let fired = |op: InvariantOp, rhs: u64| -> Vec<usize> {
        let engine = InvariantEngine::new(vec![InvariantSpec {
            name: "b".into(),
            address: Address(sym),
            op,
            rhs,
        }]);
        hits.iter()
            .enumerate()
            .filter(|(_, (v, _))| {
                !engine
                    .check_write(
                        &rustre_debug::omniscient_query::MemoryWrite {
                            sequence: 1,
                            address: Address(sym),
                            size: 8,
                            tid: rustre_debug::ThreadId(1),
                            writer_pc: None,
                            source_address: None,
                        },
                        *v,
                    )
                    .is_empty()
            })
            .map(|(i, _)| i)
            .collect()
    };

    assert_eq!(
        fired(InvariantOp::Le, 999),
        vec![4],
        "Le 999 must fire only on the 1000"
    );
    assert_eq!(
        fired(InvariantOp::Le, 1000),
        Vec::<usize>::new(),
        "Le 1000 holds at every write"
    );
    assert_eq!(
        fired(InvariantOp::Le, 39),
        vec![3, 4, 5],
        "Le 39 must fire on 40, 1000 and 50"
    );
    assert_eq!(
        fired(InvariantOp::Ge, 20),
        vec![0],
        "Ge 20 must fire only on the 10"
    );
}

#[tokio::test]
async fn zzz_dv4_leaves_no_fixture_behind() {
    for stem in ["dv4_selfexempt", "dv4_pc", "dv4_triples", "dv4_bound"] {
        let out = std::process::Command::new("pgrep")
            .args(["-x", stem])
            .output()
            .expect("pgrep must be runnable");
        let listed = String::from_utf8_lossy(&out.stdout);
        let orphans: Vec<&str> = listed
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        assert!(orphans.is_empty(), "{stem} still alive: {orphans:?}");
    }
}
