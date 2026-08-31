//! DV3 / key `symbols` — tests that bite where `live_linux_symbols.rs` does not.
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::{BreakpointKind, Debugger, LaunchOptions, OutputRedirect, StopReason};
use rustre_symbols::SymbolProvider;
use rustre_symbols::dwarf_provider::{DwarfParser, DwarfSections};
use rustre_symbols::elf_provider::ElfSymbolProvider;
use std::time::Duration;

const FIXTURE_C: &str = r#"#include <signal.h>
__attribute__((noinline)) int marker_alpha(int x) { return x * 3; }
__attribute__((noinline)) int marker_beta(int x) { return marker_alpha(x) + 1; }
int main(void) {
    raise(SIGTRAP);
    volatile int r = marker_beta(7);
    (void)r;
    for (;;) { }
    return 0;
}
"#;
const ALPHA_LINE: u32 = 2;
const BETA_LINE: u32 = 3;

struct Fixture {
    _dir: tempfile::TempDir,
    exe: String,
    bytes: Vec<u8>,
}

fn build_fixture_dwarf4() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("dv3sym.c");
    let exe = dir.path().join("dv3sym");
    std::fs::write(&src, FIXTURE_C).expect("write");
    let out = std::process::Command::new("cc")
        .args(["-no-pie", "-O0", "-g", "-gdwarf-4"])
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .output()
        .expect("cc");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let bytes = std::fs::read(&exe).expect("read elf");
    Fixture { exe: exe.to_string_lossy().to_string(), bytes, _dir: dir }
}

fn u16le(d: &[u8], o: usize) -> u16 { u16::from_le_bytes([d[o], d[o + 1]]) }
fn u32le(d: &[u8], o: usize) -> u32 { u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]]) }
fn u64le(d: &[u8], o: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[o..o + 8]);
    u64::from_le_bytes(b)
}

fn sections(elf: &[u8]) -> Vec<(String, usize, usize, u64)> {
    let e_shoff = u64le(elf, 0x28) as usize;
    let e_shentsize = u16le(elf, 0x3a) as usize;
    let e_shnum = u16le(elf, 0x3c) as usize;
    let e_shstrndx = u16le(elf, 0x3e) as usize;
    let shdr = |i: usize| {
        let b = e_shoff + i * e_shentsize;
        (u32le(elf, b) as usize, u64le(elf, b + 0x10), u64le(elf, b + 0x18) as usize, u64le(elf, b + 0x20) as usize)
    };
    let (_, _, stroff, _) = shdr(e_shstrndx);
    (0..e_shnum)
        .map(|i| {
            let (nameoff, addr, off, size) = shdr(i);
            let s = &elf[stroff + nameoff..];
            let end = s.iter().position(|&b| b == 0).unwrap_or(0);
            (String::from_utf8_lossy(&s[..end]).to_string(), off, size, addr)
        })
        .collect()
}

fn provider(fx: &Fixture) -> ElfSymbolProvider {
    let secs = sections(&fx.bytes);
    let find = |n: &str| {
        secs.iter().find(|s| s.0 == n).map(|s| &fx.bytes[s.1..s.1 + s.2]).unwrap_or_else(|| panic!("no {n}"))
    };
    ElfSymbolProvider::parse_symtab("dv3sym", find(".symtab"), find(".strtab"), true, true).expect("symtab")
}

fn dwarf_sections(fx: &Fixture) -> DwarfSections {
    let secs = sections(&fx.bytes);
    let get = |n: &str| secs.iter().find(|s| s.0 == n).map(|s| fx.bytes[s.1..s.1 + s.2].to_vec()).unwrap_or_default();
    DwarfSections {
        debug_info: get(".debug_info"),
        debug_abbrev: get(".debug_abbrev"),
        debug_str: get(".debug_str"),
        debug_line: get(".debug_line"),
        debug_line_str: get(".debug_line_str"),
        debug_str_offsets: get(".debug_str_offsets"),
        debug_addr: get(".debug_addr"),
        split_debug_info: None,
    }
}

async fn launched(fx: &Fixture) -> LinuxDebugger {
    let dbg = LinuxDebugger::new();
    dbg.launch(LaunchOptions {
        executable: fx.exe.clone(),
        args: Vec::new(),
        env: std::collections::HashMap::new(),
        working_dir: None,
        stop_at_entry: false,
        follow_forks: false,
        redirect: OutputRedirect::default(),
    })
    .await
    .expect("launch");
    dbg
}


/// name -> (entry address, size) for the three markers, straight from `.symtab`.
fn markers(p: &ElfSymbolProvider) -> Vec<(&'static str, u64, u64)> {
    ["marker_alpha", "marker_beta", "main"]
        .iter()
        .map(|n| {
            let s = p.lookup_name(n).unwrap_or_else(|| panic!("{n} missing from .symtab"));
            (*n, s.address, s.size.unwrap_or_else(|| panic!("{n} has no size")))
        })
        .collect()
}

/// Which function each 1-based source line of `FIXTURE_C` belongs to.
fn function_of_line(line: u32) -> Option<&'static str> {
    match line {
        2 => Some("marker_alpha"),
        3 => Some("marker_beta"),
        4..=9 => Some("main"),
        _ => None,
    }
}

// -- T1 ----------------------------------------------------------------------

/// Proves: the ENTRY address `.symtab` gives for a function is the LOWEST
/// address DWARF attributes to that function's source line - two independent
/// producers in the same ELF, pinned to each other.
///
/// Why this and not the existing checks: `live_linux_symbols.rs` compares the
/// symtab address only against `nm` (same table, different reader) and against
/// a breakpoint, which fires anywhere on the executed path. Measured: shifting
/// every resolved address by +8 while shifting `nm` with it leaves all six of
/// that file's tests green. This one goes red, because DWARF was not moved and
/// alpha's entry is exactly the minimum line-2 row (0x401136), not 0x40113e.
#[test]
fn a_symtab_entry_address_is_the_lowest_dwarf_row_of_its_line() {
    let fx = build_fixture_dwarf4();
    let p = provider(&fx);
    let table = DwarfParser::new(&dwarf_sections(&fx), false)
        .parse_line_table()
        .expect("parse line table");
    assert!(!table.entries.is_empty(), "guard: 0 line rows makes this vacuous");

    for (name, line) in [("marker_alpha", ALPHA_LINE), ("marker_beta", BETA_LINE)] {
        let entry = p.lookup_name(name).unwrap_or_else(|| panic!("{name}")).address;
        let lowest = table
            .entries
            .iter()
            .filter(|e| e.line == line && e.address != 0)
            .map(|e| e.address)
            .min()
            .unwrap_or_else(|| panic!("DWARF has no row for line {line} ({name})"));
        assert_eq!(
            entry, lowest,
            "{name}: .symtab says the function starts at {entry:#x}, DWARF's lowest \
             line-{line} row is {lowest:#x} (delta {})",
            entry as i64 - lowest as i64
        );
    }
}

// -- T2 ----------------------------------------------------------------------

/// Proves: nearest-symbol lookup respects the symbol's recorded SIZE at both
/// ends - the last byte of `marker_alpha` resolves to `marker_alpha` and the
/// very next byte resolves to `marker_beta`.
///
/// Why: the existing enclosing-function test probes a single address 4 bytes
/// in, so a lookup that never stops (every address above alpha resolves to
/// alpha) passes it. The oracle here is a 4-tuple of names across a boundary,
/// which no single constant answer can satisfy.
#[test]
fn nearest_lookup_stops_at_the_end_of_a_function_not_at_the_next_one() {
    let fx = build_fixture_dwarf4();
    let p = provider(&fx);
    let m = markers(&p);
    let (_, a_addr, a_size) = m[0];
    let (_, b_addr, _) = m[1];
    assert_eq!(
        a_addr + a_size,
        b_addr,
        "guard: this fixture must lay marker_beta immediately after marker_alpha \
         ({a_addr:#x}+{a_size} != {b_addr:#x})"
    );
    let got: Vec<String> = [a_addr, a_addr + 1, a_addr + a_size - 1, a_addr + a_size]
        .iter()
        .map(|a| {
            p.lookup_nearest(*a)
                .map(|s| s.name)
                .unwrap_or_else(|| "<none>".into())
        })
        .collect();
    assert_eq!(
        got,
        vec!["marker_alpha", "marker_alpha", "marker_alpha", "marker_beta"],
        "boundary walk over [{a_addr:#x}, +{a_size}] gave {got:?}"
    );
}

// -- T3 ----------------------------------------------------------------------

/// Proves, against the MACHINE and nothing else, that the resolved address is
/// the function's ENTRY and not some later instruction inside it: stopped at
/// the claimed entry of `marker_alpha`, the top of the stack must hold a return
/// address lying inside `marker_beta`, its only caller.
///
/// Why this is the check the file was missing: at a true entry the callee has
/// pushed nothing, so `[rsp]` IS the return address. Eight bytes later the
/// prologue has executed `push %rbp`, so `[rsp]` holds a saved frame pointer -
/// a stack address, orders of magnitude away from `.text`. A breakpoint alone
/// cannot tell the two apart, which is exactly why the coherent +8 mutation
/// left `a_resolved_symbol_address_is_where_the_process_really_executes` green.
#[tokio::test(flavor = "multi_thread")]
async fn at_the_resolved_entry_the_stack_top_is_a_return_address_into_the_caller() {
    let fx = build_fixture_dwarf4();
    let p = provider(&fx);
    let m = markers(&p);
    let (_, a_addr, _) = m[0];
    let (_, b_addr, b_size) = m[1];

    let dbg = launched(&fx).await;
    dbg.set_breakpoint(Address::new(a_addr), BreakpointKind::Software)
        .await
        .expect("breakpoint at marker_alpha");
    let mut tid = None;
    for _ in 0..8 {
        let ev = tokio::time::timeout(Duration::from_secs(30), dbg.continue_execution())
            .await
            .expect("continue must not hang")
            .expect("continue must not error");
        if let StopReason::Breakpoint { address, .. } = ev.reason {
            assert_eq!(address.as_u64(), a_addr, "stopped at the wrong breakpoint");
            tid = Some(ev.tid);
            break;
        }
    }
    let tid = tid.expect("the breakpoint at marker_alpha never fired");
    let rsp = dbg.get_register(tid, "rsp").await.expect("read rsp");
    let top = dbg
        .read_memory(Address::new(rsp), 8)
        .await
        .expect("read [rsp]");
    let _ = dbg.kill().await;

    let mut w = [0u8; 8];
    w.copy_from_slice(&top);
    let ret = u64::from_le_bytes(w);
    assert!(
        ret > b_addr && ret <= b_addr + b_size,
        "at the address resolved for marker_alpha ({a_addr:#x}) the top of stack is \
         {ret:#x}, which is not a return address inside marker_beta \
         [{b_addr:#x}, +{b_size}) - the stop is not at a function entry"
    );
}

// -- T4 ----------------------------------------------------------------------

/// Proves: DWARF and `.symtab` agree about WHICH function every line row falls
/// in - for every non-zero row, the nearest symbol at or below its address is
/// the function that owns that source line.
///
/// Why: it is a whole-table cross-check with no external file involved, so it
/// survives a corrupted `nm` and still catches both a uniform address shift and
/// two functions' addresses being swapped - the two mutations the existing file
/// is measurably blind to (shift) or only half-catches (swap).
#[test]
fn every_dwarf_row_lands_in_the_symtab_function_that_owns_its_line() {
    let fx = build_fixture_dwarf4();
    let p = provider(&fx);
    let table = DwarfParser::new(&dwarf_sections(&fx), false)
        .parse_line_table()
        .expect("parse line table");
    let rows: Vec<_> = table
        .entries
        .iter()
        .filter(|e| e.address != 0 && function_of_line(e.line).is_some())
        .collect();
    assert!(
        rows.len() >= 8,
        "guard: only {} usable rows, too few to bite",
        rows.len()
    );

    let mut bad = Vec::new();
    for r in &rows {
        let want = function_of_line(r.line).unwrap();
        let got = p
            .lookup_nearest(r.address)
            .map(|s| s.name)
            .unwrap_or_else(|| "<none>".into());
        if got != want {
            bad.push(format!(
                "{:#x} (line {}) -> {got}, expected {want}",
                r.address, r.line
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "{} of {} DWARF rows resolve to the wrong function: {bad:?}",
        bad.len(),
        rows.len()
    );
}

// -- T5 ----------------------------------------------------------------------

/// Proves: `ElfSymbolProvider::parse_elf`, handed whole ELF bytes, finds the
/// same three markers at the same addresses as `parse_symtab` handed the
/// hand-sliced sections.
///
/// Why it is here: `live_linux_symbols.rs` carries
/// `parse_elf_should_load_the_symbols_a_real_elf_contains` under
/// `#[ignore = "backend defect: ... a stub that drops every symbol"]`. Measured
/// on this tree with `--ignored`: that test PASSES. The stub is gone, the
/// quarantine is not, so nothing guards the capability any more. This test is
/// the un-quarantined guard, strengthened from "> 0 symbols" to an
/// address-for-address agreement between the two entry points.
#[test]
fn parse_elf_agrees_with_parse_symtab_address_for_address() {
    let fx = build_fixture_dwarf4();
    let sliced = provider(&fx);
    let whole = ElfSymbolProvider::parse_elf("dv3sym", &fx.bytes)
        .expect("parse_elf must accept a valid ELF");
    assert!(
        whole.symbol_count() > 0,
        "parse_elf found 0 symbols in an ELF whose .symtab has them"
    );
    let want: Vec<(&str, u64)> = markers(&sliced).iter().map(|(n, a, _)| (*n, *a)).collect();
    let got: Vec<(&str, u64)> = want
        .iter()
        .map(|(n, _)| {
            (
                *n,
                whole
                    .lookup_name(n)
                    .unwrap_or_else(|| panic!("parse_elf lost {n}"))
                    .address,
            )
        })
        .collect();
    assert_eq!(
        got, want,
        "parse_elf disagrees with parse_symtab on the marker addresses"
    );
}
