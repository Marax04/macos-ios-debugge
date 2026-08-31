//! LIVE Linux coverage for the DWARF **line program**, measured VERSION BY
//! VERSION.
//!
//! A previous round measured that the crate's line-program parser rejects
//! DWARF 5 — the default of every current gcc and clang — and returns zero
//! rows. That is a single data point. This file turns it into a MEASUREMENT:
//! the same fixture is compiled with `-gdwarf-2`, `-gdwarf-3`, `-gdwarf-4`,
//! `-gdwarf-5` and with the compiler default, and for each build the parsed
//! row count AND the set of code addresses those rows name are compared
//! against `readelf --debug-dump=decodedline` on the very same file. The gap
//! is therefore reported per version, and against external ground truth, not
//! against the parser's own opinion.
//!
//! Everything here runs on a REAL process: the fixture is compiled on the fly
//! with `cc -no-pie -O0 -g…`, launched under `ptrace` through `LinuxDebugger`,
//! and the addresses the line table claims are validated by planting a
//! breakpoint on one of them and running until it fires. `-no-pie` is
//! load-bearing: the binary is `ET_EXEC`, so a DWARF address is the address
//! the CPU really executes.
//!
//! No backend code is touched. Defects are documented by `#[ignore]`d tests
//! carrying the measured red.
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::{BreakpointKind, Debugger, LaunchOptions, OutputRedirect, StopReason};
use rustre_symbols::SymbolProvider;
use rustre_symbols::dwarf_provider::{DwarfParser, DwarfSections};
use rustre_symbols::elf_provider::ElfSymbolProvider;
use std::collections::BTreeSet;
use std::time::Duration;

/// Several statements on distinct, known lines so a line program has something
/// to say beyond one row: three non-inlinable functions, each a single line,
/// plus a multi-statement `main`. `raise(SIGTRAP)` gives a stop before the
/// markers run; the endless loop keeps the process alive for the live checks.
const FIXTURE_C: &str = r#"#include <signal.h>
__attribute__((noinline)) int line_alpha(int x) { return x * 3; }
__attribute__((noinline)) int line_beta(int x) { return line_alpha(x) + 1; }
__attribute__((noinline)) int line_gamma(int x) { return line_beta(x) - 2; }
int main(void) {
    raise(SIGTRAP);
    volatile int a = line_alpha(1);
    volatile int b = line_beta(2);
    volatile int c = line_gamma(3);
    (void)a; (void)b; (void)c;
    for (;;) { }
    return 0;
}
"#;

/// 1-based line of each single-line function body in `FIXTURE_C`.
const ALPHA_LINE: u32 = 2;
const BETA_LINE: u32 = 3;
const GAMMA_LINE: u32 = 4;

/// The DWARF versions this file measures.
const VERSIONS: [u16; 4] = [2, 3, 4, 5];

struct Fixture {
    _dir: tempfile::TempDir,
    exe: String,
    src_name: String,
    bytes: Vec<u8>,
}

fn build_fixture_with(extra: &[&str]) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("linefixture.c");
    let exe = dir.path().join("linefixture");
    std::fs::write(&src, FIXTURE_C).expect("write fixture source");
    let out = std::process::Command::new("cc")
        .args(["-no-pie", "-O0", "-g"])
        .args(extra)
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .output()
        .expect("cc must be available to run the live DWARF line tests");
    assert!(
        out.status.success(),
        "cc {extra:?} failed to build the fixture: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bytes = std::fs::read(&exe).expect("read the built ELF");
    Fixture {
        exe: exe.to_string_lossy().to_string(),
        src_name: "linefixture.c".to_string(),
        bytes,
        _dir: dir,
    }
}

/// Build pinned to a specific DWARF version.
fn build_dwarf(version: u16) -> Fixture {
    let flag = format!("-gdwarf-{version}");
    build_fixture_with(&[&flag])
}

/// Build with the compiler's own default DWARF version.
fn build_default() -> Fixture {
    build_fixture_with(&[])
}

// ── minimal ELF64 section reader (test-side input handling) ──────────────────

fn u16le(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([d[o], d[o + 1]])
}
fn u32le(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}
fn u64le(d: &[u8], o: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[o..o + 8]);
    u64::from_le_bytes(b)
}

/// name -> (file offset, size, virtual address) for every section.
fn sections(elf: &[u8]) -> Vec<(String, usize, usize, u64)> {
    assert_eq!(&elf[..4], b"\x7fELF", "fixture must be an ELF");
    assert_eq!(elf[4], 2, "fixture must be ELF64");
    let e_shoff = u64le(elf, 0x28) as usize;
    let e_shentsize = u16le(elf, 0x3a) as usize;
    let e_shnum = u16le(elf, 0x3c) as usize;
    let e_shstrndx = u16le(elf, 0x3e) as usize;
    let shdr = |i: usize| {
        let b = e_shoff + i * e_shentsize;
        (
            u32le(elf, b) as usize,
            u64le(elf, b + 0x10),
            u64le(elf, b + 0x18) as usize,
            u64le(elf, b + 0x20) as usize,
        )
    };
    let (_, _, stroff, _) = shdr(e_shstrndx);
    (0..e_shnum)
        .map(|i| {
            let (nameoff, addr, off, size) = shdr(i);
            let s = &elf[stroff + nameoff..];
            let end = s.iter().position(|&b| b == 0).unwrap_or(0);
            (
                String::from_utf8_lossy(&s[..end]).to_string(),
                off,
                size,
                addr,
            )
        })
        .collect()
}

fn dwarf_sections(fx: &Fixture) -> DwarfSections {
    let secs = sections(&fx.bytes);
    let get = |n: &str| {
        secs.iter()
            .find(|s| s.0 == n)
            .map(|s| fx.bytes[s.1..s.1 + s.2].to_vec())
            .unwrap_or_default()
    };
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

fn symtab_provider(fx: &Fixture) -> ElfSymbolProvider {
    let secs = sections(&fx.bytes);
    let get = |n: &str| {
        secs.iter()
            .find(|s| s.0 == n)
            .map(|s| &fx.bytes[s.1..s.1 + s.2])
            .unwrap_or_else(|| panic!("the fixture ELF must contain a {n} section"))
    };
    ElfSymbolProvider::parse_symtab("linefixture", get(".symtab"), get(".strtab"), true, true)
        .expect("the crate's symtab parser must accept a stock `cc -g` .symtab")
}

/// The version field of the FIRST line-program unit, read straight out of the
/// bytes. This is the guard that a `-gdwarf-N` build really produced version N.
fn debug_line_version(secs: &DwarfSections) -> u16 {
    assert!(
        secs.debug_line.len() > 6,
        ".debug_line too short to hold a header"
    );
    u16le(&secs.debug_line, 4)
}

// ── external ground truth: readelf ───────────────────────────────────────────

/// Every code address `readelf --debug-dump=decodedline` prints for this file.
/// Returns `None` when readelf is unavailable, so a machine without binutils
/// skips the comparison instead of failing it.
fn readelf_line_addresses(exe: &str) -> Option<BTreeSet<u64>> {
    let out = std::process::Command::new("readelf")
        .args(["--debug-dump=decodedline", exe])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let mut set = BTreeSet::new();
    for line in text.lines() {
        for tok in line.split_whitespace() {
            if let Some(hex) = tok.strip_prefix("0x") {
                if let Ok(v) = u64::from_str_radix(hex, 16) {
                    if v != 0 {
                        set.insert(v);
                    }
                }
            }
        }
    }
    if set.is_empty() { None } else { Some(set) }
}

/// The parser's answer for one build: (row count, non-zero address set).
fn parsed_rows(fx: &Fixture) -> (usize, BTreeSet<u64>) {
    let secs = dwarf_sections(fx);
    let table = DwarfParser::new(&secs, false)
        .parse_line_table()
        .expect("parse_line_table must not error on a stock `cc -g` .debug_line");
    let addrs: BTreeSet<u64> = table
        .entries
        .iter()
        .map(|e| e.address)
        .filter(|a| *a != 0)
        .collect();
    (table.entries.len(), addrs)
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
    dbg.launch(launch_opts(&fx.exe))
        .await
        .expect("the fixture must launch under ptrace");
    dbg
}

// ── tests ────────────────────────────────────────────────────────────────────

/// Proves: the versions this file claims to measure are the versions the
/// compiler actually emitted, read from the `.debug_line` header bytes.
///
/// Why this is first: every number below is labelled by a DWARF version. If
/// `-gdwarf-2` silently produced version 3 the whole measurement would be
/// mislabelled, and a "gap at version 5" could be a gap somewhere else.
#[tokio::test(flavor = "multi_thread")]
async fn each_pinned_build_really_emits_the_dwarf_version_it_was_asked_for() {
    for v in VERSIONS {
        let fx = build_dwarf(v);
        let secs = dwarf_sections(&fx);
        assert!(
            !secs.debug_line.is_empty(),
            "-gdwarf-{v} produced no .debug_line at all"
        );
        assert_eq!(
            debug_line_version(&secs),
            v,
            "-gdwarf-{v} emitted a .debug_line whose header says version {}",
            debug_line_version(&secs)
        );
    }
}

/// Proves: the DWARF versions 2, 3 and 4 all parse to a NON-EMPTY line table
/// whose rows land inside the fixture's own `.text`.
///
/// Why that is the right behaviour: a line table is the address→source map. A
/// parser that returns zero rows is indistinguishable from a binary with no
/// debug info, and every consumer above it (breakpoint-by-line, backtrace
/// annotation) silently degrades to raw addresses.
#[tokio::test(flavor = "multi_thread")]
async fn dwarf_2_3_and_4_line_programs_all_parse_to_rows_inside_text() {
    for v in [2u16, 3, 4] {
        let fx = build_dwarf(v);
        let elf_secs = sections(&fx.bytes);
        let (_, _, text_size, text_addr) = elf_secs
            .iter()
            .find(|s| s.0 == ".text")
            .cloned()
            .expect(".text");
        let (count, addrs) = parsed_rows(&fx);
        assert!(
            count > 0,
            "DWARF {v}: parsed 0 rows from a {} byte .debug_line",
            dwarf_sections(&fx).debug_line.len()
        );
        assert!(!addrs.is_empty(), "DWARF {v}: every parsed row had address 0");
        let outside = addrs
            .iter()
            .filter(|a| **a < text_addr || **a > text_addr + text_size as u64)
            .count();
        assert_eq!(
            outside, 0,
            "DWARF {v}: {outside} of {} row addresses fall outside .text [{text_addr:#x}, +{text_size:#x})",
            addrs.len()
        );
    }
}

/// Proves: for DWARF 4 the parsed row addresses are a subset of the addresses
/// `readelf` decodes from the same file — an EXTERNAL ground truth, not the
/// parser grading its own homework.
///
/// Subset, not equality, is the honest assertion: readelf also prints
/// end-of-sequence rows and its own header offsets, so an equality check would
/// fail for reasons that are not defects. Inventing an address readelf never
/// saw, on the other hand, is always wrong.
#[tokio::test(flavor = "multi_thread")]
async fn dwarf4_row_addresses_are_a_subset_of_what_readelf_decodes() {
    let fx = build_dwarf(4);
    let Some(truth) = readelf_line_addresses(&fx.exe) else {
        eprintln!("readelf unavailable — comparison skipped");
        return;
    };
    let (_, ours) = parsed_rows(&fx);
    assert!(
        !ours.is_empty(),
        "guard: the parser produced no rows to compare"
    );
    let invented: Vec<String> = ours.difference(&truth).map(|a| format!("{a:#x}")).collect();
    assert!(
        invented.is_empty(),
        "the parser reports {} row address(es) readelf never decoded: {invented:?}",
        invented.len()
    );
    // And it must not be answering with a single token row either.
    assert!(
        ours.len() >= 3,
        "only {} distinct row addresses for a 4-function fixture (readelf: {})",
        ours.len(),
        truth.len()
    );
}

/// Proves: with DWARF 4 the table maps each marker function's ENTRY address to
/// the source file that was compiled and to the line that function occupies.
///
/// Why: a table that returns *a* file and *a* line is useless; three distinct
/// functions are checked so one constant row cannot pass.
#[tokio::test(flavor = "multi_thread")]
async fn dwarf4_maps_each_function_entry_to_its_own_source_line() {
    let fx = build_dwarf(4);
    let prov = symtab_provider(&fx);
    let table = DwarfParser::new(&dwarf_sections(&fx), false)
        .parse_line_table()
        .expect("parse line table");
    for (name, want) in [
        ("line_alpha", ALPHA_LINE),
        ("line_beta", BETA_LINE),
        ("line_gamma", GAMMA_LINE),
    ] {
        let addr = prov.lookup_name(name).expect(name).address;
        let loc = table
            .source_at(addr)
            .unwrap_or_else(|| panic!("no line row covers {name} at {addr:#x}"));
        assert!(
            loc.file.ends_with(&fx.src_name),
            "{name} at {addr:#x} maps to {:?}, not the compiled {}",
            loc.file,
            fx.src_name
        );
        assert_eq!(
            loc.line, want,
            "{name} at {addr:#x} maps to line {} of {:?}, expected {want}",
            loc.line, loc.file
        );
    }
}

/// Proves: a DWARF 4 line-table address is an address the CPU really executes
/// — a breakpoint planted on the row that covers `line_gamma` fires there in
/// the live tracee.
///
/// Why this is the test that binds the measurement to reality: every other
/// assertion in this file compares a number to another number read out of the
/// same file. Only running the process proves the line table describes the
/// program that runs.
#[tokio::test(flavor = "multi_thread")]
async fn a_dwarf4_line_row_address_is_where_the_process_really_stops() {
    let fx = build_dwarf(4);
    let prov = symtab_provider(&fx);
    let entry = prov.lookup_name("line_gamma").expect("line_gamma").address;
    let table = DwarfParser::new(&dwarf_sections(&fx), false)
        .parse_line_table()
        .expect("parse line table");
    let loc = table
        .source_at(entry)
        .expect("a DWARF 4 row must cover line_gamma's entry");
    assert_eq!(loc.line, GAMMA_LINE, "guard: wrong row picked");

    let dbg = launched(&fx).await;
    dbg.set_breakpoint(Address::new(entry), BreakpointKind::Software)
        .await
        .expect("breakpoint at the line-row address must be settable");
    let mut hit = None;
    for _ in 0..8 {
        let ev = tokio::time::timeout(Duration::from_secs(30), dbg.continue_execution())
            .await
            .expect("continue must not hang")
            .expect("continue must not error");
        if let StopReason::Breakpoint { address, .. } = ev.reason {
            hit = Some(address.as_u64());
            break;
        }
    }
    let _ = dbg.kill().await;
    assert_eq!(
        hit,
        Some(entry),
        "the breakpoint planted at the DWARF-4 line-row address never fired at it"
    );
}

/// Proves: the parser never ERRORS on any of the four versions — including the
/// one it cannot decode.
///
/// Why that matters, and why it is not a pass mark: a silent empty table is
/// exactly what makes the DWARF 5 defect below hard to notice. This test pins
/// the fact that the failure mode is *silence*, so the `#[ignore]`d red tests
/// are the only signal a caller would ever get.
#[tokio::test(flavor = "multi_thread")]
async fn no_dwarf_version_makes_the_line_parser_return_an_error() {
    for v in VERSIONS {
        let fx = build_dwarf(v);
        let secs = dwarf_sections(&fx);
        assert!(
            DwarfParser::new(&secs, false).parse_line_table().is_ok(),
            "DWARF {v}: parse_line_table returned Err"
        );
    }
}

/// The MEASUREMENT itself, printed so the gap is a table of numbers rather
/// than a claim. It asserts only the thing that makes the numbers
/// trustworthy: a version whose rows are non-empty must never name an address
/// readelf did not decode.
///
/// Run with `-- --nocapture` to read the table.
#[tokio::test(flavor = "multi_thread")]
async fn dwarf_version_gap_report() {
    println!("version | .debug_line bytes | parser rows | parser addrs | readelf addrs");
    let default_fx = build_default();
    let default_v = debug_line_version(&dwarf_sections(&default_fx));
    let (default_rows, _) = parsed_rows(&default_fx);
    for v in VERSIONS {
        let fx = build_dwarf(v);
        let secs = dwarf_sections(&fx);
        let (count, addrs) = parsed_rows(&fx);
        let truth = readelf_line_addresses(&fx.exe);
        println!(
            "   {v}    | {:>17} | {count:>11} | {:>12} | {:>13}",
            secs.debug_line.len(),
            addrs.len(),
            truth
                .as_ref()
                .map(|s| s.len().to_string())
                .unwrap_or_else(|| "n/a".into())
        );
        if let Some(t) = truth {
            if !addrs.is_empty() {
                let invented = addrs.difference(&t).count();
                assert_eq!(
                    invented, 0,
                    "DWARF {v}: {invented} parsed addresses are absent from readelf's decoding"
                );
            }
        }
    }
    println!(
        "compiler default (`cc -g`) emits DWARF version {default_v} -> {default_rows} parser rows"
    );
}

// ── documented defects (measured, NOT fixed here) ────────────────────────────

/// DEFECT — the DWARF **5** line program parses to ZERO rows.
///
/// This is the version every current gcc and clang emits for a plain `cc -g`,
/// so in practice the line table is empty for freshly built binaries. The
/// header parser bails on v5 (`parse_line_program_header`: "v5 header layout
/// differs — fallback") and `parse_line_table` then hands back an empty table
/// with `Ok`, so nothing upstream can tell "no debug info" from "debug info
/// the parser refused".
///
/// Expected: a non-empty table, as versions 2/3/4 produce from the identical
/// source (see `dwarf_version_gap_report` for the per-version numbers, printed
/// by the run rather than copied into a comment that can rot).
/// Obtained: 0 rows, while `readelf --debug-dump=decodedline` decodes rows for
/// the same file.
#[tokio::test(flavor = "multi_thread")]
async fn dwarf5_line_program_should_parse_to_rows_like_every_other_version() {
    let fx = build_dwarf(5);
    let secs = dwarf_sections(&fx);
    assert_eq!(
        debug_line_version(&secs),
        5,
        "guard: fixture must be DWARF 5"
    );
    let (count, addrs) = parsed_rows(&fx);
    assert!(
        count > 0 && !addrs.is_empty(),
        "DWARF 5 .debug_line ({} bytes) parsed to {count} rows / {} addresses, \
         while readelf decodes {:?} addresses from the same file",
        secs.debug_line.len(),
        addrs.len(),
        readelf_line_addresses(&fx.exe).map(|s| s.len())
    );
}

/// DEFECT — the COMPILER DEFAULT build (plain `cc -g`, no `-gdwarf-N`) has the
/// same empty line table, because that default is DWARF 5.
///
/// Kept separate from the version-pinned test on purpose: a reader could
/// dismiss "we do not support `-gdwarf-5`" as an exotic flag. This one passes
/// no version flag at all, which is what every real build does.
#[tokio::test(flavor = "multi_thread")]
async fn the_default_compiler_build_should_have_a_usable_line_table() {
    let fx = build_default();
    let secs = dwarf_sections(&fx);
    let version = debug_line_version(&secs);
    let (count, _) = parsed_rows(&fx);
    assert!(
        count > 0,
        "the compiler's default `cc -g` emitted .debug_line version {version} \
         ({} bytes) and the parser produced {count} rows",
        secs.debug_line.len()
    );
}

/// DEFECT — with DWARF 5 an address that demonstrably belongs to a function
/// maps to NO source location at all.
///
/// This is the consumer-visible face of the empty table: `source_at` on
/// `line_alpha`'s entry address — the same address `nm` prints and a
/// breakpoint fires at — answers `None`, while the identical source built with
/// `-gdwarf-4` answers line 2 of `linefixture.c`
/// (`dwarf4_maps_each_function_entry_to_its_own_source_line` passes).
#[tokio::test(flavor = "multi_thread")]
async fn dwarf5_should_map_a_function_address_to_its_source_line() {
    let fx = build_dwarf(5);
    let prov = symtab_provider(&fx);
    let addr = prov.lookup_name("line_alpha").expect("line_alpha").address;
    let table = DwarfParser::new(&dwarf_sections(&fx), false)
        .parse_line_table()
        .expect("parse line table");
    let loc = table
        .source_at(addr)
        .unwrap_or_else(|| panic!("DWARF 5: no line row covers line_alpha at {addr:#x}"));
    assert_eq!(loc.line, ALPHA_LINE);
    assert!(loc.file.ends_with(&fx.src_name));
}
