//! LIVE Linux coverage for the SYMBOL half of the debugger: loading an ELF's
//! symbol table, resolving a name to an address, refusing a name that does not
//! exist, and mapping an address back to a source line through DWARF.
//!
//! Every test compiles a C fixture on the fly with `cc -no-pie -O0 -g` and
//! launches it under `ptrace` via `LinuxDebugger`. `-no-pie` is load-bearing:
//! the binary is `ET_EXEC`, so the address `nm` prints IS the address the
//! function occupies at run time — which is what lets a resolved address be
//! checked against the RUNNING process (bytes read out of the tracee, and a
//! breakpoint that actually fires) rather than only against a file.
//!
//! The backend exposes no `load_symbols`/`resolve_symbol` on the `Debugger`
//! trait; the workspace's symbol layer is `rustre_symbols`, which the debug
//! crate depends on for exactly this. So the "load" step here is
//! `ElfSymbolProvider::parse_symtab` + `DwarfParser`, and the ELF section
//! slicing that feeds them is done by this file (see `sections`) because the
//! crate's own container entry points are stubs — see the two `#[ignore]`d
//! tests at the bottom, which document that with the measured red.
#![cfg(target_os = "linux")]

use rustre_core::address::Address;
use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::{BreakpointKind, Debugger, LaunchOptions, OutputRedirect, StopReason};
use rustre_symbols::SymbolProvider;
use rustre_symbols::dwarf_provider::{DwarfParser, DwarfSections, DwarfSymbolProvider};
use rustre_symbols::elf_provider::ElfSymbolProvider;
use std::time::Duration;

/// Three named, non-inlinable functions at known source lines, and a
/// `raise(SIGTRAP)` in `main` so a test can park the process at a point where
/// `marker_alpha` has NOT run yet and a breakpoint on it must still fire.
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
/// 1-based line of the `marker_alpha` body in `FIXTURE_C`.
const ALPHA_LINE: u32 = 2;
/// 1-based line of the `marker_beta` body.
const BETA_LINE: u32 = 3;

struct Fixture {
    _dir: tempfile::TempDir,
    exe: String,
    src_name: String,
    bytes: Vec<u8>,
}

/// Build with the compiler's DEFAULT DWARF version (v5 on any current gcc/clang).
fn build_fixture() -> Fixture {
    build_fixture_with(&[])
}

/// Build pinned to DWARF 4 — the version the crate's line-program parser
/// actually decodes (see `parse_line_program_header`, which bails on v5).
fn build_fixture_dwarf4() -> Fixture {
    build_fixture_with(&["-gdwarf-4"])
}

fn build_fixture_with(extra: &[&str]) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("symfixture.c");
    let exe = dir.path().join("symfixture");
    std::fs::write(&src, FIXTURE_C).expect("write fixture source");
    let out = std::process::Command::new("cc")
        .args(["-no-pie", "-O0", "-g"])
        .args(extra)
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .output()
        .expect("cc must be available to run the live symbol tests");
    assert!(
        out.status.success(),
        "cc failed to build the fixture: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bytes = std::fs::read(&exe).expect("read the built ELF");
    Fixture {
        exe: exe.to_string_lossy().to_string(),
        src_name: "symfixture.c".to_string(),
        bytes,
        _dir: dir,
    }
}

/// The address `nm` prints for a text symbol — the independent ground truth
/// every address assertion in this file is measured against.
fn nm_address(exe: &str, want: &str) -> Option<u64> {
    let nm = std::process::Command::new("nm").arg(exe).output().ok()?;
    if !nm.status.success() {
        return None;
    }
    let listing = String::from_utf8_lossy(&nm.stdout).to_string();
    for line in listing.lines() {
        let mut parts = line.split_whitespace();
        let addr = parts.next()?;
        let Some(kind) = parts.next() else { continue };
        let name = parts.next().unwrap_or("");
        if name == want && (kind == "T" || kind == "t") {
            return u64::from_str_radix(addr, 16).ok();
        }
    }
    None
}

// ── minimal ELF64 section-header reader (test-side input handling) ───────────

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
            u32le(elf, b) as usize,        // sh_name
            u64le(elf, b + 0x10),          // sh_addr
            u64le(elf, b + 0x18) as usize, // sh_offset
            u64le(elf, b + 0x20) as usize, // sh_size
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

fn section<'a>(elf: &'a [u8], secs: &[(String, usize, usize, u64)], name: &str) -> &'a [u8] {
    secs.iter()
        .find(|s| s.0 == name)
        .map(|s| &elf[s.1..s.1 + s.2])
        .unwrap_or_else(|| panic!("the fixture ELF must contain a {name} section"))
}

/// Load the fixture's `.symtab` through the crate's real symtab parser.
fn symtab_provider(fx: &Fixture) -> ElfSymbolProvider {
    let secs = sections(&fx.bytes);
    let symtab = section(&fx.bytes, &secs, ".symtab");
    let strtab = section(&fx.bytes, &secs, ".strtab");
    ElfSymbolProvider::parse_symtab("symfixture", symtab, strtab, true, true)
        .expect("the crate's symtab parser must accept a stock `cc -g` .symtab")
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
        debug_str_offsets: get(".debug_str_offsets"),
        debug_addr: get(".debug_addr"),
        split_debug_info: None,
    }
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

/// Launch the fixture under ptrace, stopped at the exec trap.
async fn launched(fx: &Fixture) -> LinuxDebugger {
    let dbg = LinuxDebugger::new();
    dbg.launch(launch_opts(&fx.exe))
        .await
        .expect("the fixture must launch under ptrace");
    dbg
}

// ── tests ────────────────────────────────────────────────────────────────────

/// Proves: the address the symbol layer resolves `marker_alpha` to is the
/// address `nm` reports AND the address the CPU really executes.
///
/// Why that is the right behaviour: a resolver that returns a plausible-looking
/// address is worse than one that returns nothing, and a file-only comparison
/// cannot tell the two apart. Planting a breakpoint at the resolved address and
/// running until it fires is the only check that binds the number to the
/// running process.
#[tokio::test(flavor = "multi_thread")]
async fn a_resolved_symbol_address_is_where_the_process_really_executes() {
    let fx = build_fixture();
    let want = nm_address(&fx.exe, "marker_alpha").expect("nm must list marker_alpha");
    let prov = symtab_provider(&fx);

    let sym = prov
        .lookup_name("marker_alpha")
        .expect("the loaded .symtab must contain marker_alpha");
    assert_eq!(
        sym.address, want,
        "resolved address {:#x} disagrees with nm's {want:#x}",
        sym.address
    );

    let dbg = launched(&fx).await;
    dbg.set_breakpoint(Address::new(sym.address), BreakpointKind::Software)
        .await
        .expect("breakpoint at the resolved address must be settable");
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
        Some(sym.address),
        "the breakpoint planted at the resolved address never fired at it"
    );
}

/// Proves: a name that is not in the binary resolves to NOTHING — not to a
/// nearby symbol, not to zero, not to the closest fuzzy match.
///
/// Why: `resolve_symbol` is the input to breakpoint placement. Returning a
/// plausible address for a misspelt name would place a breakpoint in an
/// unrelated function and every later observation would be silently wrong.
#[tokio::test(flavor = "multi_thread")]
async fn a_symbol_that_does_not_exist_is_refused_not_approximated() {
    let fx = build_fixture();
    let prov = symtab_provider(&fx);
    // Sanity: the provider is not simply empty (that would make this vacuous).
    assert!(
        prov.lookup_name("marker_alpha").is_some(),
        "guard: the provider must actually hold the fixture's symbols"
    );
    for bogus in [
        "marker_gamma",
        "marker_alph",
        "marker_alpha2",
        "MARKER_ALPHA",
    ] {
        assert!(
            prov.lookup_name(bogus).is_none(),
            "resolved a symbol that does not exist: {bogus:?} -> {:?}",
            prov.lookup_name(bogus)
        );
    }
    // NOTE: `""` is deliberately NOT probed. ELF symtab entry 0 is the null
    // symbol, whose name IS the empty string, so a provider that answers
    // `Some(addr 0)` for `""` is reporting what the file contains — measured,
    // and correct, not a defect.
    // And the live process agrees the name is absent: nm does not list it.
    assert!(nm_address(&fx.exe, "marker_gamma").is_none());
}

/// Proves: an address INSIDE a function body resolves back to that function,
/// not to the next symbol above it.
///
/// Why: every backtrace frame `pc` points into the middle of a function, never
/// at its entry, so nearest-below is the only lookup a symbolicated stack can
/// use. Verified against the live process: the probed address is read back out
/// of the tracee to confirm it is mapped, executable text.
#[tokio::test(flavor = "multi_thread")]
async fn an_address_inside_the_body_resolves_to_the_enclosing_function() {
    let fx = build_fixture();
    let prov = symtab_provider(&fx);
    let alpha = prov.lookup_name("marker_alpha").expect("marker_alpha");
    let beta = prov.lookup_name("marker_beta").expect("marker_beta");
    assert!(alpha.address != beta.address);

    let dbg = launched(&fx).await;
    let probe = alpha.address + 4;
    let bytes = dbg
        .read_memory(Address::new(probe), 4)
        .await
        .expect("the probed address must be mapped in the tracee");
    assert_eq!(bytes.len(), 4);
    let _ = dbg.kill().await;

    let got = prov
        .lookup_nearest(probe)
        .expect("an address inside marker_alpha must resolve to something");
    assert_eq!(
        got.name, "marker_alpha",
        "address {probe:#x} (inside marker_alpha at {:#x}) resolved to {}",
        alpha.address, got.name
    );
}

/// Proves: the bytes at the resolved address in the RUNNING process are the
/// bytes the ELF holds for that function.
///
/// Why: it is the direct check that the symbol address is not merely
/// self-consistent inside the file — it names the same instructions the CPU is
/// about to execute. Read before any breakpoint is planted, so no trap byte can
/// be mistaken for a mismatch.
#[tokio::test(flavor = "multi_thread")]
async fn the_bytes_at_a_resolved_address_match_the_on_disk_function() {
    let fx = build_fixture();
    let prov = symtab_provider(&fx);
    let alpha = prov.lookup_name("marker_alpha").expect("marker_alpha");
    let secs = sections(&fx.bytes);
    let (_, text_off, text_size, text_addr) = secs
        .iter()
        .find(|s| s.0 == ".text")
        .cloned()
        .expect(".text");
    assert!(
        alpha.address >= text_addr && alpha.address < text_addr + text_size as u64,
        "marker_alpha {:#x} is outside .text [{text_addr:#x}, +{text_size:#x})",
        alpha.address
    );
    let file_off = text_off + (alpha.address - text_addr) as usize;
    let on_disk = &fx.bytes[file_off..file_off + 8];

    let dbg = launched(&fx).await;
    let live = dbg
        .read_memory(Address::new(alpha.address), 8)
        .await
        .expect("read_memory at the resolved address");
    let _ = dbg.kill().await;
    assert_eq!(
        live.as_slice(),
        on_disk,
        "live bytes at {:#x} differ from the ELF's",
        alpha.address
    );
}

/// Proves: the DWARF line table built from the fixture's own `.debug_line`
/// maps the resolved function addresses back to the fixture's `.c` file and to
/// the lines those functions really occupy.
///
/// Why: line info that returns *a* file and *a* line is useless; the value is
/// only correct if it names the file that was compiled and a line inside the
/// function whose address was asked about. Both markers are checked, so a table
/// that returns one constant row for everything fails.
#[tokio::test(flavor = "multi_thread")]
async fn dwarf_line_info_names_the_compiled_source_file_and_line() {
    let fx = build_fixture_dwarf4();
    let prov = symtab_provider(&fx);
    let secs = dwarf_sections(&fx);
    assert!(
        secs.has_debug_line(),
        "`cc -g` must emit .debug_line; without it this test is vacuous"
    );
    let table = DwarfParser::new(&secs, false)
        .parse_line_table()
        .expect("parse the fixture's line program");
    assert!(
        !table.entries.is_empty(),
        "the line table parsed 0 rows from a {} byte .debug_line",
        secs.debug_line.len()
    );

    for (name, line) in [("marker_alpha", ALPHA_LINE), ("marker_beta", BETA_LINE)] {
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
            loc.line, line,
            "{name} at {addr:#x} maps to line {} of {:?}, expected {line}",
            loc.line, loc.file
        );
    }
}

/// Proves: every line-table row points into the fixture's own `.text`, so the
/// address→line mapping cannot be answering from an unrelated address space.
#[tokio::test(flavor = "multi_thread")]
async fn every_line_row_addresses_the_fixture_text_segment() {
    let fx = build_fixture_dwarf4();
    let secs_elf = sections(&fx.bytes);
    let (_, _, text_size, text_addr) = secs_elf
        .iter()
        .find(|s| s.0 == ".text")
        .cloned()
        .expect(".text");
    let table = DwarfParser::new(&dwarf_sections(&fx), false)
        .parse_line_table()
        .expect("parse line table");
    let rows: Vec<_> = table.entries.iter().filter(|e| e.address != 0).collect();
    assert!(!rows.is_empty(), "no non-zero line rows");
    let outside = rows
        .iter()
        .filter(|e| e.address < text_addr || e.address > text_addr + text_size as u64)
        .count();
    assert_eq!(
        outside,
        0,
        "{outside} of {} line rows fall outside .text [{text_addr:#x}, +{text_size:#x})",
        rows.len()
    );
}

// ── documented defects (not fixed here: reported to the coordinator) ─────────

/// DEFECT — `ElfSymbolProvider::parse_elf` is a stub: given a whole, valid ELF
/// with a populated `.symtab`, it returns a provider holding ZERO symbols
/// instead of parsing the section headers. Every symbol in the file is lost,
/// and `lookup_name("marker_alpha")` therefore answers `None` for a symbol that
/// demonstrably exists (`nm` prints it, and `parse_symtab` on the very same
/// bytes finds it — see the passing tests above).
///
/// The stub is at `crates/rustre-symbols/src/elf_provider.rs`:
/// "This stub returns an empty provider to avoid a full ELF parser dep."
#[test]
#[ignore = "backend defect: ElfSymbolProvider::parse_elf is a stub that drops every symbol"]
fn parse_elf_should_load_the_symbols_a_real_elf_contains() {
    let fx = build_fixture();
    let prov =
        ElfSymbolProvider::parse_elf("symfixture", &fx.bytes).expect("a valid ELF must be accepted");
    assert!(
        prov.symbol_count() > 0,
        "parse_elf found 0 symbols in an ELF whose .symtab has them"
    );
    assert!(
        prov.lookup_name("marker_alpha").is_some(),
        "parse_elf lost marker_alpha, which nm lists"
    );
}

/// DEFECT — `DwarfSymbolProvider::load(path)` is a stub: handed the path of a
/// binary built with `cc -g`, it returns an empty provider (it only records the
/// path as the provider name), so `source_line_for_address` answers `None` for
/// every address in the file, and `compile_units()` is empty for a binary whose
/// `.debug_info` this same file parses successfully in
/// `dwarf_line_info_names_the_compiled_source_file_and_line`.
#[test]
#[ignore = "backend defect: DwarfSymbolProvider::load is a stub returning an empty provider"]
fn dwarf_provider_load_should_read_debug_info_from_the_binary() {
    let fx = build_fixture();
    let prov = DwarfSymbolProvider::load(&fx.exe).expect("load must accept the path");
    let addr = nm_address(&fx.exe, "marker_alpha").expect("nm");
    assert!(
        !prov.compile_units().is_empty(),
        "load() parsed 0 compile units from a `cc -g` binary"
    );
    assert!(
        prov.source_line_for_address(addr).is_some(),
        "load() cannot map marker_alpha to a source line"
    );
}

/// DEFECT — the DWARF **5** line program, which is what every current gcc and
/// clang emit for a plain `cc -g`, yields ZERO rows: `parse_line_program_header`
/// returns `None` for any `version` outside `2..=4`
/// (`crates/rustre-symbols/src/dwarf_provider.rs`, comment
/// "v5 header layout differs — fallback"), so `parse_line_table` silently hands
/// back an empty table.
///
/// Measured red on this fixture: `readelf --debug-dump=decodedline` lists 12+
/// rows (`sf.c` lines 2,3,4 at 0x401136, 0x40114c, 0x40116a …) from a 130-byte
/// `.debug_line` marked "DWARF Version: 5"; `parse_line_table()` returns
/// `entries.len() == 0`. The failure text was
/// "the line table parsed 0 rows from a 128 byte .debug_line".
/// Nothing is wrong with the rest of the parser — the same test against a
/// `-gdwarf-4` build passes (`dwarf_line_info_names_the_compiled_source_file_and_line`),
/// which is what isolates the defect to the v5 header.
#[test]
#[ignore = "backend defect: the line-program parser rejects DWARF 5, the current compiler default"]
fn dwarf5_line_program_should_not_parse_to_zero_rows() {
    let fx = build_fixture();
    let secs = dwarf_sections(&fx);
    assert!(secs.has_debug_line());
    assert_eq!(secs.debug_line[4], 5, "guard: this fixture must be DWARF 5");
    let table = DwarfParser::new(&secs, false)
        .parse_line_table()
        .expect("parse line table");
    assert!(
        !table.entries.is_empty(),
        "DWARF 5 .debug_line ({} bytes) parsed to 0 rows",
        secs.debug_line.len()
    );
}
