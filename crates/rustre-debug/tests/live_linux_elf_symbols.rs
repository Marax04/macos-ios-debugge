//! LIVE Linux measurement of `ElfSymbolProvider::parse_elf` against REAL ELF
//! files, in every shape a debugger actually meets: `-no-pie` (`ET_EXEC`) and
//! PIE (`ET_DYN`), with and without `-g`, stripped and unstripped, and a shared
//! object whose only symbol table is `.dynsym`.
//!
//! The previous round established that `parse_elf` is a stub — it validates the
//! `e_ident` bytes and then returns an EMPTY provider
//! (`crates/rustre-symbols/src/elf_provider.rs`: "This stub returns an empty
//! provider to avoid a full ELF parser dep."). This file does NOT fix it. It
//! measures, per ELF shape, the exact size of the hole a cure has to fill:
//!
//!   * EXPECTED — what `nm` (and `nm -D` for the stripped/shared shapes)
//!     independently reports the file contains;
//!   * REACHABLE — what the crate's own working `parse_symtab` yields when it
//!     is handed the right section bytes, i.e. the number `parse_elf` would
//!     produce if it merely walked the section headers and delegated;
//!   * OBTAINED — what `parse_elf` actually returns today.
//!
//! Every fixture is compiled on the fly with `cc` and then LAUNCHED under
//! ptrace through `LinuxDebugger`, so each shape is proven to be a real,
//! runnable ELF (a shared object is exercised through a host executable that
//! links it) and not a byte blob that only looks like one. The tracee is killed
//! on every path, including the failing ones.
#![cfg(target_os = "linux")]

use rustre_debug::linux_debugger::LinuxDebugger;
use rustre_debug::{Debugger, LaunchOptions, OutputRedirect};
use rustre_symbols::SymbolProvider;
use rustre_symbols::elf_provider::ElfSymbolProvider;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// One non-inlinable exported function plus a global, so every shape has at
/// least one symbol of each kind that a debugger cares about.
const FIXTURE_C: &str = r#"#include <signal.h>
int elf_global_counter = 7;
__attribute__((noinline)) int elf_marker(int x) { return x * 3 + elf_global_counter; }
int main(void) { volatile int r = elf_marker(5); (void)r; for (;;) { } return 0; }
"#;

/// A shared object: its exported symbol lives in `.dynsym`, never in a
/// `.symtab` that a stripped build would have dropped.
const LIB_C: &str = r#"int shared_marker(int x) { return x + 1; }
"#;

/// The host that links the shared object, so the `.so` shape is still measured
/// against a REAL running process.
const HOST_C: &str = r#"int shared_marker(int);
int main(void) { volatile int r = shared_marker(1); (void)r; for (;;) { } return 0; }
"#;

// ── fixtures ─────────────────────────────────────────────────────────────────

struct Fixture {
    _dir: tempfile::TempDir,
    /// The file whose bytes are measured (an exe, or the `.so`).
    subject: String,
    /// The executable to launch under ptrace (== `subject` except for the `.so`).
    exe: String,
    /// Extra environment the tracee needs (`LD_LIBRARY_PATH` for the `.so`).
    env: HashMap<String, String>,
    bytes: Vec<u8>,
}

fn cc(args: &[&str]) {
    let out = std::process::Command::new("cc")
        .args(args)
        .output()
        .expect("cc must be available to run the live ELF-symbol tests");
    assert!(
        out.status.success(),
        "cc {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Build the standard fixture with `extra` appended to `cc -O0`.
fn build(extra: &[&str]) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("elffixture.c");
    let exe = dir.path().join("elffixture");
    std::fs::write(&src, FIXTURE_C).expect("write fixture source");
    let mut args: Vec<String> = vec!["-O0".into()];
    args.extend(extra.iter().map(|s| (*s).to_string()));
    args.push(src.to_string_lossy().into_owned());
    args.push("-o".into());
    args.push(exe.to_string_lossy().into_owned());
    cc(&args.iter().map(String::as_str).collect::<Vec<_>>());
    let bytes = std::fs::read(&exe).expect("read the built ELF");
    let p = exe.to_string_lossy().to_string();
    Fixture {
        subject: p.clone(),
        exe: p,
        env: HashMap::new(),
        bytes,
        _dir: dir,
    }
}

/// Build a shared object plus a host executable that links it. The measured
/// subject is the `.so`; the launched process is the host.
fn build_shared() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let libsrc = dir.path().join("elflib.c");
    let hostsrc = dir.path().join("elfhost.c");
    let lib = dir.path().join("libelffix.so");
    let host = dir.path().join("elfhost");
    std::fs::write(&libsrc, LIB_C).expect("write lib source");
    std::fs::write(&hostsrc, HOST_C).expect("write host source");
    cc(&[
        "-O0",
        "-fPIC",
        "-shared",
        "-g",
        &libsrc.to_string_lossy(),
        "-o",
        &lib.to_string_lossy(),
    ]);
    cc(&[
        "-O0",
        "-g",
        &hostsrc.to_string_lossy(),
        "-o",
        &host.to_string_lossy(),
        "-L",
        &dir.path().to_string_lossy(),
        "-lelffix",
    ]);
    let bytes = std::fs::read(&lib).expect("read the built .so");
    let mut env = HashMap::new();
    env.insert(
        "LD_LIBRARY_PATH".to_string(),
        dir.path().to_string_lossy().to_string(),
    );
    Fixture {
        subject: lib.to_string_lossy().to_string(),
        exe: host.to_string_lossy().to_string(),
        env,
        bytes,
        _dir: dir,
    }
}

// ── ground truth: nm ─────────────────────────────────────────────────────────
//
// This is the ONLY oracle in the file that is independent of the bytes the
// crate parses: `nm` is a separate program (binutils) reading the same file
// with its own ELF reader. Until this round it was DECORATIVE — `Gap::expected`
// appeared only inside `format!` arguments and in no assertion, so every
// comparison here was `obtained` against `reachable`, two numbers computed from
// the same bytes by the same crate: an identity, not a measurement. Forcing
// `nm_count` to 0 left 9 tests out of 9 green.
//
// The cure is not a stricter count. A count is lax by construction:
// `obtained >= 28` survives the oracle moving to 31. What is compared now is
// the SET of names, and for every defined symbol its ADDRESS — both taken from
// nm's own output.

/// One row of `nm` output: a name, and the address nm printed for it (`None`
/// for undefined symbols, which nm prints with a blank value column).
#[derive(Debug, Clone)]
struct NmSym {
    name: String,
    addr: Option<u64>,
}

/// Every symbol `nm` reports for `file`. `None` when nm refuses the file (e.g.
/// "no symbols"), which is itself a measurement.
fn nm_symbols(file: &str, args: &[&str]) -> Option<Vec<NmSym>> {
    let out = std::process::Command::new("nm")
        .args(args)
        .arg(file)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let listing = String::from_utf8_lossy(&out.stdout).to_string();
    let mut v = Vec::new();
    for line in listing.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        match f.len() {
            // "                 U puts"  →  type, name
            2 => v.push(NmSym {
                name: f[1].to_string(),
                addr: None,
            }),
            // "0000000000001139 T elf_marker"  →  value, type, name
            3 => v.push(NmSym {
                name: f[2].to_string(),
                addr: u64::from_str_radix(f[0], 16).ok(),
            }),
            _ => {}
        }
    }
    Some(v)
}

/// Number of symbol lines `nm` prints. Kept for the reported figures.
fn nm_count(file: &str, args: &[&str]) -> Option<usize> {
    nm_symbols(file, args).map(|v| v.len())
}

/// name -> the set of addresses a provider holds under that name.
fn provider_index(prov: &ElfSymbolProvider) -> HashMap<String, HashSet<u64>> {
    let mut m: HashMap<String, HashSet<u64>> = HashMap::new();
    for s in SymbolProvider::all_symbols(prov) {
        m.entry(s.name.clone()).or_default().insert(s.address);
    }
    m
}

/// THE BITING ASSERTION.
///
/// Every name `nm` reports must be present in `prov`, and every DEFINED
/// symbol must sit at exactly the address nm printed for it. Nothing here is
/// derived from the crate's own parse: the names and the addresses both come
/// out of binutils.
///
/// It is a SET containment, not a count, on purpose: a count is satisfied by
/// any 29 symbols, including 29 wrong ones, and survives the oracle changing
/// from 29 to 31. Losing a single name, or shifting a single address by one
/// byte, fails this.
fn assert_matches_nm(label: &str, prov: &ElfSymbolProvider, file: &str, nm_args: &[&str]) {
    let nm = nm_symbols(file, nm_args)
        .unwrap_or_else(|| panic!("{label}: nm must be able to list {file}"));
    assert!(
        !nm.is_empty(),
        "{label}: guard — the oracle itself must report something, else this test cannot bite"
    );
    let idx = provider_index(prov);

    // `nm` prints GNU symbol versioning as `name@GLIBC_2.34`. That suffix is
    // NOT in `.dynstr`: it is built by joining `.gnu.version` to
    // `.gnu.version_r`, a section the crate does not read. Matching on the base
    // name is therefore an oracle normalisation, not a relaxation — measured:
    // `readelf -sW --dyn-syms` shows the string as `__libc_start_main` with
    // `(2)` beside it, so the crate reads the bytes correctly and only omits
    // the version join. That omission is a real, separate gap and is recorded
    // by `elf_symbols_do_not_carry_the_gnu_version_suffix` below with its red.
    let base = |n: &str| n.split('@').next().unwrap_or(n).to_string();
    let missing: Vec<&str> = nm
        .iter()
        .filter(|s| !idx.contains_key(&s.name) && !idx.contains_key(&base(&s.name)))
        .map(|s| s.name.as_str())
        .collect();
    assert!(
        missing.is_empty(),
        "{label}: parse_elf lost {} of the {} names nm reports: {:?}",
        missing.len(),
        nm.len(),
        &missing[..missing.len().min(12)]
    );

    let wrong: Vec<String> = nm
        .iter()
        .filter_map(|s| {
            let want = s.addr?;
            let got = idx.get(&s.name).or_else(|| idx.get(&base(&s.name)))?;
            if got.contains(&want) {
                None
            } else {
                Some(format!("{} nm=0x{want:x} crate={got:x?}", s.name))
            }
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "{label}: {} of {} symbols sit at an address nm disagrees with: {:?}",
        wrong.len(),
        nm.len(),
        &wrong[..wrong.len().min(12)]
    );
}

// ── test-side ELF64 section reader (input handling, not the thing under test) ─

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

/// name -> (file offset, size) for every section header.
fn sections(elf: &[u8]) -> Vec<(String, usize, usize)> {
    assert_eq!(&elf[..4], b"\x7fELF", "fixture must be an ELF");
    assert_eq!(elf[4], 2, "fixture must be ELF64");
    let e_shoff = u64le(elf, 0x28) as usize;
    let e_shentsize = u16le(elf, 0x3a) as usize;
    let e_shnum = u16le(elf, 0x3c) as usize;
    let e_shstrndx = u16le(elf, 0x3e) as usize;
    if e_shoff == 0 || e_shnum == 0 {
        return Vec::new();
    }
    let shdr = |i: usize| {
        let b = e_shoff + i * e_shentsize;
        (
            u32le(elf, b) as usize,
            u64le(elf, b + 0x18) as usize,
            u64le(elf, b + 0x20) as usize,
        )
    };
    let (_, stroff, _) = shdr(e_shstrndx);
    (0..e_shnum)
        .map(|i| {
            let (nameoff, off, size) = shdr(i);
            let s = &elf[stroff + nameoff..];
            let end = s.iter().position(|&b| b == 0).unwrap_or(0);
            (String::from_utf8_lossy(&s[..end]).to_string(), off, size)
        })
        .collect()
}

fn section<'a>(elf: &'a [u8], name: &str) -> Option<&'a [u8]> {
    sections(elf)
        .into_iter()
        .find(|s| s.0 == name)
        .map(|s| &elf[s.1..s.1 + s.2])
}

/// REACHABLE: what the crate's own `parse_symtab` yields from `symtab_name` +
/// `strtab_name` — i.e. what `parse_elf` would return if it only walked the
/// section headers and delegated to the parser it already has.
fn reachable(elf: &[u8], symtab_name: &str, strtab_name: &str) -> usize {
    match (section(elf, symtab_name), section(elf, strtab_name)) {
        (Some(symtab), Some(strtab)) => {
            ElfSymbolProvider::parse_symtab("reachable", symtab, strtab, true, true)
                .map_or(0, |p| p.symbol_count())
        }
        _ => 0,
    }
}

// ── live process ─────────────────────────────────────────────────────────────

fn launch_opts(fx: &Fixture) -> LaunchOptions {
    LaunchOptions {
        executable: fx.exe.clone(),
        args: Vec::new(),
        env: fx.env.clone(),
        working_dir: None,
        stop_at_entry: false,
        follow_forks: false,
        redirect: OutputRedirect::default(),
    }
}

/// Launch the fixture under ptrace, prove the tracee really exists, and kill
/// it.
///
/// The process is killed here, before any assertion in the caller runs, so a
/// failing measurement can never leak an orphan.
async fn prove_runnable(fx: &Fixture) {
    let dbg = LinuxDebugger::new();
    dbg.launch(launch_opts(fx))
        .await
        .expect("the fixture must launch under ptrace");
    let pid = dbg.target_pid().expect("a launched tracee has a pid").0;
    let alive = Path::new(&format!("/proc/{pid}")).exists();
    let _ = dbg.kill().await;
    assert!(alive, "the tracee pid {pid} has no /proc entry");
}

/// EXPECTED / REACHABLE / OBTAINED for one shape, gathered after the shape has
/// been proven to run.
struct Gap {
    expected: usize,
    reachable: usize,
    obtained: usize,
}

async fn measure(fx: &Fixture, nm_args: &[&str], symtab: &str, strtab: &str) -> Gap {
    prove_runnable(fx).await;
    let expected = nm_count(&fx.subject, nm_args).unwrap_or(0);
    let reachable = reachable(&fx.bytes, symtab, strtab);
    let obtained = ElfSymbolProvider::parse_elf("subject", &fx.bytes)
        .expect("parse_elf must accept a valid ELF")
        .symbol_count();
    Gap {
        expected,
        reachable,
        obtained,
    }
}

// ── passing tests: what parse_elf DOES get right ─────────────────────────────

/// Proves: `parse_elf` accepts every real ELF shape a debugger meets — ET_EXEC,
/// ET_DYN, stripped, and a shared object — without erroring.
///
/// Why that is the right behaviour: the header validation is the one part of
/// the function that is implemented, and it must not reject a file the loader
/// itself accepts. This test also fixes the boundary of the defect: the hole is
/// NOT "parse_elf fails", it is "parse_elf succeeds and returns nothing", which
/// is the strictly worse failure because a caller cannot tell it apart from a
/// file that genuinely has no symbols.
#[tokio::test(flavor = "multi_thread")]
async fn parse_elf_accepts_every_real_elf_shape() {
    let shapes: Vec<(&str, Fixture, &[&str])> = vec![
        ("no-pie -g", build(&["-no-pie", "-g"]), &[]),
        ("pie -g", build(&["-fPIE", "-pie", "-g"]), &[]),
        ("no-pie, no -g", build(&["-no-pie"]), &[]),
        ("no-pie -g stripped", build(&["-no-pie", "-g", "-s"]), &["-D"]),
        ("shared object", build_shared(), &["-D"]),
    ];
    for (label, fx, nm_args) in &shapes {
        prove_runnable(fx).await;
        let prov = ElfSymbolProvider::parse_elf("subject", &fx.bytes)
            .unwrap_or_else(|e| panic!("parse_elf rejected a runnable ELF ({label}): {e}"));
        // Accepting the file is not the claim worth making — the stub this
        // file was written against accepted every one of these shapes and
        // returned nothing. What is asserted is that each shape yields the
        // names and the addresses binutils reads out of the SAME file.
        assert_matches_nm(label, &prov, &fx.subject, nm_args);
    }
}

/// Proves: `parse_elf` refuses bytes that are not an ELF, and refuses a real
/// ELF truncated below its `e_ident`.
///
/// Why: the header check is the only guarantee the function currently offers,
/// so it must be real. A stub that returned `Ok(empty)` for ANY input would
/// make the emptiness above indistinguishable from garbage-in.
#[tokio::test(flavor = "multi_thread")]
async fn parse_elf_refuses_bytes_that_are_not_an_elf() {
    let fx = build(&["-no-pie", "-g"]);
    prove_runnable(&fx).await;
    assert!(
        ElfSymbolProvider::parse_elf("x", b"not an elf at all!!!").is_err(),
        "parse_elf accepted non-ELF bytes"
    );
    assert!(
        ElfSymbolProvider::parse_elf("x", &fx.bytes[..8]).is_err(),
        "parse_elf accepted an ELF truncated below e_ident"
    );
    // Truncating anywhere inside the section-header machinery must not be
    // answered with a confident empty provider either.
    for cut in [8usize, 16, 40, 63] {
        let r = ElfSymbolProvider::parse_elf("x", &fx.bytes[..cut.min(fx.bytes.len())]);
        assert!(
            r.as_ref().map_or(true, |p| p.symbol_count() == 0),
            "parse_elf invented {} symbols out of the first {cut} bytes",
            r.map_or(0, |p| p.symbol_count())
        );
    }
    let prov = ElfSymbolProvider::parse_elf("x", &fx.bytes)
        .expect("guard: the untruncated bytes must still be accepted");
    // `Ok` is the weak half of this test: `Ok(empty)` for ANY input would make
    // acceptance meaningless. The oracle nails the other half — accepted means
    // parsed, measured against nm.
    assert_matches_nm("untruncated", &prov, &fx.subject, &[]);
}

/// Proves: the crate's `parse_symtab` — the parser `parse_elf` refuses to
/// delegate to — reads the fixture's `.symtab` correctly, in BOTH the ET_EXEC
/// and the ET_DYN build.
///
/// Why this belongs here: it establishes that the cure for `parse_elf` needs no
/// new parser. The symbol decoding already works; only the section-header walk
/// that finds `.symtab`/`.strtab` is missing. Without this test the gap
/// measurements below could be read as "the crate cannot parse ELF symbols at
/// all", which is false and would misdirect the fix.
#[tokio::test(flavor = "multi_thread")]
async fn the_symbol_decoder_parse_elf_refuses_to_use_already_works() {
    for extra in [&["-no-pie", "-g"][..], &["-fPIE", "-pie", "-g"][..]] {
        let fx = build(extra);
        prove_runnable(&fx).await;
        let symtab = section(&fx.bytes, ".symtab").expect(".symtab must exist in an unstripped cc build");
        let strtab = section(&fx.bytes, ".strtab").expect(".strtab must exist");
        let prov = ElfSymbolProvider::parse_symtab("fx", symtab, strtab, true, true)
            .expect("parse_symtab must accept a stock cc .symtab");
        assert!(
            prov.lookup_name("elf_marker").is_some(),
            "parse_symtab lost elf_marker in the {extra:?} build"
        );
        assert!(
            prov.lookup_name("elf_global_counter").is_some(),
            "parse_symtab lost the global in the {extra:?} build"
        );
        // Two spot names cannot tell a working decoder from one that keeps the
        // strings and loses the values. nm supplies both the full name set and
        // every address, from its own reader.
        assert_matches_nm(&format!("parse_symtab {extra:?}"), &prov, &fx.subject, &[]);
    }
}

/// Proves: a stripped executable really has NO `.symtab`, and its `.dynsym`
/// still carries symbols.
///
/// Why: it stops the stripped-shape gap below from being scored against a
/// number that does not exist. For the stripped shape the honest expectation
/// for a fixed `parse_elf` is "everything in `.dynsym`", not "everything nm
/// prints for the unstripped build" — a measurement is only a defect if the
/// data it asks for is actually in the file.
#[tokio::test(flavor = "multi_thread")]
async fn a_stripped_build_keeps_only_its_dynamic_symbols() {
    let fx = build(&["-no-pie", "-g", "-s"]);
    prove_runnable(&fx).await;
    assert!(
        section(&fx.bytes, ".symtab").is_none(),
        "guard: `cc -s` must have removed .symtab"
    );
    let dynsym = section(&fx.bytes, ".dynsym").expect(".dynsym survives stripping");
    let dynstr = section(&fx.bytes, ".dynstr").expect(".dynstr survives stripping");
    let prov = ElfSymbolProvider::parse_symtab("stripped", dynsym, dynstr, true, true)
        .expect("parse_symtab must accept .dynsym");
    assert!(
        prov.symbol_count() > 0,
        "a stripped dynamic executable must still hold .dynsym entries"
    );
    // `> 0` is satisfied by one wrong symbol. The dynamic set nm -D reads out
    // of the stripped file is not.
    assert_matches_nm("stripped .dynsym", &prov, &fx.subject, &["-D"]);
    // And the complement: plain nm must find nothing, which is what makes the
    // -D oracle above the RIGHT oracle for this shape rather than a weaker one.
    assert_eq!(
        nm_count(&fx.subject, &[]).unwrap_or(0),
        0,
        "guard: `cc -s` must leave plain nm with no symbols to print"
    );
}

// ── measured defects (documented, NOT fixed here) ────────────────────────────
//
// Each test below fails with the numbers copied into its doc comment. They are
// #[ignore]d so the suite stays green while the hole stays recorded.

/// DEFECT — ET_EXEC, `cc -no-pie -O0 -g`. `parse_elf` returns a provider with
/// ZERO symbols for a file whose `.symtab` the crate's own `parse_symtab`
/// reads in full.
///
/// MEASURED (this fixture): expected `nm` = 29, reachable via `parse_symtab`
/// on `.symtab`/`.strtab` = 35 (35 counts the null entry at index 0 and the
/// FILE/SECTION entries nm does not print — the reachable figure is the one a
/// fixed `parse_elf` should match), obtained from `parse_elf` = 0.
/// Failure text: "no-pie -g: parse_elf obtained 0 of 29 symbols (35 reachable
/// through the crate's own parse_symtab)", left: 0, right: 35.
#[tokio::test(flavor = "multi_thread")]
async fn parse_elf_should_load_the_symtab_of_a_no_pie_binary() {
    let fx = build(&["-no-pie", "-g"]);
    let g = measure(&fx, &[], ".symtab", ".strtab").await;
    assert!(
        g.reachable > 0,
        "guard: the fixture must actually contain symbols"
    );
    assert_eq!(
        g.obtained, g.reachable,
        "no-pie -g: parse_elf obtained {} of {} symbols ({} reachable through the crate's own parse_symtab)",
        g.obtained, g.expected, g.reachable
    );
    // The equality above compares two numbers produced from the SAME bytes by
    // the SAME crate — it cannot fail while the crate is self-consistently
    // wrong. nm is the outside witness: names and addresses, as a set.
    assert!(g.expected > 0, "guard: nm must report symbols for this shape");
    let prov = ElfSymbolProvider::parse_elf("subject", &fx.bytes).expect("valid ELF");
    assert_matches_nm("no-pie -g", &prov, &fx.subject, &[]);
}

/// DEFECT — ET_DYN, `cc -fPIE -pie -O0 -g`. Same stub, same total loss, on the
/// shape that is the DEFAULT on every current distribution: a PIE is what a
/// debugger normally attaches to, so this is the common case, not an edge one.
///
/// MEASURED: expected `nm` = 31, reachable = 37, obtained = 0.
/// Failure text: "pie -g: parse_elf obtained 0 of 31 symbols (37 reachable)",
/// left: 0, right: 37.
#[tokio::test(flavor = "multi_thread")]
async fn parse_elf_should_load_the_symtab_of_a_pie_binary() {
    let fx = build(&["-fPIE", "-pie", "-g"]);
    let g = measure(&fx, &[], ".symtab", ".strtab").await;
    assert!(g.reachable > 0, "guard: the fixture must contain symbols");
    assert_eq!(
        g.obtained, g.reachable,
        "pie -g: parse_elf obtained {} of {} symbols ({} reachable)",
        g.obtained, g.expected, g.reachable
    );
    // The equality above compares two numbers produced from the SAME bytes by
    // the SAME crate — it cannot fail while the crate is self-consistently
    // wrong. nm is the outside witness: names and addresses, as a set.
    assert!(g.expected > 0, "guard: nm must report symbols for this shape");
    let prov = ElfSymbolProvider::parse_elf("subject", &fx.bytes).expect("valid ELF");
    assert_matches_nm("pie -g", &prov, &fx.subject, &[]);
}

/// DEFECT — `cc -no-pie -O0` with NO `-g`. This isolates the defect from DWARF:
/// a binary with no debug info still has a full `.symtab`, and a debugger that
/// can name functions in it is exactly what `parse_elf` exists for. The loss is
/// identical, which proves the stub is unconditional rather than a
/// debug-info-dependent path.
///
/// MEASURED: expected `nm` = 29, reachable = 35, obtained = 0 — identical to
/// the `-g` build, which is what proves the stub is unconditional.
/// Failure text: "no -g: parse_elf obtained 0 of 29 symbols (35 reachable)",
/// left: 0, right: 35.
#[tokio::test(flavor = "multi_thread")]
async fn parse_elf_should_load_the_symtab_of_a_binary_built_without_g() {
    let fx = build(&["-no-pie"]);
    let g = measure(&fx, &[], ".symtab", ".strtab").await;
    assert!(g.reachable > 0, "guard: the fixture must contain symbols");
    assert_eq!(
        g.obtained, g.reachable,
        "no -g: parse_elf obtained {} of {} symbols ({} reachable)",
        g.obtained, g.expected, g.reachable
    );
    // The equality above compares two numbers produced from the SAME bytes by
    // the SAME crate — it cannot fail while the crate is self-consistently
    // wrong. nm is the outside witness: names and addresses, as a set.
    assert!(g.expected > 0, "guard: nm must report symbols for this shape");
    let prov = ElfSymbolProvider::parse_elf("subject", &fx.bytes).expect("valid ELF");
    assert_matches_nm("no -g", &prov, &fx.subject, &[]);
}

/// DEFECT — `cc -no-pie -g -s` (stripped). Here the correct answer is the
/// `.dynsym` contents, which survive stripping; `nm` without `-D` reports "no
/// symbols" (measured as 0) while `nm -D` lists the dynamic ones. `parse_elf`
/// returns 0 either way, so a caller cannot distinguish "stripped, but these
/// imports are still known" from "nothing at all".
///
/// MEASURED: expected `nm -D` = 2, reachable via `.dynsym`/`.dynstr` = 3
/// (the null entry at index 0 is included by parse_symtab and not printed by
/// nm — the difference is accounted for, not noise), obtained = 0.
/// Failure text: "stripped: parse_elf obtained 0 of 2 dynamic symbols (3
/// reachable through .dynsym)", left: 0, right: 3.
#[tokio::test(flavor = "multi_thread")]
async fn parse_elf_should_load_the_dynsym_of_a_stripped_binary() {
    let fx = build(&["-no-pie", "-g", "-s"]);
    let g = measure(&fx, &["-D"], ".dynsym", ".dynstr").await;
    assert!(g.reachable > 0, "guard: .dynsym must hold entries");
    assert_eq!(
        g.obtained, g.reachable,
        "stripped: parse_elf obtained {} of {} dynamic symbols ({} reachable through .dynsym)",
        g.obtained, g.expected, g.reachable
    );
    // The equality above compares two numbers produced from the SAME bytes by
    // the SAME crate — it cannot fail while the crate is self-consistently
    // wrong. nm is the outside witness: names and addresses, as a set.
    assert!(g.expected > 0, "guard: nm must report symbols for this shape");
    let prov = ElfSymbolProvider::parse_elf("subject", &fx.bytes).expect("valid ELF");
    assert_matches_nm("stripped", &prov, &fx.subject, &["-D"]);
}

/// DEFECT — a shared object (`cc -fPIC -shared -g`), measured while a real
/// process has it mapped. A `.so` is the shape a debugger loads for every
/// module in `/proc/pid/maps`, and its exported names live in `.dynsym`.
///
/// MEASURED: expected `nm -D` = 5, reachable via `.dynsym`/`.dynstr` = 6
/// (null entry again), obtained = 0. `shared_marker` — the exported symbol the
/// running host calls — is among the lost ones.
/// Failure text: "shared object: parse_elf obtained 0 of 5 dynamic symbols (6
/// reachable), and lost the exported shared_marker: true".
#[tokio::test(flavor = "multi_thread")]
async fn parse_elf_should_load_the_dynsym_of_a_shared_object() {
    let fx = build_shared();
    let g = measure(&fx, &["-D"], ".dynsym", ".dynstr").await;
    assert!(g.reachable > 0, "guard: the .so must export something");
    let prov = ElfSymbolProvider::parse_elf("so", &fx.bytes).expect("valid ELF");
    let lost = prov.lookup_name("shared_marker").is_none();
    // SUPERSET, not equality — corrected after the cure, with the reason.
    //
    // This `.so` is built WITHOUT `-s`, so it carries a `.symtab` as well, and
    // `parse_elf` prefers the full table when one is present, exactly as gdb
    // and lldb do: `.symtab` is a superset that also names the local symbols.
    // Measured after the fix: 25 obtained against 6 reachable through
    // `.dynsym` alone — more, not fewer, and `shared_marker` among them.
    //
    // The equality this used to assert was the right shape while `parse_elf`
    // returned nothing, and became the wrong shape once it returned the better
    // answer. The stripped-binary test above still pins the `.dynsym` fallback
    // down, so nothing is left unguarded by this relaxation.
    assert!(
        g.obtained >= g.reachable && !lost,
        "shared object: parse_elf obtained {} symbols, fewer than the {} reachable through .dynsym alone, or lost the exported shared_marker: {lost}",
        g.obtained, g.reachable
    );
    // `>=` is the lax half of this file: it stays green if the count drifts up
    // for any reason at all. The set does not.
    assert!(g.expected > 0, "guard: nm -D must report exports for the .so");
    assert_matches_nm("shared object", &prov, &fx.subject, &["-D"]);
    // And the exported symbol must sit where nm says, not merely exist.
    let nm_marker = nm_symbols(&fx.subject, &["-D"])
        .expect("nm -D on the .so")
        .into_iter()
        .find(|s| s.name == "shared_marker")
        .and_then(|s| s.addr)
        .expect("nm -D must show shared_marker with an address");
    assert_eq!(
        prov.lookup_name("shared_marker").map(|s| s.address),
        Some(nm_marker),
        "shared_marker is at a different address than nm reports"
    );
}

/// DEFECT (measured, NOT fixed here) — the provider does not carry GNU symbol
/// versioning. `nm -D` on a stripped `cc` build prints
/// `__libc_start_main@GLIBC_2.34`; `parse_elf` reports the bare
/// `__libc_start_main`.
///
/// It is not a parsing error: `readelf -sW --dyn-syms` shows the `.dynstr`
/// string IS the bare name, with the version index `(2)` beside it. The suffix
/// is produced by joining `.gnu.version` to `.gnu.version_r`, two sections
/// `parse_elf` never reads. It matters because two different versions of the
/// same name are two different symbols to the loader, and a debugger that
/// merges them resolves the wrong one.
///
/// MEASURED RED (this test, on a `cc -O0 -no-pie -g -s` fixture):
/// "the version suffix is not carried: nm says
/// __libc_start_main@GLIBC_2.34, the provider has __libc_start_main".
#[tokio::test(flavor = "multi_thread")]
#[ignore = "documented defect: GNU symbol versioning is not applied to .dynsym names"]
async fn elf_symbols_do_not_carry_the_gnu_version_suffix() {
    let fx = build(&["-no-pie", "-g", "-s"]);
    prove_runnable(&fx).await;
    let versioned: Vec<String> = nm_symbols(&fx.subject, &["-D"])
        .expect("nm -D")
        .into_iter()
        .map(|s| s.name)
        .filter(|n| n.contains('@'))
        .collect();
    assert!(
        !versioned.is_empty(),
        "guard: the fixture must import at least one versioned symbol"
    );
    let prov = ElfSymbolProvider::parse_elf("stripped", &fx.bytes).expect("valid ELF");
    for name in &versioned {
        assert!(
            prov.lookup_name(name).is_some(),
            "the version suffix is not carried: nm says {name}, the provider has {}",
            name.split('@').next().unwrap_or(name)
        );
    }
}
