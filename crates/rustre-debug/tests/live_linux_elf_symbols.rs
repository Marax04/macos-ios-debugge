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
use std::collections::HashMap;
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

/// Number of symbol lines `nm` prints for `file` with `args`. `None` when nm
/// refuses the file (e.g. "no symbols"), which is itself a measurement.
fn nm_count(file: &str, args: &[&str]) -> Option<usize> {
    let out = std::process::Command::new("nm")
        .args(args)
        .arg(file)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let listing = String::from_utf8_lossy(&out.stdout).to_string();
    Some(
        listing
            .lines()
            .filter(|l| l.split_whitespace().count() >= 2)
            .count(),
    )
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
    let shapes: Vec<(&str, Fixture)> = vec![
        ("no-pie -g", build(&["-no-pie", "-g"])),
        ("pie -g", build(&["-fPIE", "-pie", "-g"])),
        ("no-pie, no -g", build(&["-no-pie"])),
        ("no-pie -g stripped", build(&["-no-pie", "-g", "-s"])),
        ("shared object", build_shared()),
    ];
    for (label, fx) in &shapes {
        prove_runnable(fx).await;
        let r = ElfSymbolProvider::parse_elf("subject", &fx.bytes);
        assert!(r.is_ok(), "parse_elf rejected a runnable ELF ({label})");
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
    assert!(
        ElfSymbolProvider::parse_elf("x", &fx.bytes).is_ok(),
        "guard: the untruncated bytes must still be accepted"
    );
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
#[ignore = "backend defect: parse_elf is a stub — 0 of 35 symbols on an ET_EXEC -g build"]
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
}

/// DEFECT — ET_DYN, `cc -fPIE -pie -O0 -g`. Same stub, same total loss, on the
/// shape that is the DEFAULT on every current distribution: a PIE is what a
/// debugger normally attaches to, so this is the common case, not an edge one.
///
/// MEASURED: expected `nm` = 31, reachable = 37, obtained = 0.
/// Failure text: "pie -g: parse_elf obtained 0 of 31 symbols (37 reachable)",
/// left: 0, right: 37.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "backend defect: parse_elf is a stub — 0 of 37 symbols on a PIE -g build"]
async fn parse_elf_should_load_the_symtab_of_a_pie_binary() {
    let fx = build(&["-fPIE", "-pie", "-g"]);
    let g = measure(&fx, &[], ".symtab", ".strtab").await;
    assert!(g.reachable > 0, "guard: the fixture must contain symbols");
    assert_eq!(
        g.obtained, g.reachable,
        "pie -g: parse_elf obtained {} of {} symbols ({} reachable)",
        g.obtained, g.expected, g.reachable
    );
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
#[ignore = "backend defect: parse_elf is a stub — 0 of 35 symbols with no debug info"]
async fn parse_elf_should_load_the_symtab_of_a_binary_built_without_g() {
    let fx = build(&["-no-pie"]);
    let g = measure(&fx, &[], ".symtab", ".strtab").await;
    assert!(g.reachable > 0, "guard: the fixture must contain symbols");
    assert_eq!(
        g.obtained, g.reachable,
        "no -g: parse_elf obtained {} of {} symbols ({} reachable)",
        g.obtained, g.expected, g.reachable
    );
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
#[ignore = "backend defect: parse_elf is a stub — 0 dynamic symbols on a stripped build"]
async fn parse_elf_should_load_the_dynsym_of_a_stripped_binary() {
    let fx = build(&["-no-pie", "-g", "-s"]);
    let g = measure(&fx, &["-D"], ".dynsym", ".dynstr").await;
    assert!(g.reachable > 0, "guard: .dynsym must hold entries");
    assert_eq!(
        g.obtained, g.reachable,
        "stripped: parse_elf obtained {} of {} dynamic symbols ({} reachable through .dynsym)",
        g.obtained, g.expected, g.reachable
    );
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
#[ignore = "backend defect: parse_elf is a stub — 0 dynamic symbols on a shared object"]
async fn parse_elf_should_load_the_dynsym_of_a_shared_object() {
    let fx = build_shared();
    let g = measure(&fx, &["-D"], ".dynsym", ".dynstr").await;
    assert!(g.reachable > 0, "guard: the .so must export something");
    let prov = ElfSymbolProvider::parse_elf("so", &fx.bytes).expect("valid ELF");
    let lost = prov.lookup_name("shared_marker").is_none();
    assert!(
        g.obtained == g.reachable && !lost,
        "shared object: parse_elf obtained {} of {} dynamic symbols ({} reachable), and lost the exported shared_marker: {lost}",
        g.obtained, g.expected, g.reachable
    );
}
