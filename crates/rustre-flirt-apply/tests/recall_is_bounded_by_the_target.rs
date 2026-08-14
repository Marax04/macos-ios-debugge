//! Recall must be measured against what the target actually contains (T14).
//!
//! # A correction to iterations 46–47
//!
//! Those iterations measured 522 signatures from `libmingwex.a` finding 4 names
//! in a mingw-built corpus binary, concluded that most of them were false, and
//! published: **"real recall is about 1 in 522"**.
//!
//! The arithmetic was right and the conclusion was not. 522 is the wrong
//! denominator. A static linker pulls in only the archive members a program
//! needs, so almost none of `libmingwex` is *in* `sample1_c.exe` — and a
//! signature for a function that was never linked cannot be found by any
//! matcher.
//!
//! Measured (iteration 55, `examples/recall_ceiling.rs`) with an oracle that
//! needs no symbols: search the target for each pattern's concrete leading run.
//!
//! | minimum prefix | signatures | entry bytes present in target |
//! |---|---|---|
//! | ≥ 4 bytes | 513 | **3** |
//! | ≥ 8 bytes | 495 | **1** |
//! | ≥ 12 bytes | 469 | 1 |
//! | ≥ 16 bytes | 445 | 1 |
//!
//! The scanner finds **2**. So the ceiling is about 3, not 522, and the matcher
//! is near it — not failing at it. "1 in 522" described the linker's behaviour,
//! not ours.
//!
//! Reported at several prefix lengths on purpose: a 4-byte run occurs by chance,
//! so a single number would over-claim in exactly the way the short-prefix false
//! positives already did.
//!
//! # What this does not say
//!
//! Byte presence is necessary, not sufficient: a run can appear inside an
//! unrelated function. So the ceiling is an **upper** bound on what is findable,
//! which is the safe direction for the claim being made — that the denominator,
//! not the matcher, explains the number.
//!
//! # How loose that bound is, measured (iteration 56)
//!
//! A survey across runtime archives, scanning corpus binaries:
//!
//! | archive | signatures | findable (≥8B) | found |
//! |---|---|---|---|
//! | `libmingw32` | 43 | 24 | **24** |
//! | `libmsvcrt` | 364 | 7 | **7** |
//! | `libstdc++` (vs a C++ binary) | 5427 | 187 | **5** |
//!
//! On C the bound is tight and the matcher reaches it exactly. On `libstdc++` it
//! does not, and the cause is **not** database scale: rebuilding the database
//! from only the 187 findable signatures still finds **3**.
//!
//! The reading consistent with the data is that C++ **shares prologues** — the
//! same 16-byte opening belongs to many distinct functions (template
//! instantiations, thunks, wrappers), so those bytes being present does not mean
//! *that* function is. The ceiling stays a valid upper bound, but on C++ it is
//! **loose**, and "160 findable" must not be read as "160 missed".
//!
//! This is why the assertion below uses the C binary: it is the case where the
//! bound is tight enough for the comparison to mean something.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use rustre_flirt::PatternByte;

const ARCHIVE: &str = r"C:\msys64\mingw64\lib\libmingwex.a";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .expect("il crate deve stare in <root>/crates/<name>")
}

fn corpus(name: &str) -> PathBuf {
    repo_root().join("tests/decompiler_corpus/bin").join(name)
}

fn patterns() -> Option<Vec<rustre_flirt::FlirtPattern>> {
    let data = std::fs::read(ARCHIVE).ok()?;
    let opts = rustre_flirt_gen::coff_archive::ArchiveHarvestOptions::default();
    let (pats, _) = rustre_flirt_gen::coff_archive::harvest_archive_bytes(&data, &opts).ok()?;
    (!pats.is_empty()).then_some(pats)
}

fn concrete_prefix(p: &rustre_flirt::FlirtPattern) -> Vec<u8> {
    p.initial_bytes
        .iter()
        .take_while(|b| matches!(b, PatternByte::Exact(_)))
        .map(|b| match b {
            PatternByte::Exact(v) => *v,
            PatternByte::Wildcard => unreachable!(),
        })
        .collect()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && needle.len() <= hay.len() && hay.windows(needle.len()).any(|w| w == needle)
}

/// Signatures whose entry bytes (at least `min_len` concrete bytes) appear in
/// the target — an upper bound on what any matcher could find.
fn ceiling(pats: &[rustre_flirt::FlirtPattern], target: &[u8], min_len: usize) -> usize {
    pats.iter()
        .map(concrete_prefix)
        .filter(|pre| pre.len() >= min_len && contains(target, pre))
        .count()
}

fn scanner_finds(pats: &[rustre_flirt::FlirtPattern], target: &[u8]) -> usize {
    let sig = rustre_flirt_gen::SigWriter::default().build(pats, "ceiling");
    rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig).map_or(0, |s| {
        s.scan_fast(target, 0)
            .into_iter()
            .map(|m| m.function_name)
            .collect::<HashSet<_>>()
            .len()
    })
}

#[test]
fn the_inputs_are_not_vacuous() {
    let Some(pats) = patterns() else {
        eprintln!("SKIP: {ARCHIVE} assente");
        return;
    };
    assert!(pats.len() > 100, "attese molte firme, {}", pats.len());
    assert!(
        corpus("sample1_c.exe").exists(),
        "corpus assente: la misura non avrebbe bersaglio"
    );
}

/// The correction, as an assertion: almost none of the archive is in the binary.
#[test]
fn almost_none_of_the_archive_is_linked_into_the_target() {
    let Some(pats) = patterns() else { return };
    let Ok(target) = std::fs::read(corpus("sample1_c.exe")) else {
        eprintln!("SKIP: corpus assente");
        return;
    };

    let ceil8 = ceiling(&pats, &target, 8);
    assert!(
        ceil8 < 20,
        "{ceil8} firme su {} hanno i byte d'ingresso nel target: il linker ne \
         collega molte piu' di prima, quindi il denominatore del recall cambia \
         e la conclusione dell'iterazione 55 va rimisurata",
        pats.len()
    );
}

/// The point of the whole file: the matcher is near the ceiling, so the low
/// absolute count is the target's doing, not the matcher's.
#[test]
fn the_scanner_is_close_to_the_ceiling() {
    let Some(pats) = patterns() else { return };
    let Ok(target) = std::fs::read(corpus("sample1_c.exe")) else {
        eprintln!("SKIP: corpus assente");
        return;
    };

    let found = scanner_finds(&pats, &target);
    let ceil4 = ceiling(&pats, &target, 4);

    assert!(
        ceil4 > 0,
        "tetto zero: l'oracolo non trova nessun prefisso, verifica l'input"
    );
    assert!(
        found + 2 >= ceil4,
        "trovati {found} contro un tetto di {ceil4}: il matcher e' molto sotto \
         il tetto, e questa volta il difetto sarebbe nostro"
    );
}
