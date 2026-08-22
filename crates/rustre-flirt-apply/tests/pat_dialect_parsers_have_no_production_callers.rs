//! The three dialect `.pat` parsers are called by nothing that ships (T4).
//!
//! # The fact this establishes, and why by test rather than by grep
//!
//! T4's remaining step is to reduce the three public dialect parsers to
//! re-exports of `pat_canonical`. What decides how risky that is: whether
//! anything on a real path depends on their behaviour.
//!
//! Iteration 50 already corrected one overstatement here — the production `.pat`
//! reader turned out to be a *fourth*, private function that the public-symbol
//! matrix had missed. So "nothing calls these" is exactly the kind of claim this
//! project has been wrong about before, and a grep is only as good as its
//! pattern: that mistake is on record from the CRC hunt, where searching for
//! reflected polynomials alone certified "no duplicates remain" while five
//! remained.
//!
//! So this scans the source of all four crates and enumerates every reference,
//! classifying each as production code, test code, or an example. The assertion
//! is on the production count.
//!
//! # What it does not claim
//!
//! These are `pub`. Something outside this workspace can call them, and this
//! scan cannot see that — which is why the conclusion below is "safe to
//! consolidate *within* the workspace", not "safe to delete".

use std::path::{Path, PathBuf};

fn crates_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .expect("il crate deve stare in <root>/crates/<name>")
}

const CRATES: &[&str] = &[
    "rustre-flirt",
    "rustre-flirt-gen",
    "rustre-flirt-apply",
    "rustre-analysis-typerecov",
];

/// Every `.rs` file under the four crates, tagged by what kind of code it is.
fn sources() -> Vec<(PathBuf, Kind)> {
    fn walk(dir: &Path, kind: Kind, out: &mut Vec<(PathBuf, Kind)>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, kind, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push((p, kind));
            }
        }
    }
    let mut out = Vec::new();
    for c in CRATES {
        let root = crates_root().join(c);
        walk(&root.join("src"), Kind::Production, &mut out);
        walk(&root.join("tests"), Kind::Test, &mut out);
        walk(&root.join("examples"), Kind::Example, &mut out);
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Production,
    Test,
    Example,
}

/// Count references to `needle`, excluding the definition itself and anything
/// inside a `#[cfg(test)]` module of a production file.
fn references(needle: &str) -> (usize, usize, usize) {
    let (mut prod, mut test, mut example) = (0usize, 0usize, 0usize);

    for (file, code_kind) in sources() {
        let Ok(source) = std::fs::read_to_string(&file) else { continue };

        // Production files carry inline `#[cfg(test)]` modules. Everything from
        // the first one to end of file is test code, not production — counting
        // it as production would understate how dead these parsers are, which is
        // the safe direction but still wrong.
        let effective = if code_kind == Kind::Production {
            source.find("#[cfg(test)]").map_or(&source[..], |i| &source[..i])
        } else {
            &source[..]
        };

        for line in effective.lines() {
            let t = line.trim();
            if t.starts_with("//") || t.starts_with("/*") || t.starts_with('*') {
                continue;
            }
            // Skip the definition site.
            if t.starts_with("pub fn") || t.starts_with("fn ") {
                continue;
            }
            if !t.contains(needle) {
                continue;
            }
            match code_kind {
                Kind::Production => prod += 1,
                Kind::Test => test += 1,
                Kind::Example => example += 1,
            }
        }
    }
    (prod, test, example)
}

#[test]
fn the_scanner_finds_something_at_all() {
    // Vacuity guard: if the walk returned nothing, every "zero callers" claim
    // below would be free. This project has been caught by a degenerate corpus
    // three times.
    let files = sources();
    assert!(
        files.len() > 50,
        "attesi molti file sorgente, trovati {}",
        files.len()
    );
    assert!(
        files.iter().any(|(_, k)| *k == Kind::Production),
        "nessun file di produzione trovato: il walk non sta guardando src/"
    );

    // And a positive control: a symbol that certainly *is* used in production.
    let (prod, _, _) = references("crc16_flirt");
    assert!(
        prod > 0,
        "il controllo positivo non trova riferimenti: lo scanner e' rotto, non \
         sono i parser a essere morti"
    );
}

#[test]
fn the_dialect_parsers_are_unused_by_production_code() {
    // The three public dialect parsers T4 wants to reduce to re-exports.
    for needle in [
        "pat_parser::parse_pat_text",
        "pat_parser_v2::parse_pat_line",
        "SimpleFlirtDatabase::parse_pat_text",
    ] {
        let (prod, test, example) = references(needle);
        assert_eq!(
            prod, 0,
            "{needle}: {prod} riferimenti in codice di produzione \
             (test {test}, example {example}) — consolidarlo NON e' piu' \
             una pulizia di API, tocca un percorso reale: rimisura prima di T4"
        );
    }
}

/// The contrast, asserted so the two facts stay together: the parser that *is*
/// on the shipping path is reached through `load_pat_file`, and that one is
/// used. Consolidation must not touch it blindly.
#[test]
fn the_production_reader_is_the_one_reached_through_load_pat_file() {
    let (prod, _, _) = references("load_pat_file");
    assert!(
        prod > 0,
        "load_pat_file non risulta usato in produzione: la correzione \
         dell'iterazione 50 andrebbe rivista"
    );
}
