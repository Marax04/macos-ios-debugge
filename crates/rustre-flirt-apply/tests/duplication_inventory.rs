//! Pins the measured duplication so it cannot grow unnoticed.
//!
//! # What was actually measured, and why the old number was wrong
//!
//! The session's baseline claimed "~12 duplicated/parallel modules". Measured
//! properly on 2026-07-29 it is wrong in **both** directions:
//!
//! * parallel-named modules (`*_v2`, `*_new`): **3**, not ~12 — and two of them
//!   are referenced by nothing but their own `pub mod` line, i.e. **935 lines of
//!   dead code**;
//! * duplicated **public type names** across the four crates: **52**, which the
//!   module count never captured. `SigHeader` exists 5 times, `ApplyResult`,
//!   `TrieNode` and `PatternTrie` 4 times each.
//!
//! The type count is the one that matters. A duplicated *module* is tidiness; a
//! duplicated *type* is the shape that produced every real defect in this
//! session — two `FlirtPattern`s, two `SigHeader` layouts, three trie encoders.
//! Each pair round-trips happily through its own half of the stack and fails
//! only where the halves meet.
//!
//! These tests do not demand the duplication be fixed. They demand it not get
//! **worse** without someone noticing, and they record the real numbers so the
//! next inventory does not have to rediscover them.

use std::collections::BTreeMap;
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

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Public `struct`/`enum` names, mapped to the files declaring them.
fn public_types() -> BTreeMap<String, Vec<String>> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for c in CRATES {
        let mut files = Vec::new();
        rust_files(&crates_root().join(c).join("src"), &mut files);
        for f in files {
            let Ok(src) = std::fs::read_to_string(&f) else { continue };
            for line in src.lines() {
                let t = line.trim_start();
                for kw in ["pub struct ", "pub enum "] {
                    if let Some(rest) = t.strip_prefix(kw) {
                        let name: String = rest
                            .chars()
                            .take_while(|c| c.is_alphanumeric() || *c == '_')
                            .collect();
                        if !name.is_empty() {
                            map.entry(name).or_default().push(f.display().to_string());
                        }
                    }
                }
            }
        }
    }
    map
}

#[test]
fn duplicated_public_type_names_do_not_grow() {
    let map = public_types();
    let dups: Vec<(&String, usize)> = map
        .iter()
        .filter(|(_, v)| v.len() > 1)
        .map(|(k, v)| (k, v.len()))
        .collect();

    // Sanity: the scan must find types at all, or the ceiling below is vacuous.
    assert!(map.len() > 100, "lo scan ha trovato solo {} tipi: sospetto", map.len());

    eprintln!("tipi pubblici duplicati: {}", dups.len());
    for (name, n) in dups.iter().take(10) {
        eprintln!("  {name} x{n}");
    }

    // Measured at 52. The ceiling leaves no headroom on purpose: a new
    // duplicate should require a deliberate decision to raise this number.
    assert!(
        dups.len() <= 52,
        "i tipi pubblici duplicati sono saliti a {}: era 52. \
         Un tipo duplicato è la forma che ha prodotto ogni difetto reale di \
         questa sessione — se è intenzionale, alza la soglia spiegando perché",
        dups.len()
    );
}

#[test]
fn the_worst_offenders_are_still_the_ones_measured() {
    // Named explicitly so a *shift* is visible even when the total holds: five
    // `SigHeader`s becoming four while something else gains one would otherwise
    // pass silently.
    let map = public_types();
    for (name, expected_max) in [
        ("SigHeader", 5usize),
        ("ApplyResult", 4),
        ("TrieNode", 4),
        ("PatternTrie", 4),
    ] {
        let n = map.get(name).map_or(0, Vec::len);
        assert!(
            n <= expected_max,
            "`{name}` ora esiste {n} volte (era {expected_max})"
        );
    }
}

#[test]
fn parallel_named_modules_do_not_multiply() {
    let mut found = Vec::new();
    for c in CRATES {
        let dir = crates_root().join(c).join("src");
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".rs") {
                continue;
            }
            let stem = name.trim_end_matches(".rs");
            if stem.ends_with("_v2")
                || stem.ends_with("_new")
                || stem.ends_with("_old")
                || stem.ends_with('2')
            {
                found.push(format!("{c}/{name}"));
            }
        }
    }
    found.sort();
    eprintln!("moduli con nome parallelo: {found:?}");
    assert!(
        found.len() <= 3,
        "i moduli paralleli sono saliti a {}: {found:?}",
        found.len()
    );
}

/// The two dead modules must stay identifiable.
///
/// They are `pub`, so deleting them is a breaking change for an external
/// consumer — the cleanup is a decision for the maintainer, not a side effect
/// of this test.
///
/// An earlier attempt marked them `#[deprecated]`. That was reverted: the lint
/// fires at the crate root where `pub mod` is declared, so no `#[allow]` inside
/// the module can silence the 8 warnings it produced for the modules' own
/// tests. A permanent warning nobody can act on trains people to ignore
/// warnings, which costs more than the signal is worth. The doc comment carries
/// the same information without the noise, and this test keeps it honest.
#[test]
fn the_dead_modules_are_still_documented_as_dead() {
    let lib = crates_root().join("rustre-flirt/src/lib.rs");
    let Ok(src) = std::fs::read_to_string(&lib) else {
        eprintln!("lib.rs non leggibile — test saltato");
        return;
    };
    for m in ["flirt_matcher_v2", "signature_matcher_new"] {
        let decl = format!("pub mod {m};");
        if !src.contains(&decl) {
            eprintln!("{m} è stato rimosso — aggiorna questo test e PROGRESS.md");
            continue;
        }
        let idx = src.find(&decl).unwrap();
        let before = &src[idx.saturating_sub(500)..idx];
        assert!(
            before.contains("Dead code"),
            "`{m}` ha perso la nota che lo segnala come codice morto: senza,              qualcuno ci costruira' sopra credendolo vivo"
        );
    }
}
