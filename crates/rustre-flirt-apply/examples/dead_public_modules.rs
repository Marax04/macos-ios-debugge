//! Which public modules does nothing in the workspace use? (T8)
//!
//! T4, T5, T6 and T38 all ended at the same wall: "these are `pub`, so removing
//! them is a breaking change — the maintainer decides". Four separate asks, one
//! question. This measures the whole surface at once so the decision can be
//! taken once, against a list, instead of four times against anecdotes.
//!
//! For each `pub mod` in the four crates, count references from **production**
//! code elsewhere in the workspace — excluding the module's own file, its
//! `pub mod` declaration, `#[cfg(test)]` blocks, comments, and `use` lines that
//! merely re-export.
//!
//! # Two bugs this scanner had, both in the dangerous direction
//!
//! The first version reported 52 of 70 modules dead — including
//! `sig_file_loader`, referenced four times in `lib.rs`, and `typerecov_bridge`,
//! called by the decompiler. Both errors made live modules look dead:
//!
//! 1. it cut each file at the first `#[cfg(test)]`, discarding every line of
//!    production code that followed an inline test module;
//! 2. it scanned only the four crates, while consumers live elsewhere in the
//!    workspace.
//!
//! Both are now fixed, and the bias is deliberately the other way: inline test
//! code is counted as a reference, so a module is called dead only when nothing
//! at all mentions it. Over-counting keeps a live module off the list;
//! under-counting would put one on it, which is the error that matters.
//!
//! The scan sees only this workspace. These are `pub`, so an external caller is
//! not excluded: the honest conclusion is "unused **here**", never "safe to
//! delete".

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const CRATES: &[&str] = &[
    "rustre-flirt",
    "rustre-flirt-gen",
    "rustre-flirt-apply",
    "rustre-analysis-typerecov",
];

fn crates_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .expect("il crate deve stare in <root>/crates/<name>")
}

/// Every `.rs` file under every crate's `src/` in the workspace.
///
/// Inline `#[cfg(test)]` code is **not** stripped: counting a test reference
/// keeps a module off the dead list, which is the safe direction for a claim
/// that something is unused.
fn production_sources() -> Vec<(PathBuf, String)> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    let Ok(rd) = std::fs::read_dir(crates_root()) else { return Vec::new() };
    for e in rd.flatten() {
        walk(&e.path().join("src"), &mut files);
    }
    files
        .into_iter()
        .filter_map(|p| {
            let text = std::fs::read_to_string(&p).ok()?;
            Some((p, text))
        })
        .collect()
}

/// Collect every `pub mod` and decide which are referenced nowhere.
///
/// Split out of `main` so the gathering pass and the reporting pass are
/// each readable on their own.
fn collect_dead_modules() -> (Vec<(String, String, usize)>, Vec<String>) {
    let sources = production_sources();

    // Every `pub mod NAME;` and the file that declares it.
    // Modules are collected from the four crates only; references are searched
    // across the whole workspace, because consumers live elsewhere (the
    // decompiler calls `typerecov_bridge`).
    let mut modules: BTreeMap<String, String> = BTreeMap::new();
    let owned: Vec<&(PathBuf, String)> = sources
        .iter()
        .filter(|(p, _)| {
            p.components().any(|c| {
                CRATES.contains(&c.as_os_str().to_string_lossy().as_ref())
            })
        })
        .collect();
    for (path, text) in &owned {
        for line in text.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("pub mod ")
                && let Some(name) = rest.strip_suffix(';') {
                    let krate = path
                        .parent()
                        .and_then(|p| p.parent())
                        .and_then(|p| p.file_name())
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    modules.insert(name.to_string(), krate);
                }
        }
    }

    let mut dead: Vec<(&String, &String, usize)> = Vec::new();
    let mut live = 0usize;

    for (name, krate) in &modules {
        let needle = format!("{name}::");
        let own_file = format!("{name}.rs");
        let mut refs = 0usize;
        for (path, text) in &sources {
            if path.file_name().is_some_and(|f| f == own_file.as_str()) {
                continue;
            }
            for line in text.lines() {
                let t = line.trim();
                if t.starts_with("//") || t.starts_with("pub mod ") || t.starts_with("pub use ") {
                    continue;
                }
                if t.contains(&needle) {
                    refs += 1;
                }
            }
        }
        if refs == 0 {
            dead.push((name, krate, refs));
        } else {
            live += 1;
        }
    }

    // Positive control: a module that is certainly used must not be on the list.
    // Without this, a scanner that silently finds nothing reports everything as
    // dead and looks like a dramatic finding.
    for control in ["sig_file_loader", "typerecov_bridge"] {
        if dead.iter().any(|(n, ..)| n.as_str() == control) {
            eprintln!(
                "CONTROLLO FALLITO: {control} risulta morto ma e' certamente usato —                  lo scanner e' rotto, non il codice"
            );
            std::process::exit(1);
        }
    }

    println!("file sorgente analizzati    : {}", sources.len());
    println!("moduli pubblici nei 4 crate : {}", modules.len());
    println!("  usati da codice di produzione : {live}");
    println!("  NON usati nel workspace       : {}", dead.len());
    println!();
    // Of the production-unused modules, which are still used by tests or
    // examples? Those are integration targets — separate crates — so they can
    // only reach `pub` items. Making them `pub(crate)` would break the tests,
    // which is a materially different decision from "delete it".
    let mut aux_files = Vec::new();
    if let Ok(rd) = std::fs::read_dir(crates_root()) {
        for e in rd.flatten() {
            for sub in ["tests", "examples"] {
                let d = e.path().join(sub);
                let Ok(inner) = std::fs::read_dir(&d) else { continue };
                for f in inner.flatten() {
                    if f.path().extension().is_some_and(|x| x == "rs")
                        && let Ok(t) = std::fs::read_to_string(f.path()) {
                            aux_files.push(t);
                        }
                }
            }
        }
    }
    (
        dead.into_iter()
            .map(|(n, f, c)| (n.clone(), f.clone(), c))
            .collect(),
        aux_files,
    )
}

fn main() {
    let (dead, aux_files) = collect_dead_modules();

    let used_by_tests = |name: &str| -> bool {
        let needle = format!("{name}::");
        aux_files.iter().any(|t| t.contains(&needle))
    };

    let (aux, truly): (Vec<_>, Vec<_>) = dead.iter().partition(|(n, ..)| used_by_tests(n));
    println!("  di cui usati da test/example  : {} (devono restare `pub`)", aux.len());
    println!("  senza alcun uso nel workspace : {}", truly.len());
    println!();

    let mut by_crate: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (name, krate, _) in &truly {
        by_crate.entry(krate.as_str()).or_default().push(name.as_str());
    }
    for (krate, names) in &by_crate {
        println!("{krate} ({}):", names.len());
        for n in names {
            println!("   {n}");
        }
    }
    println!();
    println!("Elencati sopra: nessun uso ne' in produzione ne' nei test.");
    println!("Lo scan vede solo questo workspace: sono `pub`, quindi");
    println!("\"non usato qui\" non significa \"sicuro da cancellare\".");
}
