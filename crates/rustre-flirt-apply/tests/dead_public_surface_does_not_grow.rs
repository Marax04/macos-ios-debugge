//! The unused public surface, measured once for a decision taken once (T8).
//!
//! # Why this replaces four separate asks
//!
//! T4 (parsers), T5 (matchers), T6 (appliers) and T38 (935 dead lines) each
//! ended at the same wall: the modules are `pub`, so removing them is a breaking
//! change and the maintainer decides. Four asks, one question. Measured across
//! the four crates at once:
//!
//! | | count |
//! |---|---|
//! | public modules | 70 |
//! | used by production code | 23 |
//! | not used by production | 47 |
//! | …of those, used by tests or examples | 17 |
//! | **no use anywhere in the workspace** | **30** |
//!
//! The 17 matter: integration tests and examples are separate crates, so they
//! can only reach `pub` items. Making those `pub(crate)` would break the tests —
//! a different decision from deleting them. The 30 are the actionable list.
//!
//! # The scanner had two bugs, both in the dangerous direction
//!
//! Its first run reported 52 dead, including `sig_file_loader` (referenced four
//! times in `lib.rs`) and `typerecov_bridge` (called by the decompiler). It cut
//! each file at the first `#[cfg(test)]`, discarding production code after an
//! inline test module, and it searched only the four crates while consumers live
//! elsewhere. Both made live modules look dead.
//!
//! Hence the positive control below: a scanner that silently finds nothing
//! reports everything as unused and looks like a dramatic result.
//!
//! # Limit
//!
//! The scan sees this workspace only. These are `pub`: an external caller is not
//! excluded, so the conclusion is "unused **here**", never "safe to delete".

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

/// Every `src/*.rs` in the workspace, with inline test code kept — counting a
/// test reference keeps a module off the dead list, the safe direction.
fn sources() -> Vec<(PathBuf, String)> {
    let mut files = Vec::new();
    if let Ok(rd) = std::fs::read_dir(crates_root()) {
        for e in rd.flatten() {
            walk(&e.path().join("src"), &mut files);
        }
    }
    files
        .into_iter()
        .filter_map(|p| std::fs::read_to_string(&p).ok().map(|t| (p, t)))
        .collect()
}

fn is_ours(p: &Path) -> bool {
    p.components()
        .any(|c| CRATES.contains(&c.as_os_str().to_string_lossy().as_ref()))
}

/// `module name -> production references elsewhere in the workspace`.
fn module_refs() -> BTreeMap<String, usize> {
    let srcs = sources();
    let mut modules: Vec<String> = Vec::new();
    for (p, text) in srcs.iter().filter(|(p, _)| is_ours(p)) {
        let _ = p;
        for line in text.lines() {
            if let Some(rest) = line.trim().strip_prefix("pub mod ")
                && let Some(n) = rest.strip_suffix(';') {
                    modules.push(n.to_string());
                }
        }
    }

    let mut out = BTreeMap::new();
    for name in modules {
        let needle = format!("{name}::");
        let own = format!("{name}.rs");
        let mut refs = 0usize;
        for (p, text) in &srcs {
            if p.file_name().is_some_and(|f| f == own.as_str()) {
                continue;
            }
            refs += text
                .lines()
                .map(str::trim)
                .filter(|t| !t.starts_with("//") && !t.starts_with("pub mod ") && !t.starts_with("pub use "))
                .filter(|t| t.contains(&needle))
                .count();
        }
        out.insert(name, refs);
    }
    out
}

#[test]
fn the_scanner_finds_modules_that_are_certainly_used() {
    // Positive control. Both were wrongly reported dead by the first version.
    let refs = module_refs();
    assert!(refs.len() > 50, "trovati solo {} moduli pubblici", refs.len());
    for control in ["sig_file_loader", "typerecov_bridge"] {
        let n = refs.get(control).copied().unwrap_or(0);
        assert!(
            n > 0,
            "{control} risulta senza riferimenti, ma e' certamente usato: \
             lo scanner e' rotto, non il codice"
        );
    }
}

/// The gate: the unused surface must not grow silently. An inequality against a
/// measured baseline, not an exact pin — the point is to notice new dead public
/// API, not to freeze the current amount.
#[test]
fn the_unused_public_surface_does_not_grow() {
    const BASELINE_UNUSED_BY_PRODUCTION: usize = 47;

    let refs = module_refs();
    let unused = refs.values().filter(|n| **n == 0).count();
    assert!(
        unused <= BASELINE_UNUSED_BY_PRODUCTION,
        "moduli pubblici non usati dalla produzione passati da \
         {BASELINE_UNUSED_BY_PRODUCTION} a {unused}: ogni nuovo modulo pubblico \
         inutilizzato e' superficie da mantenere per sempre"
    );
}
