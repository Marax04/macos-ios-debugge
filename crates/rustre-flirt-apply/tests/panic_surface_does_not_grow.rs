//! The panic surface in production code, counted and capped (T24).
//!
//! # Why a count, after three individual fixes
//!
//! Three reachable panics were found and fixed in iterations 63–65, all the same
//! shape: a guard against a hostile binary implemented by aborting the process.
//! None of them appeared in an `unwrap|expect` inventory — two were `assert!`,
//! and the worst was reached with a value *inside* the legal range.
//!
//! Counting the whole class is what stops it coming back. Measured across the
//! four crates' production code (inline `#[cfg(test)]` excluded by brace depth,
//! comments skipped):
//!
//! | crate | panic-shaped constructs |
//! |---|---|
//! | `rustre-flirt` | 4 |
//! | `rustre-flirt-gen` | 9 |
//! | `rustre-flirt-apply` | 32 |
//! | `rustre-analysis-typerecov` | 14 |
//! | **total** | **59** |
//!
//! # What the 59 are, checked rather than assumed
//!
//! The largest group — 18 across `sig_file_loader` and `ida_sig_compat` — is
//! `raw[a..b].try_into().unwrap()`: the `unwrap` is infallible (four bytes into
//! `[u8; 4]`), and the slice is length-checked upstream, which the hostile-input
//! sweeps of T11 exercised without producing a panic.
//!
//! The `.min()/.max().unwrap()` calls in `match_validator` sit after an explicit
//! `candidates.is_empty()` return, and the later ones operate on a set filtered
//! to equal the maximum, so it is non-empty by construction. The
//! `batch_applicator` ones are mutex poisoning.
//!
//! One is a genuine API contract rather than hostile data: `FlirtSig::new`
//! asserts `pattern_bytes.len() == mask.len()`. All 19 of its callers pass
//! literals; no parser builds those two vectors independently. Documented under
//! `# Panics`, and left alone — turning a caller's programming error into a
//! `Result` would spread noise, not safety.
//!
//! # Limit
//!
//! This counts syntax, not reachability. It cannot tell a guarded `unwrap` from
//! an exposed one; it exists so that *new* ones get noticed and classified, not
//! to certify the existing ones.
//!
//! `debug_assert*` is excluded: it is compiled out in release, and this project
//! builds nothing else, so counting it would inflate the figure with constructs
//! no shipped binary can execute. There are 3 of them, which is precisely the
//! gap between a naive substring count (62) and the release-only one (59).

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

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Lines outside any `#[cfg(test)]` module, tracked by brace depth.
///
/// Cutting at the *first* `#[cfg(test)]` instead would drop every production
/// line after an inline test module — the mistake that made an earlier count
/// read 6 where the answer was 9.
fn production_lines(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut depth, mut in_test, mut test_depth) = (0i64, false, 0i64);
    for line in text.lines() {
        if !in_test && line.contains("#[cfg(test)]") {
            in_test = true;
            test_depth = depth;
            continue;
        }
        let delta = i64::try_from(line.matches('{').count()).unwrap()
            - i64::try_from(line.matches('}').count()).unwrap();
        if in_test {
            depth += delta;
            if depth <= test_depth && line.contains('}') {
                in_test = false;
            }
            continue;
        }
        out.push(line);
        depth += delta;
    }
    out
}

fn panic_sites() -> usize {
    const NEEDLES: &[&str] = &[
        ".unwrap()",
        ".expect(",
        "panic!",
        "unreachable!",
        "todo!",
        "assert!",
        "assert_eq!",
        "assert_ne!",
    ];
    let mut total = 0usize;
    for c in CRATES {
        let mut files = Vec::new();
        rust_files(&crates_root().join(c).join("src"), &mut files);
        for f in files {
            let Ok(text) = std::fs::read_to_string(&f) else { continue };
            for line in production_lines(&text) {
                let t = line.trim();
                if t.starts_with("//") || t.starts_with('*') {
                    continue;
                }
                // `debug_assert*` is compiled out in release, and this project
                // builds nothing else — counting it would inflate the number
                // with constructs that cannot panic in any shipped binary.
                // Removing the token first also stops `assert_eq!` from matching
                // inside `debug_assert_eq!`, which is what made this counter read
                // 62 where a release-only count is 59.
                let t = t.replace("debug_assert", "");
                total += NEEDLES.iter().map(|n| t.matches(n).count()).sum::<usize>();
            }
        }
    }
    total
}

#[test]
fn the_counter_is_not_vacuous() {
    // A counter that finds nothing would make the gate below pass forever.
    assert!(
        panic_sites() > 20,
        "conteggio sospettosamente basso: lo scanner non sta leggendo i sorgenti"
    );
}

/// The gate. An inequality against a measured baseline: the point is that a new
/// panic on an untrusted path gets noticed and classified, not that the number
/// is frozen.
#[test]
fn the_panic_surface_does_not_grow() {
    const BASELINE: usize = 59;
    let n = panic_sites();
    assert!(
        n <= BASELINE,
        "costrutti che possono panicare passati da {BASELINE} a {n} in codice di \
         produzione: verifica se il nuovo e' raggiungibile da un binario non \
         fidato — tre volte su tre lo era, e due volte era un `assert!` che \
         nessuna ricerca di `unwrap|expect` avrebbe trovato"
    );
}
