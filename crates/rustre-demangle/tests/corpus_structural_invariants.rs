//! Structural invariants over the real corpora, defined without an oracle.
//!
//! Both properties here are *relational*: they hold between symbols, or between
//! a symbol and its own input, rather than asserting what any single decoding
//! should be. That is what makes them usable for Go and Swift, where nothing
//! can contradict a wrong answer — the technique that found the Go
//! package-init collision when per-symbol completeness checks could not.
//!
//! Neither found a defect when it was written; both were measured at zero
//! (2026-07-28) and are here so that a future change cannot introduce one
//! quietly. Each carries a vacuity guard, because "no offenders because it is
//! right" and "no offenders because nothing was compared" are indistinguishable
//! from a green test.

use std::collections::HashMap;

/// Every symbol either corpus decodes, paired with its rendering and ABI.
fn decoded_corpus() -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for path in ["tests/data/real_symbols.txt", "tests/data/pdb_symbols.txt"] {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines() {
            let sym = line.trim();
            if sym.is_empty() {
                continue;
            }
            if let Some(r) = rustre_demangle::demangle(sym) {
                out.push((sym.to_owned(), r.demangled, format!("{:?}", r.abi)));
            }
        }
    }
    out
}

/// Replace the first Itanium ctor/dtor variant tag, so `C1`/`C2` and
/// `D0`/`D1`/`D2` — separate entry points for one entity, rendered identically
/// by `c++filt` and `cpp_demangle` — compare equal.
fn strip_ctor_dtor_variant(mangled: &str) -> String {
    let b = mangled.as_bytes();
    for i in 0..b.len().saturating_sub(1) {
        let constructor = b[i] == b'C' && matches!(b[i + 1], b'1' | b'2' | b'3');
        let destructor = b[i] == b'D' && matches!(b[i + 1], b'0' | b'1' | b'2');
        if constructor || destructor {
            let mut out = mangled.to_owned();
            out.replace_range(i..i + 2, "@@");
            return out;
        }
    }
    mangled.to_owned()
}

/// Two symbols from *different* ABIs must not share a rendering either.
///
/// The same-ABI case is guarded in `tests/msvc_constant_pool.rs`, which keys by
/// `(abi, rendering)` — so a Go symbol and an Itanium symbol collapsing into
/// one string would slip through it entirely. A consumer that indexes by the
/// demangled name alone, which is the normal thing to do, would conflate them
/// regardless of what ABI each came from.
///
/// Measured at zero across both corpora.
#[test]
fn no_two_symbols_from_different_abis_share_a_rendering() {
    let corpus = decoded_corpus();
    let mut by_rendering: HashMap<&str, Vec<(&str, &str)>> = HashMap::new();
    for (sym, rendering, abi) in &corpus {
        by_rendering
            .entry(rendering.as_str())
            .or_default()
            .push((sym.as_str(), abi.as_str()));
    }

    let offenders: Vec<_> = by_rendering
        .iter()
        .filter(|(_, group)| group.len() > 1)
        // Only cross-ABI groups; same-ABI collisions have their own guard.
        .filter(|(_, group)| group.iter().any(|(_, a)| *a != group[0].1))
        .filter(|(_, group)| {
            let keys: Vec<String> = group
                .iter()
                .map(|(s, _)| strip_ctor_dtor_variant(s))
                .collect();
            !keys.windows(2).all(|w| w[0] == w[1])
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "symbols from different ABIs share a rendering: {offenders:?}"
    );
    assert!(
        corpus.len() > 2000,
        "vacuity guard: only {} decodes examined — did the corpora move?",
        corpus.len()
    );
}

/// A mangled symbol must not decode to itself.
///
/// An identity echo is a decode that told the caller nothing, and for a scheme
/// with a mangling sigil it is a *failed* decode reported as a success — the
/// class of defect fixed three times over in this crate (`?module` in Swift,
/// `?(…)` in D, `<invalid>` in the alternate Itanium path), each of which
/// counted a fabrication as `DeclineReason::Decoded`.
///
/// **Go is exempt, and legitimately so**: its symbols are not encoded, they are
/// already readable, and `main.main` decoding to `main.main` is the correct
/// answer rather than a failure. That exemption is the reason this invariant
/// cannot simply be "output ≠ input" crate-wide, and it is also why the Go
/// count is asserted as a live figure below rather than being ignored.
///
/// Measured 2026-07-28: Itanium 0 of 847, MSVC 0 of 14, Rust 0 of 137.
#[test]
fn no_encoded_symbol_decodes_to_itself() {
    let corpus = decoded_corpus();
    let mut checked: HashMap<&str, usize> = HashMap::new();
    let mut echoes: Vec<(&str, &str)> = Vec::new();

    for (sym, rendering, abi) in &corpus {
        if abi == "Go" {
            continue;
        }
        *checked.entry(abi.as_str()).or_default() += 1;
        if sym == rendering {
            echoes.push((sym.as_str(), abi.as_str()));
        }
    }

    assert!(
        echoes.is_empty(),
        "encoded symbols decoded to themselves: {echoes:?}"
    );
    // Vacuity: each encoded ABI must actually be represented in the corpora.
    for abi in ["Itanium", "Msvc", "Rust"] {
        let n = checked.get(abi).copied().unwrap_or(0);
        assert!(n > 10, "only {n} {abi} decodes examined — the guard is vacuous");
    }
}

/// Go's echoes are expected, and their *proportion* is pinned.
///
/// Stated as a range rather than an exact count so ordinary corpus edits do not
/// break it, but tight enough to catch the two ways this could go wrong: Go
/// silently ceasing to decode (the count collapses) or Go starting to
/// fabricate transformations on names that need none (the count collapses the
/// other way, as echoes turn into rewrites).
///
/// Measured 2026-07-28: 1809 echoes of 2163 Go decodes, about 84%.
#[test]
fn go_echoes_stay_within_their_measured_band() {
    let corpus = decoded_corpus();
    let go: Vec<_> = corpus.iter().filter(|(_, _, abi)| abi == "Go").collect();
    let echoes = go.iter().filter(|(s, d, _)| s == d).count();

    assert!(
        go.len() > 1500,
        "vacuity guard: only {} Go decodes found",
        go.len()
    );
    let pct = echoes * 100 / go.len();
    assert!(
        (70..=95).contains(&pct),
        "Go identity-echo share moved to {pct}% ({echoes} of {}); \
         it was 84% when measured — a large move means Go either stopped \
         decoding or started rewriting names that need no rewriting",
        go.len()
    );
}
