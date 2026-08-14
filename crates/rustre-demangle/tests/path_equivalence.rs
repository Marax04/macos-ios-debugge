//! Every public entry point must agree on every real symbol.
//!
//! The crate offers several ways in — `demangle`, `batch_demangle`,
//! `batch_demangle_parallel` (deduplicating via a shared cache) — and
//! `tests/concurrency.rs` already checks the batch pair against each other.
//! Two gaps remain: that comparison runs over a small hard-coded list, and the
//! cache-consistency test drives a *stub* demangler (`|s| s.to_uppercase()`),
//! so it exercises LRU mechanics rather than agreement with real decoding.
//!
//! A divergence here would be invisible in ordinary use and impossible to
//! reproduce from a single symbol: whether a caller got the right answer would
//! depend on which entry point it used and what ran before it.

fn corpora() -> Vec<&'static str> {
    include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

/// The sequential and deduplicating batch paths must agree with each other,
/// across the whole corpus.
#[test]
fn batch_paths_agree_with_each_other() {
    let syms = corpora();
    assert!(syms.len() > 6000, "corpora changed shape: {}", syms.len());

    let sequential = rustre_demangle::batch_demangle(&syms);
    let deduplicated = rustre_demangle::batch_demangle_parallel(&syms);
    assert_eq!(sequential.len(), syms.len());
    assert_eq!(deduplicated.len(), syms.len());

    let mut mismatches: Vec<(&str, String, String, &'static str)> = Vec::new();
    for (i, s) in syms.iter().enumerate() {
        if sequential[i].demangled != deduplicated[i].demangled {
            mismatches.push((
                s,
                sequential[i].demangled.clone(),
                deduplicated[i].demangled.clone(),
                "sequential vs deduplicated",
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} symbols differ between batch paths; first 10: {:#?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(10)]
    );
}

/// Repeating the whole corpus must not change any answer.
///
/// The deduplicating path keys a cache on the mangled string; a stale or
/// mis-keyed entry would surface as the second occurrence of a symbol
/// decoding differently from the first.
#[test]
fn repeated_symbols_decode_identically() {
    let syms = corpora();
    let doubled: Vec<&str> = syms.iter().chain(syms.iter()).copied().collect();

    let results = rustre_demangle::batch_demangle_parallel(&doubled);
    assert_eq!(results.len(), syms.len() * 2);

    let mut mismatches: Vec<(&str, String, String)> = Vec::new();
    for (i, s) in syms.iter().enumerate() {
        let (first, second) = (&results[i], &results[i + syms.len()]);
        if first.demangled != second.demangled {
            mismatches.push((s, first.demangled.clone(), second.demangled.clone()));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} symbols decoded differently on their second occurrence; first 10: {:#?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(10)]
    );
}

/// `demangle` itself must be a pure function of its input.
///
/// The dispatcher holds a process-wide `AutoDemangler` in a `OnceLock` and the
/// backends carry per-call substitution and back-reference tables; state
/// leaking between calls would show up as an answer that depends on what was
/// demangled before it.
#[test]
fn demangle_is_order_independent() {
    let syms = corpora();

    let forward: Vec<Option<String>> = syms
        .iter()
        .map(|s| rustre_demangle::demangle(s).map(|r| r.demangled))
        .collect();

    let mut backward: Vec<Option<String>> = syms
        .iter()
        .rev()
        .map(|s| rustre_demangle::demangle(s).map(|r| r.demangled))
        .collect();
    backward.reverse();

    let mismatches: Vec<&&str> = syms
        .iter()
        .zip(forward.iter().zip(backward.iter()))
        .filter(|(_, (f, b))| f != b)
        .map(|(s, _)| s)
        .collect();

    assert!(
        mismatches.is_empty(),
        "{} symbols decode differently depending on call order; first 10: {:#?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(10)]
    );
}

/// DOCUMENTED GAP: `batch_demangle` does not agree with `demangle`.
///
/// `batch_demangle` routes through `Demangler2` (`src/dispatch.rs`), a third
/// hand-rolled dispatcher alongside `AutoDemangler` and the MSVC parser's own.
/// It duplicates the routing logic, so the two drift apart whenever either
/// gains a feature. 391 corpus symbols decode differently, and the breakdown
/// matters more than the total because it shows this is not a subtle drift:
///
/// * **356** — `Demangler2` has **no Go support at all**. It returns
///   `internal/godebug.update.func1` unchanged where `demangle()` renders
///   `internal/godebug.update {closure-1 #1}`. (The other ~1800 Go symbols
///   agree only by accident: both yield the input, one by decoding it to
///   itself and one by failing to decode it.)
/// * **33** — the `.refptr.`/`__imp_` linker-wrapper unwrapping added to
///   `AutoDemangler` never reached `Demangler2`.
/// * **2** — legacy Rust hashes. `RustDemangler` renders with the alternate
///   `{:#}` formatter to drop the trailing `::h<16 hex>`; `Demangler2` keeps
///   it.
///
/// So converging them is not a refactor of shared logic — it is giving
/// `batch_demangle` an ABI it does not implement.
///
/// Asserted as the CORRECT behaviour and ignored, following the convention of
/// `fidelity_demangle.rs::fidelity_known_gaps`: the gap stays visible via
/// `cargo test -- --ignored` without turning CI red.
///
/// **Narrowed to Go only.** The divergence was 2199 corpus symbols; 36 of them
/// were missing capability rather than a missing ABI — 34 linker indirection
/// wrappers (`.refptr._ZN…`, `__imp__ZN…`) and 2 legacy Rust symbols that the
/// Itanium arm claimed, mislabelling the language *and* leaking the
/// disambiguator hash. Both are fixed and pinned by
/// `tests/demangler2_parity.rs`, which asserts parity on every ABI except Go.
///
/// What remains is exactly the 2163 Go symbols, and that is not a wiring job:
/// `MangleLanguage` has no `Go` variant, so closing it changes a public enum.
/// That is the deliberate decision this note asks for — and it is now the ONLY
/// thing standing between the two paths.
#[test]
#[ignore = "documents the Demangler2/AutoDemangler divergence; the assertion is the correct behaviour"]
fn batch_demangle_should_agree_with_demangle() {
    let syms = corpora();
    let batch = rustre_demangle::batch_demangle(&syms);

    let mismatches: Vec<(&str, String, String)> = syms
        .iter()
        .enumerate()
        .filter_map(|(i, s)| {
            let direct =
                rustre_demangle::demangle(s).map_or_else(|| (*s).to_owned(), |r| r.demangled);
            (batch[i].demangled != direct)
                .then(|| (*s, batch[i].demangled.clone(), direct))
        })
        .collect();

    assert!(
        mismatches.is_empty(),
        "{} symbols decode differently via batch_demangle; first 10: {:#?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(10)]
    );
}
