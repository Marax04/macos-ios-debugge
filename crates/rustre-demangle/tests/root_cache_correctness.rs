//! The crate-root `DemanglerCache` must return what `demangle` returns.
//!
//! This crate has **three** distinct types called `DemanglerCache`:
//! `demangler_cache::DemanglerCache`, `demangler_registry::DemanglerCache`, and
//! `stats::DemanglerCache` — the last being the one re-exported at the crate root
//! and therefore the one a consumer reaches first. (The crate CLAUDE.md records
//! "two"; there are three.)
//!
//! `tests/cache_correctness.rs` covers the `demangler_cache` one. The root
//! re-export had **no correctness coverage at all** — only the mechanics tests in
//! `tests/concurrency.rs`, which drive a stub demangler and so prove capacity and
//! thread-safety while saying nothing about whether a cached answer matches the
//! real one.
//!
//! Measured on 2026-07-30: 12936 lookups over both corpora at three capacities
//! (16, 256, 100 000 — the first two force heavy eviction and recomputation),
//! **0 mismatches**. No defect; the gap was in the coverage, not the code.

use rustre_demangle::{Demangler, DemanglerCache, DemanglingResult};

/// The live path wrapped as a `Demangler`, so the cache calls the real thing
/// rather than a stub. Using a stub is exactly what made the existing mechanics
/// tests blind to correctness.
struct Live;

impl Demangler for Live {
    fn detect(&self, s: &str) -> bool {
        rustre_demangle::demangle(s).is_some()
    }
    fn demangle(&self, s: &str) -> Option<DemanglingResult> {
        rustre_demangle::demangle(s)
    }
}

fn corpus() -> Vec<&'static str> {
    include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

/// `get_or_demangle` must agree with the uncached path — on the miss, on the
/// hit, and after eviction has forced a recomputation.
#[test]
fn the_root_cache_agrees_with_the_live_path_under_eviction() {
    let syms = corpus();
    assert!(syms.len() > 6000, "corpus changed shape: {}", syms.len());

    // Capacities chosen so the first two cannot hold the corpus: every entry is
    // evicted and recomputed, which is where a mis-keyed or stale entry appears.
    for cap in [16usize, 256, 100_000] {
        let mut cache = DemanglerCache::with_capacity(cap);
        let mut mismatches: Vec<String> = Vec::new();
        let mut checked = 0;

        // Two passes: the second consists of hits and post-eviction recomputes.
        for _pass in 0..2 {
            for s in &syms {
                // `get_or_demangle` falls back to a clone of the input when the
                // demangler declines, so the expectation must do the same.
                let want = rustre_demangle::demangle(s)
                    .map_or_else(|| (*s).to_owned(), |r| r.demangled);
                let got = cache.get_or_demangle(s, &Live);
                checked += 1;
                if got != want {
                    mismatches.push(format!("{s}\n  want: {want}\n  got:  {got}"));
                }
            }
        }

        assert!(checked > 12000, "vacuous at cap={cap}: only {checked} lookups");
        assert!(
            mismatches.is_empty(),
            "cap={cap}: {} cached answers differ from the live path; first 3: {:#?}",
            mismatches.len(),
            &mismatches[..mismatches.len().min(3)]
        );
    }
}

/// The documented eviction policy is insertion-ordered, not LRU.
///
/// The field doc says "Shared LRU engine; **never promotes**, so eviction is
/// insertion-ordered". That is a claim about behaviour, so it is checkable: with
/// capacity 2, insert A then B, touch A, then insert C. A true LRU would evict B
/// (least recently used); an insertion-ordered cache evicts A.
///
/// Asserted because a *silent* switch to promotion would change eviction order
/// for every consumer while every correctness test above still passed — the
/// answers would stay right, only the hit pattern would move.
#[test]
fn the_root_cache_does_not_promote_on_access() {
    let mut cache = DemanglerCache::with_capacity(2);
    let (a, b, c) = ("_Z1av", "_Z1bv", "_Z1cv");

    cache.get_or_demangle(a, &Live);
    cache.get_or_demangle(b, &Live);
    assert_eq!(cache.len(), 2, "both entries should be resident");

    // Touch A. Under a promoting LRU this makes A the most recent.
    cache.get_or_demangle(a, &Live);

    // Insert C: one of A or B must go.
    cache.get_or_demangle(c, &Live);
    assert_eq!(cache.len(), 2, "capacity must be respected");

    // If A survived, the cache promoted on access and the doc is wrong. Detect
    // it by hit rate: re-requesting A is a hit only if A is still resident.
    let before = cache.hit_rate();
    cache.get_or_demangle(a, &Live);
    let a_was_resident = cache.hit_rate() > before;
    assert!(
        !a_was_resident,
        "A survived eviction, so the cache promotes on access — the field doc \
         says it never promotes and eviction is insertion-ordered"
    );
}
