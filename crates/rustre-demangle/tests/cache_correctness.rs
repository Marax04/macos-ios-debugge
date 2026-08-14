//! `DemanglerCache` must return what the demangler would have returned.
//!
//! `tests/concurrency.rs` already drives this cache hard, but with a *stub*
//! demangler (`|s| Ok(s.to_uppercase())`): that proves the LRU mechanics —
//! capacity, eviction, thread-safety — while saying nothing about whether a
//! cached answer matches the real one. A cache that serves a stale or
//! mis-keyed entry is a correctness bug no mechanics test can see, and it is
//! the kind that only appears under eviction pressure with real inputs.
//!
//! So: wrap the actual demangler, run the real corpus through, and compare
//! every answer against the uncached path — on the miss, on the hit, and after
//! the entry has been evicted and recomputed.

use std::sync::Arc;

use rustre_demangle::demangler_cache::DemanglerCache;

fn corpus() -> Vec<&'static str> {
    include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

/// The cache's own contract: `demangle` returns the input unchanged when the
/// backing function declines, so compare against that same convention.
fn direct(s: &str) -> String {
    rustre_demangle::demangle(s).map_or_else(|| s.to_owned(), |r| r.demangled)
}

fn real_cache(capacity: usize) -> DemanglerCache {
    DemanglerCache::new(
        capacity,
        Arc::new(|s: &str| {
            Ok(rustre_demangle::demangle(s).map_or_else(|| s.to_owned(), |r| r.demangled))
        }),
    )
}

/// A cache large enough to hold everything must never alter an answer, and
/// must give the same answer on the second pass (the hit path).
#[test]
fn cached_answers_match_uncached_on_miss_and_hit() {
    let syms = corpus();
    let cache = real_cache(syms.len() * 2);

    let mut mismatches: Vec<(&str, String, String, &'static str)> = Vec::new();
    for s in &syms {
        let want = direct(s);
        let miss = cache.demangle(s);
        if miss != want {
            mismatches.push((s, want.clone(), miss, "miss"));
            continue;
        }
        let hit = cache.demangle(s);
        if hit != want {
            mismatches.push((s, want, hit, "hit"));
        }
    }

    assert!(
        mismatches.is_empty(),
        "{} cached answers differ from the uncached path; first 10: {:#?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(10)]
    );
}

/// Under eviction pressure every entry is recomputed many times over. A
/// mis-keyed insert or a stale read surfaces here and nowhere else.
#[test]
fn answers_survive_eviction_pressure() {
    let syms = corpus();
    // Far smaller than the corpus, so almost every lookup evicts something.
    let cache = real_cache(64);

    let mut mismatches: Vec<(&str, String, String)> = Vec::new();
    // A straight scan of a deduplicated corpus produces evictions but no hits
    // at all — every entry is gone before the pass comes round again — so it
    // would exercise only half of what this test is named for. Interleaving a
    // small hot set keeps some entries live while the cold stream evicts
    // around them, which is where a mis-keyed insert or a stale read shows up.
    let hot: Vec<&str> = syms.iter().take(16).copied().collect();
    for (i, s) in syms.iter().enumerate() {
        for probe in [*s, hot[i % hot.len()]] {
            let got = cache.demangle(probe);
            let want = direct(probe);
            if got != want {
                mismatches.push((probe, want, got));
            }
        }
    }

    let stats = cache.stats();
    println!(
        "capacity {} — {} hits, {} misses",
        stats.capacity, stats.hits, stats.misses
    );
    assert!(
        mismatches.is_empty(),
        "{} answers went wrong under eviction; first 10: {:#?}",
        mismatches.len(),
        &mismatches[..mismatches.len().min(10)]
    );
    // Guard the guard: without hits this measures eviction only.
    assert!(
        stats.hits > 1000,
        "expected the hot set to produce many hits, got {} — this test is \
         no longer exercising the cached path",
        stats.hits
    );
}

/// The cache must actually be caching: if every lookup were a miss the tests
/// above would pass while exercising none of the hit or eviction paths.
#[test]
fn the_cache_is_not_vacuous() {
    let syms: Vec<&str> = corpus().into_iter().take(500).collect();
    let cache = real_cache(1024);

    for s in &syms {
        let _ = cache.demangle(s);
    }
    for s in &syms {
        let _ = cache.demangle(s);
    }

    let stats = cache.stats();
    let expected = u64::try_from(syms.len()).expect("corpus slice fits in u64");
    assert!(
        stats.hits >= expected,
        "expected at least {expected} hits on the second pass, got {}",
        stats.hits
    );
}
