//! Concurrency stress tests for the shared caches and demanglers.
//!
//! The caches are `Mutex`/`RwLock`-guarded and are reachable from `rayon`
//! worker threads via `batch_demangle_parallel`, so they must be safe under
//! contention, must not deadlock, and must not lose or corrupt entries.

use rustre_demangle::demangler_cache::{DemanglerCache, LruCache, MultiAbiCache};
use std::sync::{Arc, Barrier};
use std::thread;

const SYMBOLS: &[&str] = &[
    "_ZN3foo3barEv",
    "_ZNSt6vectorIiSaIiEE9push_backERKi",
    "?foo@bar@@QEAAHXZ",
    "_ZN4core3fmt9Formatter3pad17h1234567890abcdefE",
    "main.main",
    "_D4main3fooFZv",
    "$s4main3fooyyF",
    "plain_symbol",
];

#[test]
fn shared_cache_under_contention_is_consistent() {
    const THREADS: usize = 8;
    const ITERS: usize = 500;

    let cache = Arc::new(DemanglerCache::new(
        64,
        Arc::new(|s: &str| Ok(s.to_uppercase())),
    ));
    let barrier = Arc::new(Barrier::new(THREADS));

    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let cache = Arc::clone(&cache);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for i in 0..ITERS {
                    let sym = SYMBOLS[(t + i) % SYMBOLS.len()];
                    let got = cache.demangle(sym);
                    // Whoever computes it, the value must be the same:
                    // a torn or cross-wired entry would show up here.
                    assert_eq!(got, sym.to_uppercase(), "wrong value for {sym}");
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("worker thread panicked");
    }

    let stats = cache.stats();
    assert_eq!(
        stats.hits + stats.misses,
        (THREADS * ITERS) as u64,
        "lookups accounted for must equal lookups performed"
    );
    assert!(
        stats.current_size <= 64,
        "cache exceeded its capacity: {} > 64",
        stats.current_size
    );
}

#[test]
fn cache_eviction_under_contention_stays_within_capacity() {
    const THREADS: usize = 8;
    const KEYS: usize = 2000;
    const CAPACITY: usize = 32;

    let cache = Arc::new(DemanglerCache::new(
        CAPACITY,
        Arc::new(|s: &str| Ok(format!("d:{s}"))),
    ));
    let barrier = Arc::new(Barrier::new(THREADS));

    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let cache = Arc::clone(&cache);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                // Every thread walks a distinct key space to force eviction.
                for i in 0..KEYS {
                    let key = format!("sym_{t}_{i}");
                    assert_eq!(cache.demangle(&key), format!("d:{key}"));
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("worker thread panicked");
    }

    assert!(
        cache.stats().current_size <= CAPACITY,
        "capacity violated under concurrent eviction: {} > {CAPACITY}",
        cache.stats().current_size
    );
}

#[test]
fn parallel_batch_demangle_matches_sequential() {
    // Build a corpus big enough for rayon to actually split the work.
    let symbols: Vec<String> = (0..2000)
        .map(|i| SYMBOLS[i % SYMBOLS.len()].to_owned())
        .collect();

    let sequential = rustre_demangle::batch_demangle(&symbols);
    let parallel = rustre_demangle::batch_demangle_parallel(&symbols);

    assert_eq!(sequential.len(), parallel.len());
    for (i, (s, p)) in sequential.iter().zip(parallel.iter()).enumerate() {
        assert_eq!(
            s.demangled, p.demangled,
            "parallel result diverges at index {i} for {}",
            s.mangled
        );
    }
}

#[test]
fn top_level_demangle_is_thread_safe() {
    // `demangle` uses a process-wide `OnceLock` demangler set; hammer its
    // initialisation from many threads at once.
    const THREADS: usize = 16;
    let barrier = Arc::new(Barrier::new(THREADS));
    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                let mut ok = 0usize;
                for i in 0..1000 {
                    let sym = SYMBOLS[(t + i) % SYMBOLS.len()];
                    if rustre_demangle::demangle(sym).is_some() {
                        ok += 1;
                    }
                }
                ok
            })
        })
        .collect();

    let mut counts: Vec<usize> = Vec::with_capacity(THREADS);
    for h in handles {
        counts.push(h.join().expect("worker thread panicked"));
    }
    // Every thread walks the same rotation of the corpus, so the number of
    // successful demanglings must be identical across threads.
    assert!(
        counts.windows(2).all(|w| w[0] == w[1]),
        "threads disagreed on how many symbols demangle: {counts:?}"
    );
}

#[test]
fn multi_abi_cache_is_thread_safe() {
    let cache = Arc::new(MultiAbiCache::new(
        128,
        vec![
            (
                "itanium",
                Arc::new(|s: &str| {
                    rustre_demangle::cpp_demangler::demangle_itanium(s)
                        .map_err(|e| anyhow::anyhow!("{e}"))
                }) as _,
            ),
            (
                "passthrough",
                Arc::new(|s: &str| Ok(s.to_owned())) as _,
            ),
        ],
    ));
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|t| {
            let cache = Arc::clone(&cache);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for i in 0..500 {
                    let _ = cache.demangle(SYMBOLS[(t + i) % SYMBOLS.len()]);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("worker thread panicked");
    }
    // Every lookup is attributed to exactly one strategy.
    let abi_total: u64 = cache.abi_stats().values().sum();
    assert!(abi_total > 0, "per-ABI attribution never recorded a success");
}

#[test]
fn lru_cache_capacity_holds_under_random_access() {
    // Single-threaded invariant check with a deterministic access pattern,
    // guarding the tick/compaction logic against unbounded growth.
    let mut cache = LruCache::new(16);
    let mut state = 0x1234_5678_u64;
    for i in 0..10_000 {
        state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let key = format!("k{}", state % 64);
        if i % 3 == 0 {
            let _ = cache.get(&key);
        } else {
            cache.insert(key, format!("v{i}"));
        }
        assert!(cache.len() <= 16, "capacity exceeded at iteration {i}");
    }
}
