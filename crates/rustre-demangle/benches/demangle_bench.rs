//! Criterion benchmarks for the demangling hot paths.
//! Run: cargo bench -p rustre-demangle

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use std::hint::black_box;

const ITANIUM: &str = "_ZNSt6vectorIiSaIiEE9push_backERKi";
const ITANIUM_LONG: &str =
    "_ZN9__gnu_cxx17__normal_iteratorIPKcNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEEppEv";
const MSVC: &str = "?GetValue@Widget@ns@@QEBAHXZ";
const RUST_LEGACY: &str = "_ZN4core3fmt9Formatter3pad17h1234567890abcdefE";
const GO: &str = "net/http.(*Server).ListenAndServe";

fn bench_single(c: &mut Criterion) {
    let mut g = c.benchmark_group("demangle_single");
    for (name, sym) in [
        ("itanium", ITANIUM),
        ("itanium_long", ITANIUM_LONG),
        ("msvc", MSVC),
        ("rust_legacy", RUST_LEGACY),
        ("go", GO),
        ("miss_plain", "plain_c_symbol"),
    ] {
        g.bench_function(name, |b| {
            b.iter(|| rustre_demangle::demangle(black_box(sym)));
        });
    }
    g.finish();
}

fn bench_cache(c: &mut Criterion) {
    let mut g = c.benchmark_group("lru_cache");
    // Hot-hit path: repeated promotion of the same small working set.
    g.bench_function("hit_promote_1k_capacity", |b| {
        b.iter_batched(
            || {
                let mut cache = rustre_demangle::demangler_cache::LruCache::new(1024);
                for i in 0..1024 {
                    cache.insert(format!("k{i}"), format!("v{i}"));
                }
                cache
            },
            |mut cache| {
                for i in 0..1024 {
                    black_box(cache.get(&format!("k{}", i % 64)));
                }
            },
            BatchSize::SmallInput,
        );
    });
    // Churn path: sustained eviction pressure past capacity.
    g.bench_function("insert_evict_churn", |b| {
        b.iter_batched(
            || rustre_demangle::demangler_cache::LruCache::new(256),
            |mut cache| {
                for i in 0..2048 {
                    cache.insert(format!("k{i}"), format!("v{i}"));
                }
                black_box(cache.len())
            },
            BatchSize::SmallInput,
        );
    });
    g.finish();
}

fn bench_batch(c: &mut Criterion) {
    let symbols: Vec<String> = (0..256)
        .map(|i| match i % 4 {
            0 => format!("_ZN3foo{}barEv", i % 10),
            1 => MSVC.to_owned(),
            2 => RUST_LEGACY.to_owned(),
            _ => GO.to_owned(),
        })
        .collect();
    c.bench_function("batch_demangle_256", |b| {
        b.iter(|| rustre_demangle::batch_demangle(black_box(&symbols)));
    });
}

criterion_group!(benches, bench_single, bench_cache, bench_batch);
criterion_main!(benches);
