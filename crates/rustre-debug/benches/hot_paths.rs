//! Benchmarks for rustre-debug hot paths.
//!
//! Run with: `cargo bench --release -p rustre-debug --bench hot_paths`
//!
//! Covers:
//! - `memory_search::search_buffer` (SIMD first-byte scan via memchr)
//! - `memory_search::search_all_regions` (rayon parallel scan)
//! - `watchpoint_engine::simd_scan_hw_registers_runtime` (AVX2 register scan)
//! - `debug_session_manager::alloc_session_id` (cache-line-aligned atomic)

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rustre_debug::memory_search::{MemoryRegion, MemorySearch, SearchPattern};
use rustre_debug::watchpoint_engine::simd_scan_hw_registers_runtime;

// ── search_buffer: exact bytes ────────────────────────────────────────────────

fn bench_search_buffer_exact(c: &mut Criterion) {
    let sizes: &[usize] = &[64 * 1024, 1024 * 1024, 16 * 1024 * 1024];
    let needle = b"\xDE\xAD\xBE\xEF";
    let mut group = c.benchmark_group("search_buffer/exact_bytes");
    for &sz in sizes {
        let mut data = vec![0u8; sz];
        // Place one hit near the end
        let hit = sz.saturating_sub(64);
        data[hit..hit + 4].copy_from_slice(needle);
        let pattern = SearchPattern::bytes(needle.to_vec()).unwrap();
        group.throughput(Throughput::Bytes(sz as u64));
        group.bench_with_input(BenchmarkId::from_parameter(sz), &sz, |b, _| {
            b.iter(|| {
                MemorySearch::default_options()
                    .search_buffer(&data, 0, &pattern, 0, None)
                    .unwrap()
            });
        });
    }
    group.finish();
}

// ── search_all_regions: parallel ──────────────────────────────────────────────

fn bench_search_all_regions(c: &mut Criterion) {
    let n_regions = 64usize;
    let region_size = 256 * 1024usize; // 256 KB each
    let total = n_regions * region_size;
    let mut data = vec![0u8; total];
    // Seed one hit per region
    for i in 0..n_regions {
        let off = i * region_size + region_size / 2;
        data[off] = 0xAA;
        data[off + 1] = 0xBB;
    }
    let regions: Vec<MemoryRegion> = (0..n_regions)
        .map(|i| MemoryRegion::readable((i * region_size) as u64, region_size, None))
        .collect();
    let pattern = SearchPattern::bytes(vec![0xAA, 0xBB]).unwrap();
    let mut group = c.benchmark_group("search_all_regions");
    group.throughput(Throughput::Bytes(total as u64));
    group.bench_function("parallel_64_regions", |b| {
        b.iter(|| {
            MemorySearch::default_options()
                .search_all_regions(&data, &regions, &pattern)
                .unwrap()
        });
    });
    group.finish();
}

// ── simd_scan_hw_registers_runtime ───────────────────────────────────────────

fn bench_simd_scan_hw_registers(c: &mut Criterion) {
    let hw_addrs = [0x1000u64, 0x2000, 0x3000, 0x4000];
    c.bench_function("simd_scan_hw_registers/hit", |b| {
        b.iter(|| simd_scan_hw_registers_runtime(0x3000, hw_addrs));
    });
    c.bench_function("simd_scan_hw_registers/miss", |b| {
        b.iter(|| simd_scan_hw_registers_runtime(0xDEAD, hw_addrs));
    });
}

// ── session id allocation ─────────────────────────────────────────────────────

fn bench_session_id_alloc(c: &mut Criterion) {
    use rustre_debug::debug_session_manager::{DebugTarget, DebugSession};
    c.bench_function("session_id_alloc", |b| {
        b.iter(|| {
            DebugSession::new(
                DebugTarget::Process { pid: 1234, process_name: "test".into() },
                "x86_64".into(),
            )
        });
    });
}

criterion_group!(
    benches,
    bench_search_buffer_exact,
    bench_search_all_regions,
    bench_simd_scan_hw_registers,
    bench_session_id_alloc,
);
criterion_main!(benches);
