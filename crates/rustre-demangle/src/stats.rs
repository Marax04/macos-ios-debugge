//! Demangling statistics, benchmarking, and the memoising [`DemanglerCache`].

use crate::backends::RustDemangler;
use crate::core_types::Demangler;
use crate::demangler_cache::LruCore;

// ── DemanglerStats ────────────────────────────────────────────────────────────

/// Throughput statistics produced by [`DemanglerBenchmark`].
#[derive(Debug, Clone)]
pub struct DemanglerStats {
    /// Number of input symbols.
    pub input_count: usize,
    /// Number of symbols that demangled successfully.
    pub success_count: usize,
    /// Average nanoseconds per demangling call (wall-clock, single-threaded).
    pub avg_ns: u64,
}

impl DemanglerStats {
    /// Success ratio in [0.0, 1.0].
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.input_count == 0 {
            0.0
        } else {
            f64::from(u32::try_from(self.success_count).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(self.input_count).unwrap_or(u32::MAX))
        }
    }
}

// ── DemanglerBenchmark ────────────────────────────────────────────────────────

/// Benchmarks the demangling throughput of a symbol slice.
///
/// Timing uses [`std::time::Instant`] for wall-clock nanoseconds — results are
/// representative for single-threaded throughput on the calling machine.
pub struct DemanglerBenchmark;

/// Ten representative Rust mangled symbols used as a default test vector.
pub const RUST_TEST_VECTORS: [&str; 10] = [
    // Legacy v0 (Itanium-style with hash)
    "_ZN4core3fmt5Write9write_fmt17hf99c3d1b7fb38d5fE",
    "_ZN3std2io5Write9write_all17h3a9d5c7ef8b24d12E",
    "_ZN4core6option6Option6unwrap17hdeadbeef00000001E",
    "_ZN4core5slice4iter4Iter4next17h1234567890abcdefE",
    "_ZN3std7process4exit17hffffffffffffffffE",
    // Rust v0 mangling (`_R` prefix). These are REAL symbols lifted from
    // `tests/data/pdb_symbols.txt` (rustc 1.96), not hand-written: the five
    // that used to sit here were malformed — `_RNvNtCsf0_4core3fmt5Write9write_fmt`
    // carries two identifiers after the module where the grammar allows one —
    // and `rustc_demangle` rejected every one of them. The benchmark recorded
    // that as a 5/10 success rate, which no assertion read.
    // Nested module function.
    "_RNvNtCs189ThkfrTWj_4core3fmt5write",
    // Deeper module nesting.
    "_RNvNtNtCs189ThkfrTWj_4core3str8converts9from_utf8",
    // Inherent impl method (`Ms…` impl path).
    "_RNvMsa_NtCs189ThkfrTWj_4core3fmtNtB5_9Formatter9write_str",
    // Generic instantiation with a back-reference (`I…E`, `B4_`).
    "_RINvNtCs189ThkfrTWj_4core9panicking13assert_failedjjEB4_",
    // Crate-root function.
    "_RNvCs4SDFJOLwvtW_7___rustc14___rust_realloc",
];

impl DemanglerBenchmark {
    /// Benchmark Rust symbol demangling for `symbols`.
    ///
    /// Each symbol is demangled once in sequence; the total wall-clock time is
    /// divided by the count to produce `avg_ns`.  Returns a [`DemanglerStats`]
    /// with per-call latency and success rate.
    #[must_use]
    pub fn benchmark_rust(symbols: &[&str]) -> DemanglerStats {
        use std::time::Instant;
        let demangler = RustDemangler;
        let mut success_count = 0usize;
        let start = Instant::now();
        for &sym in symbols {
            if demangler.demangle(sym).is_some() {
                success_count += 1;
            }
        }
        let elapsed_ns = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let avg_ns = if symbols.is_empty() {
            0
        } else {
            elapsed_ns / symbols.len() as u64
        };
        DemanglerStats {
            input_count: symbols.len(),
            success_count,
            avg_ns,
        }
    }

    /// Run the built-in Rust test vectors and return statistics.
    #[must_use]
    pub fn benchmark_rust_defaults() -> DemanglerStats {
        Self::benchmark_rust(&RUST_TEST_VECTORS)
    }
}

// ── DemanglerCache ────────────────────────────────────────────────────────────

/// A memoising wrapper around a [`Demangler`] implementation with LRU-like
///
/// eviction: once the cache holds 10 000 entries, each new insertion evicts the
/// single **oldest** entry (insertion order) in O(1).
///
/// # Usage
/// ```rust
/// use rustre_demangle::{DemanglerCache, RustDemangler};
/// let demangler = RustDemangler;
/// let mut cache = DemanglerCache::new();
/// let result = cache.get_or_demangle("_RNvCsf0_5mylib3foo", &demangler);
/// println!("{result}");
/// ```
pub struct DemanglerCache {
    /// Shared LRU engine; never promotes, so eviction is insertion-ordered.
    entries: LruCore<String>,
    /// Total cache hits.
    hits: u64,
    /// Total lookups.
    lookups: u64,
}

impl DemanglerCache {
    /// Create a cache with the default capacity of 10 000 entries.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(10_000)
    }

    /// Create a cache with a custom capacity.
    #[must_use]
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            entries: LruCore::new(max_entries),
            hits: 0,
            lookups: 0,
        }
    }

    /// Return the demangled string for `mangled`, using the cache or calling
    /// `demangler` on a miss.
    ///
    /// Returns the demangled string if the demangler succeeds, or a clone of
    /// `mangled` as a fallback.
    pub fn get_or_demangle<D: Demangler>(&mut self, mangled: &str, demangler: &D) -> String {
        self.lookups += 1;
        if let Some(cached) = self.entries.peek(mangled) {
            self.hits += 1;
            return cached.clone();
        }
        // Miss — demangle and store. `insert_keep_order` evicts the single
        // oldest entry in O(1) once at capacity.
        let result = demangler
            .demangle(mangled).map_or_else(|| mangled.to_owned(), |r| r.demangled);
        self.entries
            .insert_keep_order(mangled.to_owned(), result.clone());
        result
    }

    /// Cache hit rate as a value in `[0.0, 1.0]`.
    ///
    /// Returns `0.0` if no lookups have been performed yet.
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        if self.lookups == 0 {
            0.0
        } else {
            f64::from(u32::try_from(self.hits).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(self.lookups).unwrap_or(u32::MAX))
        }
    }

    /// Number of entries currently stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Evict all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.hits = 0;
        self.lookups = 0;
    }
}

impl Default for DemanglerCache {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests for DemanglerBenchmark and DemanglerCache ───────────────────────────

#[cfg(test)]
mod benchmark_cache_tests {
    use super::*;

    #[test]
    fn test_benchmark_rust_defaults_runs() {
        let stats = DemanglerBenchmark::benchmark_rust_defaults();
        assert_eq!(stats.input_count, RUST_TEST_VECTORS.len());
        // avg_ns must be a non-negative integer (always true for u64).
        let _ = stats.avg_ns;
    }

    /// Every vector must actually demangle.
    ///
    /// `input_count` above only counts what was fed in, so it holds even if
    /// nothing decodes. That is how
    /// `_ZN3std7process4exit17hffffffffffffffff E` — a stray space before the
    /// terminating `E` — sat in this list undetected: the benchmark dutifully
    /// recorded a failure in `success_count` that no assertion read.
    #[test]
    fn every_rust_test_vector_demangles() {
        let failures: Vec<&&str> = RUST_TEST_VECTORS
            .iter()
            .filter(|s| crate::demangle(s).is_none())
            .collect();
        assert!(
            failures.is_empty(),
            "{} of {} test vectors do not demangle: {failures:#?}",
            failures.len(),
            RUST_TEST_VECTORS.len()
        );

        let stats = DemanglerBenchmark::benchmark_rust_defaults();
        assert_eq!(
            stats.success_count,
            RUST_TEST_VECTORS.len(),
            "the benchmark's own success count must agree"
        );
    }

    #[test]
    fn test_benchmark_rust_empty() {
        let stats = DemanglerBenchmark::benchmark_rust(&[]);
        assert_eq!(stats.input_count, 0);
        assert_eq!(stats.avg_ns, 0);
        assert_eq!(stats.success_count, 0);
    }

    #[test]
    fn test_benchmark_rust_success_rate_range() {
        let stats = DemanglerBenchmark::benchmark_rust_defaults();
        let rate = stats.success_rate();
        assert!((0.0..=1.0).contains(&rate));
    }

    #[test]
    fn test_benchmark_known_rust_v0_succeeds() {
        // _RNvCsf0_5mylib3foo is a valid v0 symbol.
        let stats = DemanglerBenchmark::benchmark_rust(&["_RNvCsf0_5mylib3foo"]);
        assert_eq!(stats.input_count, 1);
        assert_eq!(stats.success_count, 1);
    }

    #[test]
    fn test_benchmark_unknown_symbol_fails() {
        let stats = DemanglerBenchmark::benchmark_rust(&["malloc"]);
        assert_eq!(stats.success_count, 0);
    }

    #[test]
    fn test_demangler_cache_miss_then_hit() {
        let d = RustDemangler;
        let mut cache = DemanglerCache::new();
        let sym = "_RNvCsf0_5mylib3foo";
        let r1 = cache.get_or_demangle(sym, &d);
        let r2 = cache.get_or_demangle(sym, &d);
        assert_eq!(r1, r2);
        assert!(cache.hit_rate() > 0.0);
    }

    #[test]
    fn test_demangler_cache_fallback_on_failure() {
        let d = RustDemangler; // will not demangle "malloc"
        let mut cache = DemanglerCache::new();
        let result = cache.get_or_demangle("malloc", &d);
        assert_eq!(result, "malloc"); // fallback to original
    }

    #[test]
    fn test_demangler_cache_hit_rate_zero_before_use() {
        let cache = DemanglerCache::new();
        assert!(cache.hit_rate().abs() < f64::EPSILON);
    }

    #[test]
    fn test_demangler_cache_eviction() {
        let d = RustDemangler;
        let mut cache = DemanglerCache::with_capacity(10);
        // Insert 11 entries to trigger eviction.
        for i in 0..11u32 {
            cache.get_or_demangle(&format!("sym_{i}"), &d);
        }
        // After eviction, cache must be smaller than max_entries.
        assert!(cache.len() <= 10);
    }

    #[test]
    fn test_demangler_cache_clear_resets_hit_rate() {
        let d = RustDemangler;
        let mut cache = DemanglerCache::new();
        cache.get_or_demangle("_RNvCsf0_5mylib3foo", &d);
        cache.get_or_demangle("_RNvCsf0_5mylib3foo", &d);
        assert!(cache.hit_rate() > 0.0);
        cache.clear();
        assert!(cache.hit_rate().abs() < f64::EPSILON);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_demangler_stats_success_rate_full() {
        let stats = DemanglerStats {
            input_count: 4,
            success_count: 4,
            avg_ns: 100,
        };
        assert!((stats.success_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_demangler_stats_success_rate_zero_input() {
        let stats = DemanglerStats {
            input_count: 0,
            success_count: 0,
            avg_ns: 0,
        };
        assert!(stats.success_rate().abs() < f64::EPSILON);
    }

    #[test]
    fn test_rust_test_vectors_count() {
        assert_eq!(RUST_TEST_VECTORS.len(), 10);
    }
}

#[cfg(test)]
mod test_validator_input {
    use crate::DDemangler;
    
    #[test]
    fn test_d_demangle_validator_input() {
        let input = "_D3foo3barFZi";
        eprintln!("Input: {input}");
        eprintln!("Detect: {}", DDemangler::detect(input));
        
        let result = DDemangler::demangle(input);
        eprintln!("Result: {result:?}");
        
        assert!(result.is_some(), "Expected Some but got None");
    }
}

#[cfg(test)]
mod test_zn3fooev {
    use crate::ItaniumNativeDemangler;

    #[test]
    fn test_demangle_zn3fooev() {
        let result = ItaniumNativeDemangler::demangle("_ZN3fooEv");
        eprintln!("Result for _ZN3fooEv: {result:?}");
        assert!(result.is_some(), "Should demangle successfully");
        let s = result.unwrap();
        eprintln!("Demangled to: {s}");
        assert!(s.contains("foo"), "Should contain 'foo', got: {s}");
    }
}
