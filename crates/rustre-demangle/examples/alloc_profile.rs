//! Allocation profile of the hot demangling paths.
//!
//! Installs a counting global allocator and reports allocations + bytes per
//! `demangle` call, per ABI. Run before and after any allocation work to see
//! whether a change actually removed allocations rather than moving them.
//!
//! Run: cargo run --release -p rustre-demangle --example `alloc_profile`
// The library itself is unsafe-free (the workspace sets `unsafe_code = "warn"`).
// This diagnostic harness is the sole exception: a counting global allocator
// cannot be written in safe Rust, since `GlobalAlloc` is an unsafe trait. Every
// method here forwards verbatim to `System` and only bumps atomics.
#![allow(unsafe_code, reason = "a counting GlobalAlloc cannot be safe code")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);

struct Counting;

// SAFETY: every method forwards verbatim to `System`, which is a correct
// `GlobalAlloc`. The counters are atomics and do not allocate, so they cannot
// re-enter the allocator or alter the pointers being returned.
unsafe impl GlobalAlloc for Counting {
    // SAFETY: `layout` is forwarded unchanged to `System::alloc`, whose
    // contract is identical to this method's.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        // SAFETY: see above.
        unsafe { System.alloc(layout) }
    }

    // SAFETY: `ptr`/`layout` come from a matching `alloc` on this allocator,
    // which delegates to `System`, so `System::dealloc` is the correct pair.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: see above.
        unsafe { System.dealloc(ptr, layout) }
    }

    // SAFETY: `ptr`/`layout`/`new_size` are forwarded unchanged to
    // `System::realloc`, whose contract is identical to this method's.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(new_size.saturating_sub(layout.size()), Ordering::Relaxed);
        // SAFETY: see above.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static A: Counting = Counting;

/// `usize` → `f64` for the display-only ratios below, without a lossy cast.
///
/// The value is split into two 32-bit halves, each of which `f64::from`
/// converts exactly; scaling the high half by 2^32 is exact, so the single
/// rounding in the final addition is the same rounding a correct `x as f64`
/// would perform. The result is therefore bit-identical to the cast it
/// replaces, for every input, and the function is total.
fn to_f64(x: usize) -> f64 {
    const TWO_POW_32: f64 = 4_294_967_296.0;
    // None of these conversions can fail: `usize` is at most 64 bits, and both
    // halves are masked/shifted down to 32.
    let wide = u64::try_from(x).unwrap_or(u64::MAX);
    let hi = u32::try_from(wide >> 32).unwrap_or(u32::MAX);
    let lo = u32::try_from(wide & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    f64::from(hi).mul_add(TWO_POW_32, f64::from(lo))
}

fn measure(label: &str, sym: &str, iters: usize) {
    // Warm up any lazily-initialised state so it is not attributed per call.
    let _ = rustre_demangle::demangle(sym);

    let a0 = ALLOCS.load(Ordering::Relaxed);
    let b0 = BYTES.load(Ordering::Relaxed);
    for _ in 0..iters {
        std::hint::black_box(rustre_demangle::demangle(std::hint::black_box(sym)));
    }
    let allocs = ALLOCS.load(Ordering::Relaxed) - a0;
    let bytes = BYTES.load(Ordering::Relaxed) - b0;

    println!(
        "{label:<14} {:>7.1} allocs/call {:>9.1} bytes/call   [{sym}]",
        to_f64(allocs) / to_f64(iters),
        to_f64(bytes) / to_f64(iters),
    );
}

/// Measure an arbitrary closure, to attribute cost to a sub-path rather than
/// to the whole `demangle` call.
fn measure_fn<T>(label: &str, iters: usize, mut f: impl FnMut() -> T) {
    let _ = f();
    let a0 = ALLOCS.load(Ordering::Relaxed);
    let b0 = BYTES.load(Ordering::Relaxed);
    for _ in 0..iters {
        std::hint::black_box(f());
    }
    let allocs = ALLOCS.load(Ordering::Relaxed) - a0;
    let bytes = BYTES.load(Ordering::Relaxed) - b0;
    println!(
        "{label:<24} {:>7.1} allocs/call {:>9.1} bytes/call",
        to_f64(allocs) / to_f64(iters),
        to_f64(bytes) / to_f64(iters),
    );
}

fn main() {
    const ITERS: usize = 20_000;
    const MSVC: &str = "?GetValue@Widget@ns@@QEBAHXZ";
    println!("Allocation profile ({ITERS} iterations per case)\n");

    measure("itanium", "_ZN3foo3barEv", ITERS);
    measure("itanium/std", "_ZNSt6vectorIiSaIiEE9push_backERKi", ITERS);
    measure("msvc", MSVC, ITERS);
    measure("rust_legacy", "_ZN4core3fmt9Formatter3pad17h1234567890abcdefE", ITERS);
    measure("rust_v0", "_RNvNtCs1234_7mycrate3foo3bar", ITERS);
    measure("go", "net/http.(*Server).ListenAndServe", ITERS);
    measure("d", "_D4main3fooFZv", ITERS);
    measure("swift", "$s4main3fooyyF", ITERS);
    measure("miss", "plain_c_symbol", ITERS);

    println!("\nNote: a miss should be close to zero allocations — the dispatcher");
    println!("should reject a non-symbol on prefix inspection alone.");

    println!("\nMSVC breakdown (parsing vs result construction):");
    measure_fn("  parse only", ITERS, || {
        rustre_demangle::msvc_demangler::MsvcDemangler::demangle_to_string(MSVC)
    });
    measure_fn("  full demangle()", ITERS, || {
        rustre_demangle::demangle(MSVC)
    });
}
