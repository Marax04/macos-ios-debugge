//! Allocation profile of the hot demangling paths.
//!
//! Installs a counting global allocator and reports allocations + bytes per
//! `demangle` call, per ABI. Run before and after any allocation work to see
//! whether a change actually removed allocations rather than moving them.
//!
//! Run: cargo run --release -p rustre-demangle --example `alloc_profile`
#![allow(
    clippy::cast_precision_loss,
    reason = "profiling harness: the reported averages are display-only"
)]
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
        allocs as f64 / iters as f64,
        bytes as f64 / iters as f64,
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
        allocs as f64 / iters as f64,
        bytes as f64 / iters as f64,
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
