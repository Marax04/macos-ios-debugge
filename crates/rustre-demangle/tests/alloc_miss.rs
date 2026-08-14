//! A rejected symbol must not allocate.
//!
//! `examples/alloc_profile.rs` notes this in prose — "a miss should be close to
//! zero allocations, the dispatcher should reject a non-symbol on prefix
//! inspection alone" — but nothing enforced it, and the dispatch path is where
//! pre-checks accumulate. Three were added on 2026-07-23 (`.refptr.`/`__imp_`
//! unwrapping, GCC clone suffixes, the linker constant pool); a single
//! `to_owned()` in any of them would cost an allocation on every symbol the
//! crate declines, which on a real corpus is the majority.
//!
//! This is also the cheapest proof that those pre-checks are allocation-free:
//! a miss traverses all of them before being rejected.
// The library itself is unsafe-free (the workspace sets `unsafe_code = "warn"`).
// Like `examples/alloc_profile.rs`, this harness is an exception: a counting
// global allocator cannot be written in safe Rust, since `GlobalAlloc` is an
// unsafe trait. Every method forwards verbatim to `System` and only bumps an
// atomic.
#![allow(unsafe_code, reason = "a counting GlobalAlloc cannot be safe code")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

static ALLOCS: AtomicUsize = AtomicUsize::new(0);

struct Counting;

// SAFETY: forwards every call to `System` unchanged, only incrementing a
// counter alongside — the allocator contract is upheld by the delegate.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Count allocations performed while `f` runs.
fn allocs_during(f: impl FnOnce()) -> usize {
    let before = ALLOCS.load(Ordering::Relaxed);
    f();
    ALLOCS.load(Ordering::Relaxed) - before
}

/// Whatever the dispatcher declines, it must decline without allocating.
///
/// Drawn from the real corpus rather than hand-picked, so this cannot drift
/// from what the crate actually rejects. Note that a dotted name like
/// `some.dotted.name` is NOT a miss — the Go detector claims any dotted name
/// by design — so which inputs decline is measured, not assumed.
#[test]
fn declining_a_symbol_allocates_nothing() {
    let corpus: Vec<&str> = include_str!("data/real_symbols.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();

    // Warm lazily-initialised state: the shared `AutoDemangler` is built on
    // first use, and that construction would otherwise be charged to the first
    // symbol measured.
    for s in corpus.iter().take(200) {
        let _ = rustre_demangle::demangle(s);
    }

    let mut declined = 0usize;
    let mut offenders: Vec<(&str, usize)> = Vec::new();
    for s in &corpus {
        if rustre_demangle::demangle(s).is_some() {
            continue;
        }
        declined += 1;
        let n = allocs_during(|| {
            let _ = rustre_demangle::demangle(s);
        });
        if n != 0 {
            offenders.push((s, n));
        }
    }

    println!("{declined} declined symbols measured");
    assert!(
        declined > 2000,
        "only {declined} symbols declined — the corpus or the dispatcher changed shape"
    );
    assert!(
        offenders.is_empty(),
        "{} declined symbols allocated; first 10: {:#?}",
        offenders.len(),
        &offenders[..offenders.len().min(10)]
    );
}
