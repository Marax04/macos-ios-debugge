//! GCC emulated-TLS symbols wrap an ordinary mangled name.
//!
//! On targets without native thread-local storage (mingw-w64 among them) GCC
//! emits, for each `thread_local` variable, a control object `__emutls_v.<sym>`
//! and — when the variable has a non-zero initialiser — a template
//! `__emutls_t.<sym>`. The payload is the variable's own mangled name.
//!
//! Before this was handled the prefix hid a decodable symbol *and* produced
//! actively wrong metadata. `__emutls_v._ZZN12_GLOBAL__N_1L10get_globalEvE6global`
//! was claimed by the permissive Go backend — it contains dots, which is all
//! that detector needs — and echoed back unchanged with `abi: Go`. So a C++
//! thread-local was reported as a Go symbol, and an identity echo was counted
//! as a decode. The bare payload had always decoded correctly as Itanium; only
//! the prefix stood in the way.
//!
//! Treating these as linker wrappers rather than teaching a backend about them
//! is deliberate: the relationship is the one `.refptr.` already models. The
//! control object is an indirection *to* the variable, not the variable, so the
//! prefix is re-attached verbatim and the two stay distinguishable.

/// The real corpus symbol, and its initialiser-template sibling.
#[test]
fn emutls_symbols_decode_their_payload_and_keep_the_prefix() {
    for prefix in ["__emutls_v.", "__emutls_t."] {
        let sym = format!("{prefix}_ZZN12_GLOBAL__N_1L10get_globalEvE6global");
        let r = rustre_demangle::demangle(&sym).unwrap_or_else(|| panic!("{sym} must decode"));

        assert_eq!(
            r.demangled,
            format!("{prefix}(anonymous namespace)::get_global()::global"),
            "{sym}"
        );
        // The ABI must come from the payload. Reporting `Go` here was the
        // original defect, and it is the part no string comparison would catch.
        assert_eq!(
            format!("{:?}", r.abi),
            "Itanium",
            "{sym} must be attributed to the payload's ABI, not the wrapper's shape"
        );
        assert_eq!(r.original, sym, "`original` must retain the whole symbol");
    }
}

/// The payload alone is unaffected — guards against the prefix leaking in.
#[test]
fn the_bare_payload_still_decodes_without_a_prefix() {
    let r = rustre_demangle::demangle("_ZZN12_GLOBAL__N_1L10get_globalEvE6global")
        .expect("must decode");
    assert_eq!(r.demangled, "(anonymous namespace)::get_global()::global");
    assert!(
        !r.demangled.contains("emutls"),
        "wrapper prefix leaked into an unwrapped symbol: {}",
        r.demangled
    );
}

/// DISCRIMINATING CASE: a wrapper around a name that is *not* mangled must
/// still be declined.
///
/// This is what separates the fix from a plausible one that merely strips a
/// prefix and declares victory. `__emutls_v.` around a plain C identifier has
/// no demangling — C does not mangle — so the correct answer is to decline,
/// exactly as `.refptr._CRT_MT` already does. A fix that returned
/// `__emutls_v.counter` as a "decode" would inflate the corpus count with an
/// identity echo, which is the same defect in a new place rather than a fix.
#[test]
fn emutls_around_an_unmangled_name_is_declined() {
    for sym in ["__emutls_v.counter", "__emutls_t.my_tls_var"] {
        assert!(
            rustre_demangle::demangle(sym).is_none(),
            "{sym} has no demangling and must be declined, not echoed"
        );
    }
}

/// SEPARATE DEFECT, found by this fix and fixed in its own right: a bare
/// prefix with no payload is claimed by the Go detector.
///
/// `split_linker_wrapper` correctly refuses an empty payload, so `__emutls_v.`
/// falls through — and `GoDemangler::detect` accepted any name with a dot at a
/// position greater than zero, without requiring anything after it. A Go
/// symbol never ends in a dot.
///
/// Kept here because this file is where it surfaced, but the fix lives in
/// `go_demangler.rs` and is covered on its own terms in
/// `tests/go_trailing_dot.rs`.
#[test]
fn a_bare_prefix_is_not_a_wrapper() {
    for sym in ["__emutls_v.", "__emutls_t."] {
        assert!(
            rustre_demangle::demangle(sym).is_none(),
            "{sym} has no payload and must be declined"
        );
    }
}
