//! GCC IPA clone suffixes (`.isra.N`, `.part.N`, `.constprop.N`, `.cold`).
//!
//! These name a specialised copy of a function created by interprocedural
//! optimisation. They contain dots, which used to be enough for the permissive
//! Go detector to claim them and fabricate closure structure:
//! `__pformat_int.isra.0` decoded as `__pformat_int.isra {closure-1 #?}`.
//! A clone suffix is proof the symbol is C/C++, never Go.

/// A C function with a clone suffix is not Go and must not acquire invented
/// closure structure. `c++filt` leaves such names alone, so declining is the
/// faithful answer.
#[test]
fn c_function_with_clone_suffix_is_not_a_go_closure() {
    for s in [
        "__pformat_int.isra.0",
        "__pthread_rwlock_timedrdlock.part.0",
        "_Unwind_ForcedUnwind_Phase2.isra.0",
        "_pthread_once_raw.constprop.0.isra.0",
        "__pthread_self_lite.part.0.cold",
    ] {
        match rustre_demangle::demangle(s) {
            None => {}
            Some(r) => panic!("{s} must be declined, got {}", r.demangled),
        }
    }
}

/// An Itanium symbol with a clone suffix still decodes, and keeps the
/// `[clone …]` annotation.
#[test]
fn itanium_symbol_with_clone_suffix_decodes() {
    let r = rustre_demangle::demangle("_ZN12_GLOBAL__N_14pool4freeEPv.constprop.0")
        .expect("clone-suffixed Itanium symbol must decode");
    assert!(
        r.demangled.contains("pool::free"),
        "payload must decode: {}",
        r.demangled
    );
    assert!(
        r.demangled.contains("[clone"),
        "clone annotation must survive: {}",
        r.demangled
    );
}

/// Real Go symbols must keep working: `.func1` is a closure, not a clone
/// suffix, and ordinary package-qualified names are untouched.
#[test]
fn go_symbols_are_unaffected() {
    for s in [
        "main.main",
        "runtime.gcBgMarkWorker",
        "internal/godebug.update.func1",
    ] {
        assert!(
            rustre_demangle::demangle(s).is_some(),
            "{s} must still decode"
        );
    }
}

/// A leading marker would leave an empty base; such a name is not a clone.
#[test]
fn leading_marker_is_not_a_clone_suffix() {
    assert!(rustre_demangle::demangle(".isra.0").is_none());
    assert!(rustre_demangle::demangle(".cold").is_none());
}
