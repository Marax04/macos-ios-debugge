//! GCC clone-suffix names are C, not Go: correctly declined and classified.
//!
//! `-freorder-blocks-and-partition` and the interprocedural optimisers emit
//! transformation clones — `classify.cold` (cold-path split),
//! `d_encoding.part.0` (partial inlining), `next_is_type_qual.isra.0` (scalar
//! replacement of aggregates), `d_demangle_callback.constprop.0` (constant
//! propagation). Each is a C function name with a compiler suffix; there is no
//! demangling. They contain a dot, so the permissive Go detector would claim
//! them and invent closure structure — hence they must be recognised as C and
//! declined. All twelve of these appear in the real corpus; before this they
//! were bucketed as `go-like` and their correct declines dragged Go's measured
//! coverage from a true 100% down to 99.4%.

#[test]
fn clone_suffixes_are_recognised_as_c() {
    for s in [
        "classify.cold",
        "d_demangle_callback.constprop.0",
        "d_encoding.part.0",
        "next_is_type_qual.isra.0",
        "pthread_once.cold",
        "push_pthread_mem.part.0",
    ] {
        assert!(
            rustre_demangle::decline::is_gcc_clone(s),
            "{s} should be recognised as a GCC clone (C, not Go)"
        );
        assert!(
            rustre_demangle::demangle(s).is_none(),
            "{s} is a C name with a compiler suffix — nothing to demangle"
        );
    }
}

#[test]
fn plain_go_symbols_are_not_mistaken_for_clones() {
    // A real Go symbol is dotted too, but carries a named component after the
    // package and no clone tag — it must NOT be swept up by the clone rule, or
    // the exclusion would start hiding genuine Go coverage.
    for s in ["runtime.main", "fmt.Println", "sync.(*Once).Do"] {
        assert!(
            !rustre_demangle::decline::is_gcc_clone(s),
            "{s} is a Go symbol, not a GCC clone"
        );
    }
}
