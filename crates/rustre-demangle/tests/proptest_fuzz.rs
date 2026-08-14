//! Property-based fuzzing: no input may panic, hang, or violate basic
//! output invariants of the public demangling API.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 2048,
        max_shrink_iters: 4096,
        ..ProptestConfig::default()
    })]

    /// Arbitrary bytes-as-string must never panic the top-level dispatcher.
    #[test]
    fn demangle_never_panics_on_arbitrary_input(s in "\\PC*") {
        let _ = rustre_demangle::demangle(&s);
    }

    /// ASCII garbage behind each known mangling prefix must never panic
    /// any scheme-specific path.
    #[test]
    fn demangle_never_panics_on_prefixed_input(
        prefix in prop::sample::select(vec!["_Z", "__Z", "?", "_R", "_D", "$s", "_$s", "@", "-[", "go:"]),
        body in "[ -~]{0,128}",
    ) {
        let sym = format!("{prefix}{body}");
        let _ = rustre_demangle::demangle(&sym);
        let _ = rustre_demangle::cpp_demangler::demangle_cpp(&sym);
        let _ = rustre_demangle::go_demangler::decode_go_symbol(&sym, true);
    }

    /// Deeply nested Itanium type-modifier chains must terminate quickly
    /// (depth guards) instead of overflowing the stack.
    #[test]
    fn deep_modifier_chains_terminate(
        modifier in prop::sample::select(vec!["P", "R", "O", "K", "V"]),
        depth in 1usize..2000,
    ) {
        let sym = format!("_Z1f{}i", modifier.repeat(depth));
        let _ = rustre_demangle::cpp_demangler::demangle_itanium(&sym);
    }

    /// Output invariants: a successful demangle must echo the original
    /// symbol and produce a non-empty demangled string.
    #[test]
    fn successful_results_are_well_formed(s in "[ -~]{1,64}") {
        if let Some(result) = rustre_demangle::demangle(&s) {
            prop_assert_eq!(&result.original, &s);
            prop_assert!(!result.demangled.is_empty());
        }
    }

    /// The classifier and the dispatcher must not disagree wildly: symbols
    /// the dispatcher demangles as Itanium must at least start with `_Z`/`__Z`.
    #[test]
    fn itanium_results_only_from_itanium_prefixes(s in "[ -~]{1,64}") {
        if let Some(result) = rustre_demangle::demangle(&s)
            && result.abi == rustre_demangle::ManglingAbi::Itanium {
            prop_assert!(s.starts_with("_Z") || s.starts_with("__Z"));
        }
    }
}
