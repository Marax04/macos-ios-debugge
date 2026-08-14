//! Regression tests for the `Ss`-constructor dropped-parameter repair
//! (`backends::repair_ss_ctor_dropped_param`).
//!
//! `cpp_demangle` ≤ 0.4.5 loses the `S2_` parameter in `std::string`
//! template constructors; `c++filt` (binutils) is the ground truth here and
//! every expected string below was produced by it (modulo the crate's usual
//! `std::basic_string<…>` → `std::string` abbreviation, which `cpp_demangle`
//! applies on both sides). The free-function `T_S2_` shapes are rendered
//! correctly by upstream and must stay untouched.

use rustre_demangle::demangle;

fn text(sym: &str) -> String {
    demangle(sym).map(|r| r.demangled).unwrap_or_default()
}

/// The defective class: both `C1` (complete) and `C2` (base) constructors.
/// These are real symbols from the corpus binaries (`real_symbols.txt`).
#[test]
fn ss_ctor_second_parameter_is_restored() {
    for sym in ["_ZNSsC1IPKcEET_S2_RKSaIcE", "_ZNSsC2IPKcEET_S2_RKSaIcE"] {
        let got = text(sym);
        assert_eq!(
            got,
            "std::string::string<char const*>\
             (char const*, char const*, std::allocator<char> const&)",
            "repair failed for {sym}"
        );
    }
}

/// Free-function `T_S2_` shapes are correct upstream — the repair must not
/// fire (its gate requires the `_ZNSsC` prefix).
#[test]
fn free_function_backref_params_untouched() {
    assert_eq!(
        text("_Z3fooIPKcEvT_S2_"),
        "void foo<char const*>(char const*, char const*)"
    );
    assert_eq!(
        text("_Z3fooIPKcEvT_S2_S2_"),
        "void foo<char const*>(char const*, char const*, char const*)"
    );
    assert_eq!(
        text("_Z3fooIPKcPiEvT_T0_S2_S4_"),
        "void foo<char const*, int*>(char const*, int*, int*, int*)"
    );
}

/// Idempotence: applying the repair to an already-correct rendering (what
/// upstream will eventually produce) must not add a third parameter.
#[test]
fn repair_is_idempotent() {
    let repaired = rustre_demangle::repair_ss_ctor_dropped_param(
        "_ZNSsC1IPKcEET_S2_RKSaIcE",
        "std::string::string<char const*>\
         (char const*, char const*, std::allocator<char> const&)",
    );
    assert_eq!(
        repaired,
        "std::string::string<char const*>\
         (char const*, char const*, std::allocator<char> const&)"
    );
}

/// The two public Itanium entry points must agree on the repaired class
/// (the standing `*_paths_agree` invariant).
#[test]
fn public_paths_agree_on_repaired_class() {
    for sym in ["_ZNSsC1IPKcEET_S2_RKSaIcE", "_ZNSsC2IPKcEET_S2_RKSaIcE"] {
        let auto = text(sym);
        let direct = rustre_demangle::cpp_demangler::demangle_itanium(sym)
            .expect("cpp_demangler path");
        assert_eq!(auto, direct, "paths disagree on {sym}");
    }
}
