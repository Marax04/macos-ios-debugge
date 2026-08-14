//! `_T` alone does not make a symbol Swift.
//!
//! `SymbolClassifier::classify` used to file every `_T…` name as Swift, which
//! is far broader than any Swift backend accepts: `SwiftDemangler::detect`
//! wants `$s`/`$S`/`_$s`/`_$S`/`_T0`/`__T0`, and `detect_old_swift` wants `_T`
//! followed by `F`. The consequence was a *phantom* defect — `_TIFFOpen`, an
//! ordinary C name, was reported as an unhandled Swift symbol, and phantom
//! defects are what hide real ones.
//!
//! The corpora contain no `_T` symbols at all, so this could not be caught by
//! a corpus invariant; these cases are hand-picked deliberately, to probe a
//! specific rule rather than to measure the corpus.

use rustre_demangle::{DeclineReason, MangleLanguage, SymbolClassifier, decline_reason};

/// Plain C names that merely start with `_T` are not Swift.
#[test]
fn c_names_starting_with_t_are_not_swift() {
    for s in [
        "_TIFFOpen",
        "_Tcl_Init",
        "_TlsAlloc",
        "_Test_helper",
        "_TABLE_SIZE",
        "_TypeInfo",
        "_Thread_local_init",
    ] {
        assert_ne!(
            SymbolClassifier::classify(s),
            MangleLanguage::Swift,
            "{s} is a C identifier, not Swift"
        );
        assert_ne!(
            decline_reason(s),
            DeclineReason::UnsupportedAbi,
            "{s} must not be reported as an unhandled mangled symbol"
        );
    }
}

/// Real Swift still classifies as Swift — the fix must not be satisfied by
/// classifying nothing as Swift.
#[test]
fn real_swift_symbols_are_still_swift() {
    for s in [
        "$s4test3FooC3baryyF",
        "$s4main3fooyyF",
        "_TFC4test3Foo3barfS0_FT_T_",
        "_TtC4test3Foo",
    ] {
        assert_eq!(
            SymbolClassifier::classify(s),
            MangleLanguage::Swift,
            "{s} is Swift"
        );
    }
}

/// Modern Swift decodes; legacy `_T` is a genuine, honestly-reported gap.
#[test]
fn modern_swift_decodes_legacy_is_an_open_gap() {
    assert!(rustre_demangle::demangle("$s4test3FooC3baryyF").is_some());

    // `demangle_old_swift` returns None rather than emit a partial result, so
    // the symbol is declined and `decline_reason` says so. This asserts the
    // current honest state; if legacy support lands, this test should be
    // updated to require decoding.
    assert_eq!(
        decline_reason("_TFC4test3Foo3barfS0_FT_T_"),
        DeclineReason::UnsupportedAbi,
        "legacy Swift is recognised but not decoded — that must stay visible"
    );
}

/// Mach-O underscore-prefixed Swift symbols must decode.
///
/// Apple's symbol table prefixes every symbol with `_`, so a Swift symbol read
/// from a macOS or iOS binary is `_$s…`, not `$s…`. The live path handled the
/// bare form only and declined the underscore one outright — losing, in
/// practice, every Swift symbol on the platform Swift is native to.
///
/// The gap survived because two `SwiftDemangler` types disagreed:
/// `swift_demangler::SwiftDemangler::detect` listed `_$s`, the one in
/// `backends` (the live path) did not.
#[test]
fn mach_o_underscore_swift_symbols_decode() {
    let bare = rustre_demangle::demangle("$s4main3fooyyF")
        .expect("bare form must decode")
        .demangled;

    for s in ["_$s4main3fooyyF", "_$S4main3fooyyF"] {
        let r = rustre_demangle::demangle(s).unwrap_or_else(|| panic!("{s} must decode"));
        assert_eq!(
            r.demangled, bare,
            "{s} must decode to the same thing as the bare form"
        );
        assert_eq!(
            SymbolClassifier::classify(s),
            MangleLanguage::Swift,
            "{s} must classify as Swift"
        );
    }
}

/// Mach-O prefixes *every* symbol with `_`, not just Swift ones.
///
/// Itanium already handled `__Z`; Rust v0 (`__R`) and D (`__D`) did not, so
/// those ABIs were lost wholesale on Apple binaries. `rustc-demangle` accepts
/// `__R`, which settles the Rust case as fact rather than inference; D follows
/// the same platform convention.
#[test]
fn mach_o_double_underscore_forms_decode() {
    for (elf, macho) in [
        ("_ZNSt10bad_typeidD1Ev", "__ZNSt10bad_typeidD1Ev"),
        (
            "_ZN4core3fmt9Formatter3pad17h1234567890abcdefE",
            "__ZN4core3fmt9Formatter3pad17h1234567890abcdefE",
        ),
        (
            "_RNvCs4SDFJOLwvtW_7___rustc10rust_panic",
            "__RNvCs4SDFJOLwvtW_7___rustc10rust_panic",
        ),
        ("_D4main3fooFZv", "__D4main3fooFZv"),
    ] {
        let a = rustre_demangle::demangle(elf)
            .unwrap_or_else(|| panic!("{elf} must decode"))
            .demangled;
        let b = rustre_demangle::demangle(macho)
            .unwrap_or_else(|| panic!("{macho} must decode — Mach-O form of {elf}"))
            .demangled;
        assert_eq!(a, b, "{macho} must decode like {elf}");
    }
}

/// The underscore allowance must not re-open the phantom-defect hole: a C name
/// with two leading underscores is still a C name.
#[test]
fn double_underscore_c_names_are_still_declined() {
    for s in ["__RTC_Initialize", "__Dispatch", "__DllMainCRTStartup"] {
        assert_ne!(
            SymbolClassifier::classify(s),
            MangleLanguage::Swift,
            "{s} is a C identifier"
        );
        assert_eq!(
            decline_reason(s),
            DeclineReason::UndecoratedC,
            "{s} is a plain C identifier — the leading underscores do not make              it a mangled symbol"
        );
    }
}
