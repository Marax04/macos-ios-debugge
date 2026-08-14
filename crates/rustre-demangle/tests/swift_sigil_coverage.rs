//! Swift has FIVE sigils, and only one of them had been probed.
//!
//! Iter 119 probed Swift with `$s` and reported the ABI covered. Swift 4.2 uses
//! `$S`, Swift 3 uses `_T`, and Apple's symbol table prefixes every symbol with
//! an underscore, so real Mach-O symbols are `_$s`, `_$S` and `__T`. "Swift is
//! covered" was an ABI-level claim built from evidence about one mangling —
//! the same shape of gap that hid legacy Rust behind Rust v0 at iter 123.
//!
//! Probing the rest found a real defect, and the crate's own authoritative
//! metric names it: `sigil::is_swift` accepts `_T` + `t`, but
//! `detect_old_swift` only accepted `F` (function), so every Swift 3 **nominal
//! type** was claimed and then declined. `decline_reason` reported
//! `UnsupportedAbi` — the variant `src/decline.rs` documents as *the only one
//! that means a defect*, locked at 0 over the corpora. It read 0 only because
//! the corpora are Itanium and Go and contain no Swift at all.
//!
//! `_TtC<module><class>` is not obscure: it is exactly what the Obj-C runtime
//! and `NSStringFromClass` show for every Swift class.
//!
//! **What is deliberately still declining:** `_TM` (metadata), `_TW` (witness
//! tables) and the rest of the Swift 3 entity alphabet. There is no Swift
//! oracle here, so those are left honest-but-unsupported rather than guessed —
//! the same line drawn for Swift's signature order and generic rendering.

fn demangled(sym: &str) -> Option<String> {
    rustre_demangle::demangle(sym).map(|r| r.demangled)
}

fn abi_of(sym: &str) -> Option<String> {
    rustre_demangle::demangle(sym).map(|r| format!("{:?}", r.abi))
}

/// One body, every sigil, one rendering.
///
/// The Mach-O underscored forms are the ones real Apple binaries carry, and
/// the crate has already been bitten by omitting them: `backends::
/// SwiftDemangler::detect` once left out `_$s`, so no Swift symbol from an
/// Apple binary decoded at all.
#[test]
fn every_sigil_decodes_the_same_body_identically() {
    const BODY: &str = "4main3fooyyF";
    let mut seen = Vec::new();
    for prefix in ["$s", "$S", "_$s", "_$S"] {
        let sym = format!("{prefix}{BODY}");
        let out = demangled(&sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert_eq!(abi_of(&sym).as_deref(), Some("Swift"), "{sym}");
        seen.push(out);
    }
    assert_eq!(seen.len(), 4);
    assert!(
        seen.windows(2).all(|w| w[0] == w[1]),
        "the same body rendered differently across sigils: {seen:?}"
    );
    assert_eq!(seen[0], "main.foo() -> ()");
}

/// Swift 3 nominal types decode, under both the plain and Mach-O prefixes.
///
/// Discriminating: `_TF…` (a function) passed before this fix — it is the one
/// entity code the old parser handled. `_TtC…` is what separates a decoder for
/// the Swift 3 grammar from a decoder for one production of it.
#[test]
fn swift_three_nominal_types_decode() {
    for (sym, want) in [
        ("_TtC4main3Foo", "class main.Foo"),
        ("__TtC4main3Foo", "class main.Foo"),
        ("_TtV4main3Bar", "struct main.Bar"),
        ("_TtO4main4Kind", "enum main.Kind"),
        ("_TtP4main1P", "protocol main.P"),
    ] {
        assert_eq!(demangled(sym).as_deref(), Some(want), "{sym}");
        assert_eq!(abi_of(sym).as_deref(), Some("Swift"), "{sym}");
    }
    // The function form the old parser already handled must be unchanged.
    assert_eq!(
        demangled("_TF4main3fooFT_T_").as_deref(),
        Some("main.foo() -> ()")
    );
}

/// Nothing may be claimed and then declined.
///
/// This is the property that was broken, stated over `decline_reason` rather
/// than over a list of symbols: any Swift shape the sigil accepts must either
/// decode or be excluded by the sigil, never land in `UnsupportedAbi`.
#[test]
fn no_decoded_swift_shape_reports_unsupported_abi() {
    let claimed = [
        "$s4main3fooyyF",
        "_$s4main3fooyyF",
        "_TF4main3fooFT_T_",
        "_TtC4main3Foo",
        "_TtV4main3Bar",
        "_TtO4main4Kind",
        "_TtP4main1P",
    ];
    let mut checked = 0;
    for sym in claimed {
        assert!(rustre_demangle::sigil::is_swift(sym), "{sym} must be claimed");
        checked += 1;
        assert_eq!(
            format!("{:?}", rustre_demangle::decline::decline_reason(sym)),
            "Decoded",
            "{sym} is claimed by the sigil but does not decode"
        );
    }
    assert!(checked >= 7, "vacuous: only {checked} shapes checked");
}

/// Truncated and unknown nominal kinds decline rather than inventing a name.
#[test]
fn malformed_nominal_types_decline() {
    for sym in [
        "_TtC",           // kind but no context
        "_TtC4main",      // context but no name
        "_TtC4main3Foo1x", // trailing bytes
        "_TtX4main3Foo",  // not a nominal kind
    ] {
        assert_eq!(demangled(sym), None, "{sym} must not decode");
    }
}

/// The C names that merely start with `_T` stay out — the false positives that
/// made `_T` a phantom-defect source before (`_TIFFOpen`).
#[test]
fn c_names_beginning_with_the_sigil_are_not_swift() {
    for sym in ["_TIFFOpen", "_Tcl_Init", "_TransformFile"] {
        assert!(!rustre_demangle::sigil::is_swift(sym), "{sym}");
        assert_ne!(abi_of(sym).as_deref(), Some("Swift"), "{sym}");
    }
}
