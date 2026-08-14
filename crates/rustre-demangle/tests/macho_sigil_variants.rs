//! Every ABI must classify a symbol the same way with and without Mach-O's
//! leading underscore.
//!
//! Apple's symbol table prefixes **every** symbol with `_`, so a symbol read
//! from a macOS or iOS binary is `__Z…` (Itanium), `__R…` (Rust v0),
//! `__ZN…17h…E` (legacy Rust), `__D…` (D) and `_$s…` (Swift). The crate learned
//! this on 2026-07-23 and taught it to `is_rust_v0`, `is_d` and `is_swift` —
//! **and missed `is_rust_legacy`**.
//!
//! The consequence was invisible to every string comparison: the Itanium
//! backend also strips the Rust hash, so `__ZN4main3foo17h…E` rendered
//! `main::foo`, exactly right — while reporting `ManglingAbi::Itanium`. Only
//! the ABI field was wrong, and that is the field consumers route on, so on a
//! real Apple binary *every* legacy Rust symbol would have been filed as C++.
//!
//! Found by an instrument rather than a hunch: **check coverage per sigil
//! VARIANT, not per ABI.** Iter 123 found legacy Rust hiding behind Rust v0 and
//! iter 124 found Swift 3 hiding behind `$s`; this is the same sweep applied to
//! the platform prefix. "ABI X is covered" keeps turning out to be a claim
//! about one of X's manglings.

/// One body per ABI, decoded with and without the Mach-O underscore, must give
/// the same rendering **and** the same ABI label.
#[test]
fn the_mach_o_prefix_changes_neither_rendering_nor_abi() {
    // (plain, mach-o) pairs carrying identical bodies.
    let pairs = [
        ("_D4main3fooFZv", "__D4main3fooFZv"),
        ("_ZN4main3fooEv", "__ZN4main3fooEv"),
        ("_RNvC1a1f", "__RNvC1a1f"),
        (
            "_ZN4main3foo17h0123456789abcdefE",
            "__ZN4main3foo17h0123456789abcdefE",
        ),
        ("$s4main3fooyyF", "_$s4main3fooyyF"),
        ("$S4main3fooyyF", "_$S4main3fooyyF"),
        ("_TtC4main3Foo", "__TtC4main3Foo"),
    ];

    let mut checked = 0;
    let mut mismatches = Vec::new();
    for (plain, macho) in pairs {
        let a = rustre_demangle::demangle(plain)
            .unwrap_or_else(|| panic!("{plain} must decode"));
        let b = rustre_demangle::demangle(macho)
            .unwrap_or_else(|| panic!("{macho} must decode"));
        checked += 1;
        if a.demangled != b.demangled {
            mismatches.push(format!(
                "{plain} => {} but {macho} => {}",
                a.demangled, b.demangled
            ));
        }
        if format!("{:?}", a.abi) != format!("{:?}", b.abi) {
            mismatches.push(format!(
                "{plain} is {:?} but {macho} is {:?}",
                a.abi, b.abi
            ));
        }
    }
    assert!(checked >= 7, "vacuous: only {checked} pairs checked");
    assert!(
        mismatches.is_empty(),
        "the Mach-O prefix changed the result:\n{}",
        mismatches.join("\n")
    );
}

/// Legacy Rust in particular: both forms are Rust, not Itanium.
///
/// Discriminating: the *rendering* is identical under either label, because the
/// Itanium path strips the hash too. Only the ABI field separates a correct
/// classification from the defect, which is why this asserts the field.
#[test]
fn mach_o_legacy_rust_is_labelled_rust() {
    for sym in [
        "_ZN4main3foo17h0123456789abcdefE",
        "__ZN4main3foo17h0123456789abcdefE",
        "__ZN4core3fmt9Formatter3pad17h1234567890abcdefE",
    ] {
        let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert_eq!(format!("{:?}", r.abi), "Rust", "{sym}");
        assert!(!r.demangled.contains("17h"), "the hash leaked: {}", r.demangled);
    }
}

/// Widening the prefix must not widen what the rule claims.
///
/// C++ symbols keep their ABI under the Mach-O prefix, including the one whose
/// last component merely begins with `17h`.
#[test]
fn mach_o_c_plus_plus_stays_itanium() {
    for sym in [
        "__ZN3foo3barEv",
        "__ZNSt10bad_typeidD1Ev",
        "__ZN3foo17hello_there_worldE",
    ] {
        let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert_eq!(format!("{:?}", r.abi), "Itanium", "{sym}");
    }
}
