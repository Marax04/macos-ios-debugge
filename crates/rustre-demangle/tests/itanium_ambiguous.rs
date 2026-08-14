//! Names that look like C but are valid Itanium manglings.
//!
//! `__Zoom` decodes to `operator||(unsigned long)`: in the Itanium grammar
//! `oo` is `operator||` and `m` is `unsigned long`. That reads like fabricated
//! output of the kind this crate has produced elsewhere — a C name dressed up
//! as something it is not — but it is not: `cpp_demangle`, and `c++filt` with
//! it, produce exactly the same string. The ambiguity is in the ABI, and
//! matching the reference is the correct behaviour.
//!
//! This suite exists to protect that. Every other prefix rule in the crate was
//! tightened during the 2026-07-23 sweep because it claimed ordinary C names
//! (`_RTC_Initialize` as Rust, `_TIFFOpen` as Swift, `_DllMainCRTStartup` as
//! D); a later reader sweeping again would reasonably try to "fix" this one
//! too, and would be removing correct output.

fn reference(s: &str) -> Option<String> {
    cpp_demangle::BorrowedSymbol::new(s.as_bytes())
        .ok()?
        .demangle(&cpp_demangle::DemangleOptions::default())
        .ok()
}

/// Where the reference decodes an ambiguous `_Z…` name, so must we — with the
/// same string.
#[test]
fn ambiguous_itanium_names_match_the_reference() {
    for s in ["__Zoom", "_Zoom"] {
        let want = reference(s).unwrap_or_else(|| {
            panic!("{s} is a valid Itanium mangling; the reference should decode it")
        });
        let got = rustre_demangle::demangle(s)
            .unwrap_or_else(|| panic!("{s} must decode: the reference gives {want}"))
            .demangled;
        assert_eq!(got, want, "{s} must match the reference exactly");
    }
}

/// Where the reference declines, we decline too — no invented output.
#[test]
fn invalid_z_names_are_declined_like_the_reference() {
    for s in ["_Zebra", "_Zone_init", "_ZERO_PAGE", "_Zip_open"] {
        assert!(
            reference(s).is_none(),
            "{s} is not a valid Itanium mangling — test premise changed"
        );
        assert!(
            rustre_demangle::demangle(s).is_none(),
            "{s} must be declined, matching the reference"
        );
    }
}
