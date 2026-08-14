//! The Mach-O underscore must not change what a symbol decodes to.
//!
//! Apple's symbol table prepends `_` to every symbol, so a symbol that is
//! `_ZN…`/`_R…`/`_D…`/`$s…` in an ELF/PE binary appears as `__Z…`/`__R…`/
//! `__D…`/`_$s…` read from a Mach-O one. The crate's notes record that this
//! whole class went unhandled until 2026-07-23 — every ABI but Itanium declined
//! the underscored form — and that neither corpus is Mach-O, so nothing built
//! from the real corpora can catch a regression here.
//!
//! Per-ABI tests exist (`swift_prefix.rs`, `d_prefix.rs`, and the Itanium/Rust
//! prefix checks), but the property they each test is one thing stated four
//! times: the underscored form must decode to *exactly* what the bare form
//! does. This states it once, uniformly, so a new ABI or a refactor of the
//! prefix handling is measured against the invariant rather than four separate
//! spellings of it. Asserting equality (not merely "both decode") is the point:
//! a Mach-O symbol that decoded to something *different* would be a silent
//! fidelity bug the per-ABI "still Swift"/"still D" checks would miss.

/// Bare symbols known to decode, one per underscore-prefix ABI. The Mach-O form
/// is the same string with one leading `_` added.
const BARE: &[(&str, &str)] = &[
    ("_ZN3foo3barEi", "Itanium"),
    ("_RNvC4main3foo", "Rust v0"),
    // Was `_D3fooQeFiZv`, which contains a `Q` back-reference — a D grammar
    // feature this crate does not implement. It decoded to `?(Q) foo` on both
    // sides, so the equality assertion below passed while both paths agreed on
    // a *fabricated* answer. An agreement test is only as good as a fixture
    // that actually decodes; `assert_fixtures_decode_cleanly` now enforces that.
    ("_D4main3fooFiZi", "D"),
    ("$s4main3fooyyF", "Swift"),
];

/// Markers this crate emits when it could not decode something and fell back to
/// printing the raw code: `?(Q)`, `?(N)`, `?module`, and so on.
fn is_fabricated(out: &str) -> bool {
    out.contains("?(") || out.contains("?module") || out.contains('?')
}

#[test]
fn mach_o_form_decodes_identically_to_the_bare_form() {
    let mut checked = 0usize;
    for (bare, abi) in BARE {
        let bare_out = rustre_demangle::demangle(bare)
            .unwrap_or_else(|| panic!("{abi} bare symbol {bare} must decode"))
            .demangled;

        let macho = format!("_{bare}");
        let macho_out = rustre_demangle::demangle(&macho)
            .unwrap_or_else(|| panic!("{abi} Mach-O symbol {macho} must decode"))
            .demangled;

        assert_eq!(
            bare_out, macho_out,
            "{abi}: Mach-O form {macho} decoded differently from bare {bare}"
        );
        checked += 1;
    }
    assert_eq!(checked, BARE.len(), "not every ABI was exercised");
}

/// The fixtures above must actually *decode*, not merely decode consistently.
///
/// This is the gap that let a broken fixture sit here unnoticed. The equality
/// test compares two spellings of the same symbol against each other, so it is
/// satisfied when both paths are wrong in the same way — and one fixture,
/// `_D3fooQeFiZv`, was exactly that: it used a `Q` back-reference, which this
/// crate does not implement, and rendered `?(Q) foo` on both sides.
///
/// Asserting the absence of fabrication markers turns the agreement test into
/// an agreement-*on-something-real* test, and makes a future fixture chosen
/// from an unimplemented corner fail here rather than pass vacuously.
#[test]
fn fixtures_decode_without_fabrication() {
    let mut checked = 0usize;
    for (bare, abi) in BARE {
        for sym in [(*bare).to_owned(), format!("_{bare}")] {
            let out = rustre_demangle::demangle(&sym)
                .unwrap_or_else(|| panic!("{abi} fixture {sym} must decode"))
                .demangled;
            assert!(
                !is_fabricated(&out),
                "{abi} fixture {sym} does not really decode: {out}"
            );
            assert_ne!(out, sym, "{abi} fixture {sym} was echoed, not decoded");
            checked += 1;
        }
    }
    assert_eq!(checked, BARE.len() * 2, "not every fixture was exercised");
}

/// The Mach-O spelling must also be *reported* the same, not just rendered the
/// same. Consumers key off `abi` for routing and off `original` for lookup
/// tables, so a normalised `original` — the leading `_` silently dropped —
/// would break a caller without changing a single rendered string.
#[test]
fn mach_o_form_reports_the_same_abi_and_preserves_the_original() {
    let mut checked = 0usize;
    for (bare, abi) in BARE {
        let bare_r = rustre_demangle::demangle(bare).expect("bare must decode");
        let macho = format!("_{bare}");
        let macho_r = rustre_demangle::demangle(&macho).expect("mach-o must decode");

        assert_eq!(
            format!("{:?}", bare_r.abi),
            format!("{:?}", macho_r.abi),
            "{abi}: Mach-O form was labelled with a different ABI"
        );
        assert_eq!(bare_r.original, *bare, "original must be the input verbatim");
        assert_eq!(
            macho_r.original, macho,
            "the leading underscore must survive in `original`"
        );
        checked += 1;
    }
    assert_eq!(checked, BARE.len());
}
