//! The three public D entry points must not drift apart.
//!
//! D is reachable through `crate::demangle` (the live path),
//! `d_demangler::d_demangle` (a free function) and `DDemangler::demangle` (the
//! struct method). All three are public API — the first two are also exposed as
//! separate MCP wire tools — and nothing in the suite pinned them together:
//! `entry_point_matrix.rs` tabulates Itanium, MSVC and Rust entry points and
//! covers no D one at all.
//!
//! That is the configuration this crate has been bitten by repeatedly.
//! `ItaniumDemangler`, `MsvcDemangler`, `AutoDemangler` and `DemanglerCache`
//! each exist two or three times and the copies disagree in both directions;
//! `backends::SwiftDemangler::detect` omitted `_$s` while
//! `swift_demangler::SwiftDemangler::detect` listed it, so no Swift symbol from
//! an Apple binary decoded at all. In every case the copies were consistent
//! until they silently were not, because no test compared them.
//!
//! They agree today — this file is a guard, not a bug report. It is written
//! over the *shapes that have actually been fixed*, so a future fix landing in
//! one copy and not the others fails here rather than in a consumer.

/// Symbols spanning every D shape corrected in this crate, plus controls.
///
/// Each entry is a shape where a partial fix is plausible: a fix applied to the
/// shared type-code table reaches all three doors, but one applied to a
/// wrapper, a prefix-stripper or a cache would not.
const SHAPES: &[(&str, &str)] = &[
    // Function pointer: `P` applied to a function type.
    ("_D4main3fooFPFiZvZv", "void main.foo(void function(int))"),
    // `Y`, the C-style variadic parameter-list terminator.
    ("_D4main3fooFiYv", "void main.foo(int, ...)"),
    // `Nn`, the `noreturn` bottom type.
    ("_D4main3fooFZNn", "noreturn main.foo()"),
    // Runtime special symbol: trailing `Z` is not a type.
    ("_D4main12__ModuleInfoZ", "main.__ModuleInfo"),
    // Controls: ordinary function, ordinary data symbol, real-world shape.
    ("_D4main3fooFiZi", "int main.foo(int)"),
    ("_D4main1xi", "int main.x"),
    (
        "_D3std5stdio7writelnFAyaZv",
        "void std.stdio.writeln(immutable(char)[])",
    ),
];

fn live(s: &str) -> Option<String> {
    rustre_demangle::demangle(s).map(|r| r.demangled)
}

#[test]
fn all_three_d_entry_points_agree() {
    use rustre_demangle::d_demangler::{DDemangler, d_demangle};

    let mut checked = 0;
    for (sym, want) in SHAPES {
        let live = live(sym).unwrap_or_else(|| panic!("{sym} must decode on the live path"));
        assert_eq!(live, *want, "live path changed for {sym}");

        assert_eq!(
            d_demangle(sym),
            live,
            "d_demangler::d_demangle diverges from crate::demangle on {sym}"
        );

        let via_struct = DDemangler::new(sym)
            .demangle()
            .unwrap_or_else(|e| panic!("DDemangler failed on {sym}: {e}"))
            .demangled;
        assert_eq!(
            via_struct, live,
            "DDemangler::demangle diverges from crate::demangle on {sym}"
        );

        checked += 1;
    }

    // Vacuity guard: "no divergences because they agree" and "no divergences
    // because nothing ran" look identical from a green test.
    assert!(
        checked >= SHAPES.len() && checked > 5,
        "too few shapes compared to be meaningful: {checked}"
    );
}

/// Apple's symbol table prefixes every symbol with `_`, so a D symbol read from
/// a Mach-O binary is `__D…`. Neither corpus is Mach-O, which is exactly how
/// this class of gap stayed hidden before — the underscored forms of Swift,
/// Rust v0 and D were declined wholesale until 2026-07-23.
///
/// The two spellings denote the same symbol and must decode identically.
#[test]
fn the_macho_spelling_reaches_the_same_decoder() {
    let mut checked = 0;
    for (sym, want) in SHAPES {
        let macho = format!("_{sym}");
        let got = live(&macho).unwrap_or_else(|| panic!("{macho} must decode"));
        assert_eq!(got, *want, "__D spelling diverges for {macho}");
        checked += 1;
    }
    assert!(checked > 5, "vacuous: only {checked} shapes compared");
}
