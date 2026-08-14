//! A demangler must account for the whole symbol.
//!
//! Two distinct linker symbols that decode to the same string are
//! indistinguishable to any consumer — for a reverse-engineering tool, two
//! different functions that look like one. That is what silently ignoring
//! trailing input produces: `_D4main3fooFiZiGARBAGE` decoded to exactly the
//! same `int main.foo(int)` as `_D4main3fooFiZi`.
//!
//! Itanium already rejects trailing input, because the live path hands it to
//! `cpp_demangle`. Comparing the backends against each other is what showed D
//! and Swift were the outliers — neither has an oracle, so nothing else could
//! have contradicted them.
//!
//! **Swift is deliberately not held to this rule**, and the reason is measured
//! rather than assumed: its parser consumes the whole symbol for only 9 of 16
//! realistic inputs. `$s10Foundation3URLV6stringACSgSS_tcfc` stops at byte 26
//! of 37 and `$s7SwiftUI4TextV6stringACSS_tcfc` at 23 of 32, because large
//! parts of the grammar (constructors, `Sg` optionals) are unimplemented and
//! the parser simply stops. Requiring full consumption there would decline 7 of
//! 16 legitimate symbols — a far bigger regression than the defect it fixes.
//! That partial consumption is itself the general form of the loss recorded in
//! `tests/swift_completeness.rs`, where a local function's name disappears.

/// Symbols that decode, paired with junk that must not be absorbed.
const D_SYMBOLS: &[&str] = &[
    "_D4main3fooFiZi",
    "_D3std5stdio7writelnFAyaZv",
    "_D4main1xi",
    "_D4main3fooFPFiZvZv",
    "_D4main3fooFZNn",
];

const JUNK: &[&str] = &["GARBAGE", "!!!", "99", "Z", "ñ"];

#[test]
fn d_does_not_absorb_trailing_input() {
    let mut checked = 0;
    for sym in D_SYMBOLS {
        let clean = rustre_demangle::demangle(sym)
            .unwrap_or_else(|| panic!("{sym} must decode"))
            .demangled;

        for junk in JUNK {
            let polluted = format!("{sym}{junk}");
            let got = rustre_demangle::demangle(&polluted).map(|r| r.demangled);
            assert_ne!(
                got.as_deref(),
                Some(clean.as_str()),
                "{polluted} decoded identically to {sym} — two distinct symbols \
                 collapsed into one rendering"
            );
            checked += 1;
        }
    }
    assert!(checked > 20, "vacuous: only {checked} pairs compared");
}

/// Control: the unpolluted symbols still decode, and to the right thing.
///
/// A rule that rejected everything would satisfy the test above.
#[test]
fn well_formed_d_symbols_are_unaffected() {
    for (sym, want) in [
        ("_D4main3fooFiZi", "int main.foo(int)"),
        (
            "_D3std5stdio7writelnFAyaZv",
            "void std.stdio.writeln(immutable(char)[])",
        ),
        ("_D4main1xi", "int main.x"),
        ("_D4main12__ModuleInfoZ", "main.__ModuleInfo"),
    ] {
        assert_eq!(
            rustre_demangle::demangle(sym).map(|r| r.demangled),
            Some((*want).to_owned()),
            "{sym}"
        );
    }
}

/// Itanium is the reference: it already declined trailing input, which is how
/// the D and Swift behaviour was recognised as wrong rather than as a choice.
#[test]
fn itanium_is_the_reference_for_this_rule() {
    assert_eq!(
        rustre_demangle::demangle("_ZN3foo3barEi").map(|r| r.demangled),
        Some("foo::bar(int)".to_owned())
    );
    assert!(
        rustre_demangle::demangle("_ZN3foo3barEiGARBAGE").is_none(),
        "Itanium must reject trailing input"
    );
}

/// `detect` and `demangle` must stay in step on the newly rejected inputs.
///
/// Moving the rejection into the grammar parser made the `DDemangler` wrapper
/// decline symbols its own `detect` still claimed — the divergence that makes
/// `if detect(s) { demangle(s).unwrap() }` panic. Both now run the same parse.
#[test]
fn d_detect_and_demangle_stay_in_step() {
    use rustre_demangle::DDemangler;

    // Equality rather than `if detect { assert … }`: measured 25 of 25 today,
    // but only because `DDemangler::detect` still claims the polluted forms.
    let mut compared = 0usize;

    for sym in D_SYMBOLS {
        for junk in JUNK {
            let polluted = format!("{sym}{junk}");
            assert_eq!(
                DDemangler::detect(&polluted),
                DDemangler::demangle(&polluted).is_some(),
                "detect and demangle disagree on {polluted}"
            );
            compared += 1;
        }
        // And the clean symbol must still be claimed *and* decoded — the
        // positive control, without which the equality above is satisfied by a
        // detector that rejects everything.
        assert!(DDemangler::detect(sym), "{sym} must still be detected");
        assert!(DDemangler::demangle(sym).is_some(), "{sym} must still decode");
    }
    assert!(compared > 20, "vacuity guard: only {compared} polluted forms compared");
}

/// MSVC was not held to this rule either, and unlike Swift there was no reason
/// for it.
///
/// The RTTI and vftable decoders parsed the name, read the storage suffix they
/// cared about, and discarded the remainder — so **6 of the 14 real MSVC
/// symbols** absorbed arbitrary trailing input:
///
/// ```text
///   ??_7type_info@@6B@         =>  const type_info::`vftable'
///   ??_7type_info@@6B@GARBAGE  =>  const type_info::`vftable'
/// ```
///
/// The Swift exemption above is measured — requiring full consumption there
/// would decline 7 of 16 legitimate symbols, because the grammar is genuinely
/// unimplemented. Here the opposite: the parser had already recognised a
/// *complete* symbol and simply never checked for leftovers, so the rule costs
/// **nothing** — all 14 real symbols still decode, byte-identically.
///
/// `msvc-demangler` cannot arbitrate this one: it absorbs trailing input in all
/// 42 cases tried. It did arbitrate the *shape* of the storage suffix, which is
/// why the bare `??_R2Foo@@` is accepted while `??_R0?AVFoo@@` is not.
#[test]
fn msvc_rejects_trailing_input() {
    let symbols = [
        "??_7type_info@@6B@",
        "??_R0?AVtype_info@@@8",
        "??_R1A@?0A@EA@type_info@@8",
        "??_R2type_info@@8",
        "??_R3type_info@@8",
        "??_R4type_info@@6B@",
    ];
    for s in symbols {
        let clean = rustre_demangle::demangle(s)
            .unwrap_or_else(|| panic!("{s} must still decode"))
            .demangled;
        for junk in ["GARBAGE", "ZZZZ", "!!", "@", "8"] {
            let dirty = format!("{s}{junk}");
            let got = rustre_demangle::demangle(&dirty).map(|r| r.demangled);
            assert_ne!(
                got.as_deref(),
                Some(clean.as_str()),
                "{dirty} collapsed onto {s}"
            );
        }
    }
}

/// The cost of the rule above, asserted rather than assumed: every real MSVC
/// symbol still decodes. This is the check the Swift exemption failed, and it
/// is what distinguishes a rule that is affordable from one that is not.
#[test]
fn the_msvc_rule_costs_no_coverage() {
    let msvc: Vec<&str> = include_str!("data/pdb_symbols.txt")
        .lines()
        .map(str::trim)
        .filter(|s| s.starts_with('?'))
        .collect();
    assert_eq!(msvc.len(), 14, "corpus changed; re-measure before trusting this");
    for s in &msvc {
        assert!(rustre_demangle::demangle(s).is_some(), "{s} stopped decoding");
    }
}
