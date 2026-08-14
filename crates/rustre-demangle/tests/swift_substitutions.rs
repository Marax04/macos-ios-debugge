//! Swift standard substitutions must name a type, in every position.
//!
//! Swift has no oracle among the crate's dependencies, so a wrong rendering has
//! nothing to contradict it. What makes this checkable anyway is that the
//! standard substitutions are a *documented finite table* (Swift's
//! `Demangle.def`): `Si` is `Swift.Int`, `SS` is `Swift.String`, and so on.
//! The mapping is not inferred here — the crate already implements it correctly
//! for types, so the two positions can be required to agree with each other.
//!
//! The defect this pins was a second copy of the same dispatch:
//! `swift_demangler::parse_module` handled a leading `S` without ever
//! consulting the substitution table, so it fell through to formatting the
//! internal substitution *index*. `$sSS7countedSiSo7NSArrayCF` rendered
//! `S5.counted` — an index leaked into user-visible output — while the very
//! same `SS` in type position rendered `Swift.String`. That is the recurring
//! shape in this crate: two copies of one rule, only one of them updated.

fn demangled(s: &str) -> String {
    rustre_demangle::demangle(s)
        .unwrap_or_else(|| panic!("{s} must decode"))
        .demangled
}

/// The table, restricted to entries this crate already renders in type
/// position. Each is checked in *both* positions, so neither copy can drift.
const SUBSTITUTIONS: &[(&str, &str)] = &[
    ("Si", "Swift.Int"),
    ("SS", "Swift.String"),
    ("Sb", "Swift.Bool"),
    ("Sd", "Swift.Double"),
    ("Sf", "Swift.Float"),
    ("Su", "Swift.UInt"),
];

/// A substitution used as the leading component of a qualified name must be
/// spelled out, never rendered as its internal index.
///
/// This is the discriminating position. In type position the table was already
/// consulted and every case passed, so a type-position test proves nothing
/// about the bug — the two must be compared *against each other*.
#[test]
fn substitutions_name_a_type_in_module_position() {
    let mut checked = 0;
    for (code, want) in SUBSTITUTIONS {
        let out = demangled(&format!("$s{code}"));
        assert_eq!(out, *want, "$s{code} in module position");

        // The specific failure mode: `S` followed by the substitution index.
        assert!(
            !is_bare_substitution_index(&out),
            "internal substitution index leaked into output for $s{code}: {out}"
        );
        checked += 1;
    }
    assert!(checked > 4, "vacuous: only {checked} substitutions checked");
}

/// Both positions must agree. Written as a cross-check rather than two
/// independent expectation lists so that a future change to the table cannot
/// update one copy and leave the other behind — which is exactly how this
/// defect arose.
#[test]
fn module_position_and_type_position_agree() {
    let mut checked = 0;
    for (code, want) in SUBSTITUTIONS {
        let as_module = demangled(&format!("$s{code}"));
        let as_type = demangled(&format!("$s4main3fooy{code}F"));

        assert_eq!(as_module, *want);
        assert!(
            as_type.contains(want),
            "type position lost {want} for {code}: {as_type}"
        );
        checked += 1;
    }
    assert!(checked > 4, "vacuous: only {checked} compared");
}

/// The real-world shape that surfaced the defect: a stdlib type as the parent
/// of a member.
#[test]
fn a_stdlib_type_can_be_the_parent_of_a_member() {
    let out = demangled("$sSS7countedSiSo7NSArrayCF");
    assert!(
        out.starts_with("Swift.String."),
        "the parent type must be named, not indexed: {out}"
    );
    assert!(out.contains("counted"), "member name lost: {out}");
}

/// Controls: ordinary symbols with no leading substitution must be untouched,
/// so the fix cannot be passing by disabling module parsing.
#[test]
fn ordinary_module_names_are_unaffected() {
    assert_eq!(demangled("$s4main3fooyyF"), "main.foo() -> ()");
    assert_eq!(
        demangled("$s10Foundation4DataV5countSivg"),
        "Foundation.Data.count.getter : Swift.Int"
    );
}

/// `S` followed only by digits — the internal substitution index, which must
/// never reach the rendered output for a *standard* substitution.
fn is_bare_substitution_index(s: &str) -> bool {
    s.strip_prefix('S')
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
}

/// An unresolvable substitution reference is not a name.
///
/// Iter 6 fixed the *standard substitution* half of this — `$sSS` now gives
/// `Swift.String` instead of `S5`. The fallback beneath it kept fabricating:
/// every letter with no standard meaning and every numeric back-reference into
/// an empty table rendered the parser's internal index as if it were a module.
///
/// Two things made it clearly wrong rather than merely odd:
///
/// * the index is not a name — it is a position in a table the caller cannot
///   see;
/// * it was not even the right index. `$sS0`, `$sS1` and `$sS12` all rendered
///   `S0`, as did `$sSO`, `$sSA` and `$sSZ`.
///
/// Found by sweeping random alphanumeric tails behind each mangling sigil,
/// where ~16% of `$s`/`$S`/`_T0` inputs decoded to fragments like `"S0."`.
///
/// The fix removes output rather than inventing better output: an unreadable
/// symbol now declines, through the same placeholder rule that already covers
/// the other unparseable Swift shapes.
#[test]
fn an_unresolvable_substitution_declines_rather_than_showing_its_index() {
    for sym in [
        // Letters with no standard-substitution meaning.
        "$sSO", "$sSA", "$sSZ",
        // Numeric back-references into an empty table.
        "$sS0", "$sS1", "$sS12",
        // The shapes as they turned up in the random sweep.
        "$sSOvuVbU48gNc7JAr",
        "$SSk3gldgbNWVHteXCvQS",
    ] {
        let got = rustre_demangle::demangle(sym).map(|r| r.demangled);
        assert!(
            got.is_none(),
            "{sym} has no resolvable substitution and must decline, got {got:?}"
        );
    }

    // Control: the standard substitutions fixed in iter 6 must still resolve —
    // a fix that simply declined every `S`-prefixed module would satisfy the
    // assertions above while undoing that work.
    for (sym, want) in [
        ("$sSS", "Swift.String"),
        ("$sSi", "Swift.Int"),
        ("$sSb", "Swift.Bool"),
        ("$sSd", "Swift.Double"),
    ] {
        assert_eq!(
            rustre_demangle::demangle(sym).map(|r| r.demangled).as_deref(),
            Some(want),
            "{sym}"
        );
    }

    // And a real symbol whose module is a standard substitution still decodes.
    // Its unread signature is echoed since iter 142 — the path this test is
    // about is unchanged; what follows it was previously dropped in silence.
    assert_eq!(
        rustre_demangle::demangle("$sSS7countedSiSo7NSArrayCF")
            .map(|r| r.demangled)
            .as_deref(),
        Some("Swift.String.counted [unparsed SiSo7NSArrayCF]")
    );
}
