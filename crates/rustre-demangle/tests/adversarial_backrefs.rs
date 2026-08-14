//! Back-reference and substitution indices must not index out of range or cycle.
//!
//! Every ABI has a back-reference form: Itanium `S<seq-id>_`, MSVC's ten numeric
//! slots, D's `Q<n>` (unimplemented), Swift's substitutions. Each is an **index
//! read from the symbol**, so the failure modes are an out-of-range table lookup,
//! index arithmetic that wraps, and a self-referential expansion that recurses
//! forever.
//!
//! This is the third input dimension swept after iters 81-84 found four defects in
//! the first two (length prefixes and nesting depth). **It found nothing** — all 79
//! inputs return, under `-C debug-assertions=on`, so the index handling is sound.
//! Kept because the dimension is cheap to check and the two before it were not
//! clean.
//!
//! A fourth dimension was also measured and is recorded here rather than asserted:
//! **time**. Escalating pathological inputs (`S_` x 6400, `PEA` x 6400, 6400 nested
//! `P`, long Go paths) all grow **linearly** — a 4x input costs about 4x, with no
//! super-linear blowup, so there is no denial-of-service shape. It is not a test
//! because a timing assertion on this machine would be flaky: the host is
//! documented as swinging ~2x under load and is shared with other agents.

/// Indices that are out of range, enormous, malformed, or cyclic.
fn cases() -> Vec<String> {
    let mut v: Vec<String> = Vec::new();

    // Itanium `S<seq-id>_`: empty (means the first substitution), in-range,
    // base-36 digits, and values past `usize`.
    for idx in [
        "",
        "0",
        "9",
        "z",
        "Z",
        "999999",
        "zzzzzz",
        "18446744073709551615",
        "99999999999999999999",
        "AAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        v.push(format!("_Z3fooS{idx}_"));
        v.push(format!("_ZN1AS{idx}_E"));
        v.push(format!("_Z3fooPS{idx}_i"));
    }

    // MSVC: a digit indexes one of ten slots, so every digit is a lookup into a
    // table that may be shorter than the index.
    for d in "0123456789".chars() {
        v.push(format!("?foo@{d}@@YAXXZ"));
        v.push(format!("?foo@@YAX{d}@Z"));
        v.push(format!("?{d}@{d}@{d}@@YAX{d}@Z"));
    }

    // D `Q<n>` is unimplemented (see `d_back_references_decline_rather_than_
    // fabricating`); it must stay harmless for any index too.
    for n in ["0", "9", "d", "999999", "18446744073709551615"] {
        v.push(format!("_D4main3fooFQ{n}Zv"));
    }

    // Swift substitutions.
    for n in ["0", "9", "99", "999999", "18446744073709551615"] {
        v.push(format!("$s4main3fooS{n}yyF"));
        v.push(format!("$sS{n}"));
    }

    // Self-referential expansions: a substitution whose value would contain the
    // substitution itself.
    v.push("_Z3fooIS_ES_".to_owned());
    v.push("_Z3fooIS0_ES0_".to_owned());
    v.push(format!("_Z3foo{}", "S_".repeat(2000)));
    v.push(format!("?foo@@YAX{}@Z", "0".repeat(2000)));

    v
}

#[test]
fn adversarial_back_reference_indices_are_harmless() {
    let cases = cases();
    assert!(cases.len() >= 79, "vacuous: only {} cases", cases.len());
    for sym in &cases {
        // Any answer is fine; returning is the requirement. Under
        // `tests/debug_assertions_hold.sh` this also catches index arithmetic
        // that would wrap in a release build.
        let _ = rustre_demangle::demangle(sym);
    }
}

/// In-range back-references must still resolve, or the sweep proves nothing.
///
/// Real Itanium symbols lean on substitutions heavily — the corpus figure is the
/// control that matters, since a parser that ignored `S…_` entirely would satisfy
/// the sweep above while losing most of the corpus.
#[test]
fn ordinary_back_references_still_resolve() {
    // A REAL corpus symbol using a substitution, not a hand-built one. My first
    // attempt asserted `_Z3fooSsS_` was valid; it is not — `Ss` is a *standard
    // abbreviation*, which registers no substitution, so `S_` had nothing to point
    // at. Real ground truth removes that whole class of mistake.
    assert_eq!(
        rustre_demangle::demangle("_ZN9__gnu_cxx15__snprintf_liteEPcyPKcS0_")
            .map(|r| r.demangled)
            .as_deref(),
        Some("__gnu_cxx::__snprintf_lite(char*, unsigned long long, char const*, char*)"),
        "S0_ must resolve to the substitution it refers to"
    );
    // And one where the substitution is a std:: type, exercising the other table.
    assert!(
        rustre_demangle::demangle("_ZL16get_adjusted_ptrPKSt9type_infoS1_PPv").is_some(),
        "S1_ after an St abbreviation must resolve"
    );

    // The corpus control: Itanium decodes must not have moved.
    let itanium = include_str!("data/real_symbols.txt")
        .lines()
        .map(str::trim)
        .filter(|s| s.starts_with("_Z"))
        .filter(|s| rustre_demangle::demangle(s).is_some())
        .count();
    assert!(
        itanium > 800,
        "only {itanium} Itanium symbols decode — substitution handling regressed"
    );
}
