//! Every named component of a Swift symbol must survive into the output.
//!
//! Swift is one of the two ABIs with no oracle among this crate's
//! dependencies, so a *loss* of information has nothing to contradict it: the
//! rendered string stays plausible, nothing is fabricated, and a piece is
//! simply missing. This is the same blind spot `tests/go_completeness.rs`
//! exists for, and the same remedy — an invariant defined over the **input**
//! rather than over the output's own fields.
//!
//! Swift identifiers are length-prefixed (`<len><chars>`), which makes them
//! extractable *lexically*, without knowing the grammar and without deciding
//! what the correct rendering would be. That distinction is what makes this
//! checkable at all for an ABI with no oracle.
//!
//! A warning, learned the hard way while writing this file: a hand-written
//! Swift symbol with a miscounted length prefix produces a truncated but
//! *correct* decoding, which reads exactly like a demangler bug. `9MyProtocol`
//! (the name is 10 characters) decodes to `main.MyProtoco`, and that is the
//! right answer for the wrong input. Every symbol below has had its prefixes
//! verified. Do not add one without doing the same.

/// Extract `<len><chars>` identifiers from a Swift mangling, lexically.
///
/// Deliberately conservative: a digit run must be followed by exactly that many
/// identifier characters, otherwise the position is skipped. Missing a real
/// identifier only weakens the check; inventing one would make it lie.
fn identifiers(s: &str) -> Vec<String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() && b[i] != b'0' {
            let mut j = i;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if let Ok(n) = s[i..j].parse::<usize>()
                && n >= 2
                && j + n <= b.len()
            {
                let cand = &s[j..j + n];
                if cand.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    out.push(cand.to_owned());
                    i = j + n;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

/// Symbols whose every named component is currently preserved. Length prefixes
/// verified.
const SETTLED: &[&str] = &[
    "$s10Foundation3URLV6stringACSgSS_tcfc",
    "$s10Foundation4DataV5countSivg",
    "$s4test3FooC3baryyF",
    "$s7SwiftUI4TextV6stringACSS_tcfc",
    "$s4main3FooC3barSivg",
    "$s4main3FooC3barSivs",
    "$s4main3FooCACycfc",
    "$s4main3FooV3bazyySi_SStF",
    "$s4main8MyStructV5valueSivp",
    "$s4main3fooyyFZ",
    "$s4main1AC1BCfd",
    "$s4main6globalSivp",
];

#[test]
fn named_components_survive_demangling() {
    let mut checked = 0;
    for sym in SETTLED {
        let out = rustre_demangle::demangle(sym)
            .unwrap_or_else(|| panic!("{sym} must decode"))
            .demangled;

        let ids = identifiers(sym);
        assert!(
            !ids.is_empty(),
            "extractor found no identifiers in {sym} — the probe is broken, not the demangler"
        );
        for id in &ids {
            assert!(
                out.contains(id.as_str()),
                "component `{id}` of {sym} is missing from the output: {out}"
            );
            checked += 1;
        }
    }
    // Vacuity guard: "nothing lost because it is right" and "nothing lost
    // because nothing was compared" look identical from a green test.
    assert!(
        checked > 25,
        "too few components compared to be meaningful: {checked}"
    );
}

/// The internal substitution index must never reach the output. Guards the same
/// leak `tests/swift_substitutions.rs` pins, but across whole symbols rather
/// than the substitution table alone.
#[test]
fn no_internal_substitution_index_leaks() {
    for sym in SETTLED {
        let out = rustre_demangle::demangle(sym)
            .unwrap_or_else(|| panic!("{sym} must decode"))
            .demangled;
        let leaked = out
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|t| t.len() > 1 && t.starts_with('S') && t[1..].bytes().all(|b| b.is_ascii_digit()));
        assert!(!leaked, "substitution index leaked for {sym}: {out}");
    }
}

/// **Open decision — asserts the correct behaviour, which is not implemented.**
///
/// Local functions and closures are not handled: there is no `L` local-entity
/// marker handling in `swift_demangler` at all, so the parser stops at the
/// enclosing function and drops the local name without saying so.
/// `$s4main5outeryyF6insideL_yyF` (prefixes verified: `4main`, `5outer`,
/// `6inside`) renders `main.outer() -> ()` — `inside` is simply gone.
///
/// The *loss* is certain. The *rendering* is not: Swift's own demangler prints
/// local entities as `inside #1 () in main.outer()`, but that spelling cannot
/// be sourced from anything inside this crate, and inventing one is how
/// fabricated output gets in — the failure mode this crate punishes hardest.
/// So this is recorded as an ignored test in the house style for oracle-blocked
/// questions, rather than fixed on a guess.
///
/// Unblock it with a Swift oracle, or with a real Mach-O Swift corpus.
///
/// **Partially addressed.** The symbol no longer *renders* as its own enclosing
/// function — it now declines, so the collision documented in
/// `a_dropped_local_name_is_not_a_silent_truncation` is gone. This test stays
/// ignored because it asserts the end state, which is that `inside` survives
/// into the output; declining is honest, not complete.
#[test]
#[ignore = "local functions are unimplemented; declining now, but the rendering still needs a Swift oracle"]
fn local_functions_do_not_lose_their_name() {
    let sym = "$s4main5outeryyF6insideL_yyF";
    let out = rustre_demangle::demangle(sym)
        .unwrap_or_else(|| panic!("{sym} must decode"))
        .demangled;
    assert!(
        out.contains("inside"),
        "the local function's name must survive: {out}"
    );
}


/// A local entity whose name is dropped must not silently become its enclosing
/// function.
///
/// Swift is deliberately exempt from the crate's trailing-input rule, for a
/// measured reason recorded in `tests/trailing_input.rs`: the parser consumes the
/// whole symbol for only 9 of 16 realistic inputs, so demanding full consumption
/// would decline 7 legitimate ones. That exemption was too broad — it also
/// covered the case where the unconsumed tail contains a **name**:
///
/// ```text
/// $s4main5outeryyF6insideL_yyF  =>  main.outer() -> ()
/// $s4main5outeryyF              =>  main.outer() -> ()
/// ```
///
/// Two different entities, one output. This is decidable with no Swift oracle,
/// because it makes no claim about how a local entity *should* render — only
/// that it must not become indistinguishable from something else. The tails the
/// exemption exists to protect are type and constructor grammar, where signature
/// detail is lost but the name is fully recovered; that behaviour is unchanged,
/// and the controls below are what prove the fix did not widen into it.
#[test]
fn a_dropped_local_name_is_not_a_silent_truncation() {
    // Length prefixes computed, never hand-counted.
    let sym = |parts: &[&str], tail: &str| {
        let mut out = String::from("$s");
        for p in parts {
            out.push_str(&p.len().to_string());
        out.push_str(p);
        }
        out.push_str(tail);
        out
    };

    let mut checked = 0;
    for (parts, local) in [
        (vec!["main", "outer"], "inside"),
        (vec!["app", "fn"], "inner"),
        (vec!["MyModule", "someFunction"], "helper"),
    ] {
        let enclosing = sym(&parts, "yyF");
        let with_local = format!("{enclosing}{}{local}L_yyF", local.len());

        let outer = rustre_demangle::demangle(&enclosing)
            .unwrap_or_else(|| panic!("{enclosing} must decode"))
            .demangled;

        let inner = rustre_demangle::demangle(&with_local).map(|r| r.demangled);
        assert_ne!(
            inner.as_deref(),
            Some(outer.as_str()),
            "{with_local} must not render as its own enclosing function"
        );
        // Either it names the local entity, or it declines. Both are honest; the
        // collision is not. Written as a disjunction so implementing local
        // entities later satisfies this test rather than breaking it.
        match inner {
            None => {}
            Some(d) => assert!(
                d.contains(local),
                "{with_local} decoded without naming {local}: {d}"
            ),
        }
        checked += 1;
    }
    assert!(checked == 3, "expected 3 pairs, checked {checked}");

    // Controls: the partial-consumption symbols the Swift exemption exists for
    // must still decode. Their tails are type/constructor grammar with no
    // dropped name, so the narrow rule must not touch them.
    for sym in [
        "$s10Foundation3URLV6stringACSgSS_tcfc",
        "$s7SwiftUI4TextV6stringACSS_tcfc",
        "$s10Foundation4DataV5countSivg",
        "$s4main3FooV3bazyySi_SStF",
        "$sSS7countedSiSo7NSArrayCF",
    ] {
        assert!(
            rustre_demangle::demangle(sym).is_some(),
            "{sym} decodes today and must keep decoding"
        );
    }
}

/// A short local name must not escape the collision guard.
///
/// `a_dropped_local_name_is_not_a_silent_truncation` (iter 65) declines a symbol
/// whose local name never reaches the output. The check was
/// `demangled.contains(name)` — a **substring** test where a **component** test
/// was meant, so a short name occurred incidentally in the enclosing rendering
/// and the guard passed vacuously:
///
/// ```text
/// $s4main5outeryyF6insideL_yyF  =>  <declined>            correct
/// $s4main5outeryyF1aL_yyF       =>  main.outer() -> ()    collided
/// ```
///
/// `"main.outer() -> ()"` contains `a`, `n`, `u`, `t`, `e`, `r`, `ou` and `ute`,
/// so the guard only worked for names long enough to be unlucky — it caught
/// `inside` and `helper` and let every one-letter local through. The fix matches
/// on identifier boundaries.
///
/// The cases are chosen from the letters of the *enclosing* rendering, which is
/// what makes them discriminating: a name absent from it (`zz`) would have been
/// caught by the old code too and proves nothing.
#[test]
fn a_short_local_name_does_not_escape_the_guard() {
    let enclosing = "$s4main5outeryyF";
    let outer = rustre_demangle::demangle(enclosing)
        .expect("the enclosing function must decode")
        .demangled;
    assert_eq!(outer, "main.outer() -> ()", "premise: the rendering under test");

    let mut checked = 0;
    // Every one of these occurs as a substring of `main.outer() -> ()`.
    for local in ["a", "n", "u", "t", "e", "r", "ou", "ute", "out"] {
        assert!(
            outer.contains(local),
            "test is not discriminating: {local:?} is not a substring of {outer:?}"
        );
        let sym = format!("{enclosing}{}{local}L_yyF", local.len());
        let got = rustre_demangle::demangle(&sym).map(|r| r.demangled);
        assert_ne!(
            got.as_deref(),
            Some(outer.as_str()),
            "{sym}: local {local:?} still collides with its enclosing function"
        );
        checked += 1;
    }
    assert!(checked >= 9, "vacuous: only {checked} short names checked");

    // KNOWN RESIDUAL, pinned rather than hidden: a local name that *coincides*
    // with an enclosing component still collides. `main` and `outer` do occur as
    // whole identifiers in `main.outer() -> ()` — as the module and the enclosing
    // function — so an input-only rule cannot tell "this name is somewhere in the
    // output" from "this name is here as the local entity".
    //
    // That is the same positional ambiguity recorded in
    // `backends::dropped_swift_local_name`'s doc for the general case: resolving
    // it needs parser state, not a better string search. Nine of eleven cases are
    // closed; these two are the boundary of the approach.
    for local in ["main", "outer"] {
        let sym = format!("{enclosing}{}{local}L_yyF", local.len());
        assert_eq!(
            rustre_demangle::demangle(&sym).map(|r| r.demangled).as_deref(),
            Some(outer.as_str()),
            "{sym} is the documented residual; if it now declines, the rule became              position-aware and this note is stale"
        );
    }

    // Control: the partial-consumption symbols the Swift exemption protects.
    for sym in [
        "$s10Foundation3URLV6stringACSgSS_tcfc",
        "$s10Foundation4DataV5countSivg",
    ] {
        assert!(
            rustre_demangle::demangle(sym).is_some(),
            "{sym} decodes today and must keep decoding"
        );
    }
}
