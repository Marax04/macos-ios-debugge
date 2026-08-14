//! SUSPECTED DEFECT: Swift function signatures look inverted.
//!
//! `src/swift_demangler.rs` states its convention in a comment:
//!
//! ```text
//! // Swift's convention: last collected type is the return, prior are params.
//! ```
//!
//! The Swift ABI mangling grammar says the opposite — `function-signature ::=
//! result-type params-type …`, result first. Under that reading the crate
//! swaps the two, which is invisible on the symmetric case everyone tests
//! (`$s4main3fooyyF`, both `()`) and wrong on every asymmetric one:
//!
//! | symbol | crate | expected under result-first |
//! |---|---|---|
//! | `$s4main3barSiyF`  | `main.bar(Swift.Int) -> ()`      | `main.bar() -> Swift.Int` |
//! | `$s4main3fooyySiF` | `main.foo((), ()) -> Swift.Int`  | `main.foo(Swift.Int) -> ()` |
//!
//! The existing coverage cannot see it: `test_swift_vec_int_param_function`
//! asserts only `result.contains("main.bar")`, and its comment records the
//! same inverted belief.
//!
//! Stronger still — the **only** full-signature assertion anywhere in the
//! crate is `swift_demangler.rs:1394`:
//!
//! ```text
//! assert_eq!(swift_demangle("$s4main3fooyyF"), "main.foo() -> ()");
//! ```
//!
//! which is precisely the symmetric case where the ordering cannot matter.
//! Every other Swift assertion checks *type* rendering (`Foundation.URL`,
//! `[String: Int]`, `(Int) -> Bool`), never a signature derived from a
//! mangling. So the current ordering has never been verified by anything.
//! That does not make result-first correct, but it does mean the existing
//! behaviour rests on an unchecked comment rather than on evidence — which is
//! the relevant fact when deciding whether to change it.
//!
//! **Why this is documented rather than fixed.** There is no Swift oracle
//! among the crate's dependencies — unlike Itanium (`cpp_demangle`), Rust
//! (`rustc-demangle`) and MSVC (`msvc-demangler`), all of which caught or
//! vindicated changes during this sweep. `__Zoom` looked like fabricated
//! Itanium output and turned out to be correct only because an oracle said so.
//! Flipping Swift's convention on a reading of the spec, with nothing able to
//! contradict me, is the mistake this crate already documents in
//! `fidelity_demangle.rs`: bending code to match a belief broke correct code
//! before.
//!
//! Resolving this needs a Swift oracle (a `swift-demangle` binary, or symbols
//! with published expansions) — then either flip the convention or delete this
//! file.

/// The symmetric case, which is correct either way and must keep working.
#[test]
fn symmetric_signature_is_unaffected() {
    let r = rustre_demangle::demangle("$s4main3fooyyF").expect("must decode");
    assert_eq!(r.demangled, "main.foo() -> ()");
}

/// DOCUMENTED GAP: asymmetric signatures, asserted as the ABI grammar implies.
#[test]
#[ignore = "suspected param/result inversion; needs a Swift oracle to confirm before changing behaviour"]
fn asymmetric_signatures_follow_result_first() {
    for (sym, expected) in [
        ("$s4main3barSiyF", "main.bar() -> Swift.Int"),
        ("$s4main3fooyySiF", "main.foo(Swift.Int) -> ()"),
    ] {
        let got = rustre_demangle::demangle(sym)
            .unwrap_or_else(|| panic!("{sym} must decode"))
            .demangled;
        assert_eq!(got, expected, "{sym}");
    }
}

/// A method on a type loses its signature entirely, while a free function
/// keeps it — inconsistent regardless of which ordering is right.
#[test]
#[ignore = "methods drop the signature that free functions keep; same investigation"]
fn methods_keep_their_signature_like_free_functions() {
    let free = rustre_demangle::demangle("$s4main3fooyyF").unwrap().demangled;
    let method = rustre_demangle::demangle("$s4test3FooC3baryyF")
        .expect("must decode")
        .demangled;
    assert!(
        free.contains("->") && method.contains("->"),
        "free `{free}` has a signature but method `{method}` does not"
    );
}

/// Length-prefixed identifiers must survive into the output.
///
/// Swift has no oracle here, so this is the same input-defined completeness
/// invariant that found two losses in Go: pull every `<len><chars>` run out of
/// the mangled form and require it in the rendered one. A missing piece cannot
/// be seen by any property defined over the result's fields, because the
/// fields stay consistent with each other while the name loses a component.
#[test]
fn every_length_prefixed_identifier_survives() {
    for sym in [
        "$s4main3fooyyF",
        "$s4test3FooC3baryyF",
        "$s4main1xSivp",
        "$s10Foundation3URLV6stringACSgSS_tcfc",
        "$s7SwiftUI4TextV6stringACSS_tcfc",
        "_$s4main3fooyyF",
    ] {
        let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        for id in length_prefixed_identifiers(sym) {
            assert!(
                r.demangled.contains(&id),
                "{sym} lost {id:?} -> {}",
                r.demangled
            );
        }
    }
}

/// OBSERVATION, not asserted: initializers render as their argument label.
///
/// `$s10Foundation3URLV6stringACSgSS_tcfc` ends in `cfc`, which marks an
/// initializer; the crate renders `Foundation.URL.string`, promoting the
/// argument label to member name and dropping `init` entirely. Whether the
/// right output is `Foundation.URL.init(string:)` or something else needs the
/// same Swift oracle as the parameter/result question above — the two are best
/// resolved together, and guessing either would risk breaking the other.
#[test]
#[ignore = "documents initializer rendering; needs the same Swift oracle as the inversion above"]
fn initializers_are_not_rendered_as_their_argument_label() {
    let r = rustre_demangle::demangle("$s10Foundation3URLV6stringACSgSS_tcfc")
        .expect("must decode")
        .demangled;
    assert!(
        r.contains("init"),
        "an initializer should say so, got {r}"
    );
}

/// Every `<decimal-length><identifier>` run in a Swift mangled name.
fn length_prefixed_identifiers(s: &str) -> Vec<String> {
    let b = s.as_bytes();
    let (mut out, mut i) = (Vec::new(), 0usize);
    while i < b.len() {
        if !b[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let Ok(len) = s[start..i].parse::<usize>() else {
            continue;
        };
        if len >= 2 && i + len <= b.len() {
            let id = &s[i..i + len];
            if id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                out.push(id.to_owned());
            }
            i += len;
        }
    }
    out
}
