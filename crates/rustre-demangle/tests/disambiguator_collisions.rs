//! OPEN DECISION: three conventions drop a disambiguator and collide.
//!
//! Zig (`__anon_<id>`) and Clojure (`__<counter>`) discard a numeric suffix, so
//! distinct symbols render identically **on the live path**:
//!
//! ```text
//! std.fmt.format__anon_1234  std.fmt.format__anon_5678  => std.fmt.format
//! clojure.core$f__5416       clojure.core$f__9999       => clojure.core/f
//! ```
//!
//! Nim was on this list until the assertion below was written against
//! `crate::demangle` instead of `demangle_nim`. It does not belong: an
//! all-lowercase Nim symbol never reaches the Nim decoder, because GNAT Ada is
//! tried first and claims it (`main__test_u4` -> Ada `main.test_u4`, which
//! keeps the suffix and does not collide). Measuring a non-live path is the
//! error this crate's own notes warn about — `crate::demangle` is the live one,
//! check there first — and it manufactured a defect that is not there.
//!
//! **Why this is documented rather than fixed.** The crate has TWO established
//! and opposite precedents, and deciding between them needs ground truth that
//! does not exist here:
//!
//! * *Keep it* — `msvc_constant_pool.rs::go_init_index_is_not_dropped` and
//!   `go_closure_index_path.rs` both restored dropped numeric information
//!   precisely because distinct functions collided, and
//!   `delegated_postprocessing.rs::stripping_the_crate_hash_causes_no_collisions`
//!   shows the crate only strips Rust's hash *after verifying it costs nothing*.
//! * *Drop it* — `corpus_decodes_do_not_collide_unexpectedly` deliberately
//!   whitelists Itanium `C1`/`C2`/`C3` ctor variants as "separate entry points
//!   for a single entity", and
//!   `convention_decoding.rs::julia_specialization_ids_are_deliberately_dropped`
//!   settles the identical question for Julia the other way, with the reasoning
//!   that two specializations of one function *are* one function.
//!
//! Which precedent applies turns on a per-language fact: is the id a
//! disambiguator between entry points of ONE entity (drop it, as with ctor
//! variants and Julia specializations) or between DIFFERENT entities (keep it,
//! as with Go closure indices)? There is no Nim, Zig or Clojure corpus and no
//! oracle for any of them, so answering it would be a guess — the failure mode
//! this crate punishes hardest.
//!
//! I attempted the fix, reverted it, and recorded this instead. The attempt is
//! worth naming: I overrode the Julia note above before reading it, which is
//! the mistake `fidelity_demangle.rs` already documents — read the note on the
//! test your change breaks.
//!
//! **Unblock it** the same way the Mach-O gap was unblocked: a real binary from
//! any one of the three toolchains, `nm`-ed into a corpus. Then the collision
//! either appears in practice or provably cannot, and the question answers
//! itself per language.

/// The collisions are real — this part is measured, not assumed.
///
/// Passing (not ignored) so the *evidence* stays checked even while the
/// decision is open: if a future change makes any of these distinct, this test
/// fails and whoever did it must update the open decision above rather than
/// leave it stale.
#[test]
fn the_documented_collisions_still_exist() {
    let d = |s: &str| rustre_demangle::demangle(s).map(|r| r.demangled);

    for (a, b) in [
        ("std.fmt.format__anon_1234", "std.fmt.format__anon_5678"),
        ("clojure.core$assoc_BANG___5416", "clojure.core$assoc_BANG___9999"),
    ] {
        let (ra, rb) = (d(a), d(b));
        assert!(ra.is_some(), "{a} must decode");
        assert_eq!(
            ra, rb,
            "{a} and {b} no longer collide — the open decision in this file's \
             header has been acted on and needs updating"
        );
    }
}

/// DOCUMENTED GAP: distinct symbols should render distinctly.
///
/// The behaviour this asserts is what "keep the disambiguator" would give. It
/// is ignored because the opposite reading — that these ids distinguish entry
/// points of a single entity, as Julia's and Itanium's ctor variants do — is
/// equally consistent with everything measurable here.
#[test]
#[ignore = "needs a Nim/Zig/Clojure corpus to decide whether these ids name one entity or several"]
fn disambiguators_should_not_collapse_distinct_symbols() {
    let d = |s: &str| rustre_demangle::demangle(s).map(|r| r.demangled);

    assert_ne!(
        d("std.fmt.format__anon_1234"),
        d("std.fmt.format__anon_5678"),
        "Zig"
    );
    assert_ne!(
        d("clojure.core$assoc_BANG___5416"),
        d("clojure.core$assoc_BANG___9999"),
        "Clojure"
    );
}

/// An all-lowercase Nim symbol is claimed by GNAT Ada, not by the Nim decoder.
///
/// Both readings are real manglings — `Main.Test_U4` is a valid GNAT name — so
/// this is ambiguity in the input, not a defect, and it is pinned rather than
/// changed. The Nim module doc asserted the opposite until this was measured.
#[test]
fn lowercase_nim_symbols_are_routed_to_ada() {
    let r = rustre_demangle::demangle("main__test_u4").expect("must decode");
    assert_eq!(r.demangled, "main.test_u4");
    assert_eq!(format!("{:?}", r.abi), "Ada");
    // The suffix survives under that reading, so these do NOT collide.
    assert_ne!(
        rustre_demangle::demangle("main__test_u4").map(|r| r.demangled),
        rustre_demangle::demangle("main__test_u5").map(|r| r.demangled)
    );
    // A module alias with an uppercase letter fails Ada's charset test and
    // reaches the Nim decoder instead.
    assert_eq!(
        rustre_demangle::demangle("newSeq__systemZassertions_u56").map(|r| r.demangled),
        Some("systemZassertions.newSeq".to_owned())
    );
}

/// Kotlin/Native, the fourth of the previously unprobed conventions, is clean:
/// it renders the full signature, so overloads stay distinct.
#[test]
fn kotlin_native_overloads_stay_distinct() {
    let d = |s: &str| rustre_demangle::demangle(s).map(|r| r.demangled);

    assert_eq!(
        d("kfun:a.B#c(kotlin.Int){}kotlin.Any?").as_deref(),
        Some("a.B.c(kotlin.Int): kotlin.Any?")
    );
    assert_ne!(
        d("kfun:a.B#c(kotlin.Int){}kotlin.Any?"),
        d("kfun:a.B#c(kotlin.Long){}kotlin.Any?"),
        "overloads differing only in parameter type must not collide"
    );
    assert_ne!(d("kfun:a.B#c(){}"), d("kfun:a.B#d(){}"));
}
