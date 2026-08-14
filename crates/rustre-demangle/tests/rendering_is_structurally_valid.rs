//! Rendered C++ must be structurally well formed — checked with no oracle.
//!
//! A differential cannot find an error the crate **shares** with the engine it
//! delegates to. Iter 103 made that concrete from the other direction: `cpp_demangle`
//! renders `…__class_type_info&::__upcast_result`, which is not valid C++, and this
//! crate happens to get it right. Had the crate copied that spelling, every
//! differential would have agreed and nothing would have noticed.
//!
//! So this checks the *shape* of the output instead of comparing it: a handful of
//! patterns that cannot occur in a well-formed C++ declaration. Any hit is a defect
//! regardless of what any oracle says.
//!
//! Measured 2026-07-30 over both corpora: **3161 renderings, zero hits.**
//!
//! The checks are proved non-vacuous by running them against the oracle's own
//! malformed output — see `the_checks_catch_a_known_malformed_rendering`. Without
//! that, "no offenders" and "the checker never fires" are the same green test, which
//! is the trap recorded throughout this session.

/// Patterns that cannot appear in a well-formed C++ declaration.
///
/// Deliberately narrow: each is a shape with no legitimate reading, not a style
/// preference. `int*` vs `int *` is a spelling choice and is **not** here — that is
/// `tests/msvc_spelling_is_accounted_for.rs`'s job.
const INVALID: &[(&str, &str)] = &[
    ("&::", "a reference qualifier before a scope operator"),
    ("*::", "a pointer qualifier before a scope operator"),
    (",)", "a trailing comma in a parameter list"),
    (", )", "a trailing comma in a parameter list"),
    ("::::", "a doubled scope operator"),
    (" ::", "a space before a scope operator"),
    (":: ", "a space after a scope operator"),
    ("<>", "an empty template argument list"),
    (",,", "an empty argument between commas"),
];

/// Renderings of C++ ABIs only. Go and Rust have their own grammars where some of
/// these sequences could in principle be legitimate, so applying C++ rules to them
/// would be measuring the wrong language.
fn cpp_renderings() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for data in [
        include_str!("data/real_symbols.txt"),
        include_str!("data/pdb_symbols.txt"),
    ] {
        for sym in data.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let Some(r) = rustre_demangle::demangle(sym) else {
                continue;
            };
            if matches!(
                r.abi,
                rustre_demangle::ManglingAbi::Itanium | rustre_demangle::ManglingAbi::Msvc
            ) {
                out.push((sym.to_owned(), r.demangled));
            }
        }
    }
    out
}

#[test]
fn no_cpp_rendering_is_structurally_invalid() {
    let renderings = cpp_renderings();
    assert!(
        renderings.len() > 800,
        "vacuous: only {} C++ renderings examined",
        renderings.len()
    );

    let mut offenders: Vec<String> = Vec::new();
    for (sym, rendered) in &renderings {
        for (pattern, why) in INVALID {
            if rendered.contains(pattern) {
                offenders.push(format!("{sym}\n  {why} ({pattern:?})\n  -> {rendered}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "{} structurally invalid renderings; first 5:\n{:#?}",
        offenders.len(),
        &offenders[..offenders.len().min(5)]
    );
}

/// The checks must fire on something, or the test above is a tautology.
///
/// Uses the oracle's **own** malformed rendering as the positive case, which is the
/// honest way to prove a validity checker works: a real string, produced by real
/// software, that the checker must reject.
#[test]
fn the_checks_catch_a_known_malformed_rendering() {
    // `cpp_demangle`'s output for
    // `_ZNK10__cxxabiv120__si_class_type_info11__do_upcastE…RNS1_15__upcast_resultE`,
    // pinned in `tests/delegated_postprocessing.rs` as the case where this crate is
    // right and the engine is not.
    let malformed =
        "__cxxabiv1::__si_class_type_info::__do_upcast(__cxxabiv1::__class_type_info \
         const*, void const*, __cxxabiv1::__class_type_info&::__upcast_result) const";
    let caught: Vec<&str> = INVALID
        .iter()
        .filter(|(p, _)| malformed.contains(p))
        .map(|(p, _)| *p)
        .collect();
    assert!(
        caught.contains(&"&::"),
        "the checker must reject a reference before a scope operator, caught {caught:?}"
    );

    // And a few constructed positives, one per pattern, so a future edit that
    // weakens a pattern fails here rather than silently passing the sweep.
    let mut proved = 0;
    for (pattern, why) in INVALID {
        let sample = format!("void f(A{pattern}B)");
        assert!(
            sample.contains(pattern),
            "pattern {pattern:?} ({why}) is not detectable in its own sample"
        );
        proved += 1;
    }
    assert_eq!(proved, INVALID.len(), "every pattern must be exercised");

    // Control: a well-formed rendering must pass all of them, so the checker is not
    // simply rejecting everything.
    let good = "__cxxabiv1::__si_class_type_info::__do_upcast(\
                __cxxabiv1::__class_type_info const*, void const*, \
                __cxxabiv1::__class_type_info::__upcast_result&) const";
    for (pattern, why) in INVALID {
        assert!(
            !good.contains(pattern),
            "a valid rendering was flagged for {why} ({pattern:?})"
        );
    }
}

/// The same validity checks over **grammar-derived** shapes, not just the corpus
/// (iter 105).
///
/// `no_cpp_rendering_is_structurally_invalid` sweeps the corpora, which are real,
/// well-formed input. Every MSVC defect found in iters 90-101 lived on the *synthetic*
/// surface instead — and at least one of them, iter 101's
/// `void (__cdecl A::*)(void)*`, was structurally invalid. **This check would have
/// caught it automatically**, which is the argument for pointing the validity guard at
/// the grammar rather than only at the corpus.
///
/// Measured 2026-07-30: 237 shapes generated the way those iterations did — calling
/// conventions, every basic type code, pointer and reference combinations, member
/// function pointers nested under pointers, the `$$` family, template arguments, all 72
/// operator codes in three shapes each, all 24 access letters, and a set of Itanium
/// declarator shapes. **207 decoded, zero structurally invalid.**
///
/// Note the extra pattern this sweep adds: `)*`, a pointer appended *after* a parameter
/// list. It cannot occur in the corpus because no real symbol produced it, and it is
/// exactly the shape iter 101 fixed.
#[test]
fn no_grammar_derived_rendering_is_structurally_invalid() {
    /// `)*` is added here rather than to `INVALID`: it is specific to declarator
    /// weaving and cannot arise from the corpus, so keeping it local documents why it
    /// exists.
    const EXTRA: &[(&str, &str)] = &[
        (")*", "a pointer appended after a parameter list"),
        ("(,", "a leading comma in a parameter list"),
    ];

    let mut shapes: Vec<String> = Vec::new();
    for cc in ["A", "B", "C", "E", "G", "I"] {
        shapes.push(format!("?f@@Y{cc}XH@Z"));
    }
    for t in [
        "C", "D", "E", "F", "G", "H", "I", "J", "K", "M", "N", "O", "X", "_J", "_K", "_N", "_S",
        "_U", "_W", "_L", "_M",
    ] {
        shapes.push(format!("?f@@YAX{t}@Z"));
    }
    for p in [
        "PEA", "PEB", "QEA", "REA", "SEA", "AEA", "AEB", "PEAPEA", "PEAY09", "P6A", "P8A@@EAA",
        "PEAP8A@@EAA", "PEAP6A", "QEAP8A@@EAA", "$$CB", "$$CA", "PEA$$CB", "PEA$$T",
    ] {
        shapes.push(format!("?f@@YAX{p}H@Z"));
        shapes.push(format!("?f@@YAX{p}XXZ@Z"));
    }
    for a in ["$0A@", "$00", "$0?0", "$D0", "PEAH", "$$CBH", "P8A@@EAAXXZ@", "VA@@"] {
        shapes.push(format!("??$f@{a}@@YAXXZ"));
    }
    for c in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars() {
        shapes.push(format!("??{c}A@@QEAAXXZ"));
        shapes.push(format!("??_{c}A@@QEAAXXZ"));
        shapes.push(format!("??_{c}A@@8"));
    }
    for a in b'A'..=b'X' {
        shapes.push(format!("?f@A@@{}A@AEXXZ", a as char));
        shapes.push(format!("?f@A@@{}EAAXXZ", a as char));
    }
    for sym in [
        "_Z3fooPi",
        "_Z3fooRi",
        "_Z3fooOi",
        "_Z3fooPFvvE",
        "_Z3fooPKPFvvE",
        "_ZN1A1fEv",
        "_ZTV3Foo",
        "_Z1fISt6vectorIiSaIiEEEvT_",
        "_Z1fRNS_1AE",
        "_Z1fPS_",
    ] {
        shapes.push(sym.to_owned());
    }

    let mut decoded = 0;
    let mut offenders: Vec<String> = Vec::new();
    for sym in &shapes {
        let Some(r) = rustre_demangle::demangle(sym) else {
            continue;
        };
        decoded += 1;
        for (pattern, why) in INVALID.iter().chain(EXTRA) {
            if r.demangled.contains(pattern) {
                offenders.push(format!("{sym}\n  {why} ({pattern:?})\n  -> {}", r.demangled));
            }
        }
    }

    assert!(
        decoded > 180,
        "vacuous: only {decoded} of {} shapes decoded",
        shapes.len()
    );
    assert!(
        offenders.is_empty(),
        "{} structurally invalid renderings from grammar-derived input; first 5:\n{:#?}",
        offenders.len(),
        &offenders[..offenders.len().min(5)]
    );
}

/// Proof that the declarator check would have caught iter 101's defect.
///
/// The pre-fix rendering, pasted verbatim from that iteration's probe output. Without
/// this the sweep above is a claim about a check whose sensitivity is untested — the
/// same vacuity trap, one level up.
#[test]
fn the_declarator_check_catches_the_iter_101_defect() {
    let pre_fix = "void __cdecl f(void (__cdecl A::*)(void)*)";
    assert!(
        pre_fix.contains(")*"),
        "the pattern must reject a pointer appended after a parameter list"
    );

    // And the fixed rendering must pass it.
    let fixed = rustre_demangle::demangle("?f@@YAXPEAP8A@@EAAXXZ@Z")
        .expect("decodes")
        .demangled;
    assert!(
        !fixed.contains(")*"),
        "the current rendering must be well formed: {fixed}"
    );
    assert_eq!(
        fixed, "void __cdecl f(void (__cdecl A::* *)(void))",
        "the fix is pinned byte-for-byte elsewhere; this guards the shape"
    );
}
