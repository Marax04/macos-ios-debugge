//! The post-processing this crate layers on top of its delegated engines.
//!
//! Iter 88 established that comparing the Itanium and Rust paths to `cpp_demangle` and
//! `rustc-demangle` is **tautological for the parse** — both delegate. What is *not*
//! tautological is the post-processing the crate applies afterwards, and iter 102
//! showed that a normalised differential cannot see spelling at all. So this compares
//! **raw** and accounts for every difference.
//!
//! Measured 2026-07-30:
//!
//! | path | compared | byte-identical | differ |
//! |---|---|---|---|
//! | Itanium | 813 | 783 | 30 |
//! | Rust | 137 | 1 | 136 |
//!
//! Every difference is a deliberate choice, and all three groups are pinned below.
//! **No defect** — but two of the three are worth guarding, because each would look
//! like a bug to someone trying to "match the oracle".

/// Itanium special names: 29 differences, all the `vtable for` spelling.
///
/// `cpp_demangle` writes `{vtable(X)}`; `c++filt` and this crate write `vtable for X`.
/// `backends::normalize_itanium_special` does the rewrite deliberately.
#[test]
fn itanium_special_names_use_the_cxxfilt_spelling() {
    let cases = [
        ("_ZTVN10__cxxabiv115__forced_unwindE", "vtable for __cxxabiv1::__forced_unwind"),
        ("_ZTVN10__cxxabiv117__class_type_infoE", "vtable for __cxxabiv1::__class_type_info"),
        ("_ZTV3Foo", "vtable for Foo"),
        ("_ZTI3Foo", "typeinfo for Foo"),
        ("_ZTS3Foo", "typeinfo name for Foo"),
    ];
    let mut checked = 0;
    for (sym, want) in cases {
        assert_eq!(
            rustre_demangle::demangle(sym).map(|r| r.demangled).as_deref(),
            Some(want),
            "{sym}"
        );
        checked += 1;
    }
    assert!(checked == 5, "expected 5 cases, checked {checked}");
}

/// **The crate is right and the oracle is wrong here.** Pinned so nobody "fixes" it.
///
/// `_ZNK10__cxxabiv120__si_class_type_info11__do_upcastEPKNS_17__class_type_infoEPKvRNS1_15__upcast_resultE`
///
/// The third parameter is `RNS1_15__upcast_resultE`: `R` (lvalue reference) applied to
/// the nested name `<S1_>::__upcast_result`. A reference qualifier goes at the **end**
/// of the declarator, so the parameter is
/// `__cxxabiv1::__class_type_info::__upcast_result&`.
///
/// ```text
/// cpp_demangle: …__class_type_info&::__upcast_result    <- not valid C++
/// this crate:   …__class_type_info::__upcast_result&
/// ```
///
/// This is the only raw Itanium difference that is not the `vtable for` spelling, and
/// it is the crate coming out ahead of the engine it delegates to. Recorded because a
/// future change aimed at raw agreement would replace correct output with the oracle's
/// malformed rendering.
#[test]
fn a_reference_to_a_nested_type_puts_the_ampersand_last() {
    let sym = "_ZNK10__cxxabiv120__si_class_type_info11__do_upcastEPKNS_17__class_type_infoEPKvRNS1_15__upcast_resultE";
    let got = rustre_demangle::demangle(sym)
        .expect("must decode")
        .demangled;
    assert!(
        got.contains("__class_type_info::__upcast_result&"),
        "the reference belongs at the end of the declarator: {got}"
    );
    assert!(
        !got.contains("__class_type_info&::"),
        "an `&` in the middle of a qualified name is not valid C++: {got}"
    );
}

/// Rust crate disambiguators are stripped — and that loses no identity.
///
/// `rustc-demangle` renders `core[d2e35dc664ad455]::panicking::assert_failed`; this
/// crate renders `core::panicking::assert_failed`. That accounts for 136 of the 137
/// raw differences, and the crate CLAUDE.md records *keeping* the hash as the defect on
/// the `rustre-symbols-pdb` side, so stripping is the intended behaviour.
///
/// Stripping is information loss, though, and this session has repeatedly found the
/// "distinct inputs, one output" failure. So the question worth answering is whether it
/// causes **collisions**: two different symbols rendering alike. Measured over both
/// corpora: **137 Rust symbols, 137 distinct renderings, 0 collisions.** Asserted here,
/// because a corpus containing two versions of the same crate would change the answer
/// and should fail loudly rather than silently merge two functions.
#[test]
fn stripping_the_crate_hash_causes_no_collisions() {
    use std::collections::BTreeMap;

    let mut by_rendering: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut count = 0;
    for data in [
        include_str!("data/pdb_symbols.txt"),
        include_str!("data/real_symbols.txt"),
    ] {
        for sym in data.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let Some(r) = rustre_demangle::demangle(sym) else {
                continue;
            };
            if r.abi != rustre_demangle::ManglingAbi::Rust {
                continue;
            }
            count += 1;
            by_rendering
                .entry(r.demangled)
                .or_default()
                .push(sym.to_owned());
        }
    }

    assert!(count >= 130, "vacuous: only {count} Rust symbols examined");

    let collisions: Vec<_> = by_rendering
        .iter()
        .filter(|(_, syms)| {
            let mut uniq = (*syms).clone();
            uniq.sort();
            uniq.dedup();
            uniq.len() > 1
        })
        .collect();
    assert!(
        collisions.is_empty(),
        "hash-stripping merged distinct symbols — two functions now share a rendering, \
         which is the failure mode stripping was assumed not to have:\n{collisions:#?}"
    );

    // And the stripping itself must still happen: a rendering carrying a
    // disambiguator would mean the behaviour silently reverted.
    // A disambiguator is `[` + hex digits + `]`. Testing for `[` and `]` alone matches
    // Rust **slice types** — `<&mut [u8] as core::fmt::Debug>::fmt` is a legitimate
    // rendering and my first version flagged it.
    let leaked: Vec<&String> = by_rendering
        .keys()
        .filter(|d| {
            d.split('[').skip(1).any(|after| {
                after
                    .split_once(']')
                    .is_some_and(|(inner, _)| {
                        inner.len() >= 8 && inner.bytes().all(|b| b.is_ascii_hexdigit())
                    })
            })
        })
        .collect();
    assert!(
        leaked.is_empty(),
        "crate disambiguators reached the output: {leaked:#?}"
    );
}
