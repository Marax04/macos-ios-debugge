//! MSVC grammar beyond the corpus, differenced against `msvc-demangler`.
//!
//! MSVC is the one ABI where this is worth doing and not tautological: measured at
//! iter 89, the live Itanium and Rust paths **delegate** to `cpp_demangle` and
//! `rustc-demangle`, so comparing them to those engines proves nothing — but
//! **MSVC does not delegate**. The live MSVC parser is this crate's own code, and
//! `msvc-demangler` is an independent engine, so every disagreement is a real
//! finding.
//!
//! The existing coverage is narrow: 14 real PDB symbols and 20 curated feature
//! shapes. This sweeps 54 grammar-derived symbols the oracle accepts — every
//! calling convention, every basic type code, pointer/reference/cv combinations,
//! template numeric arguments, storage classes, vtables, thunks, RTTI and the
//! anonymous namespace.
//!
//! Measured 2026-07-30: **46 identical, 5 differing, 3 missed**. Four of the eight
//! gaps were fabrications and are fixed here, taking it to **50 identical**:
//!
//! | symbol | was | now |
//! |---|---|---|
//! | `?f@?A0x12345678@@YAXXZ` | `x12345678::f::operator[]::f(void)` | `` `anonymous namespace'::f `` |
//! | `?f@@YAX_L@Z` | `f(_unknown_L)` | `f(__int128)` |
//! | `?f@@YAX_M@Z` | `f(_unknown_M)` | `f(unsigned __int128)` |
//! | `??_DA@@QEAAXXZ` | `A::operator_unknown_D(void)` | `` A::`vbase destructor'(void) `` |
//!
//! The anonymous namespace was the worst: an `operator[]` invented from nothing,
//! the hex discriminator turned into a namespace, and the function name emitted
//! twice — confidently wrong structure rather than a missing feature.
//!
//! `_unknown_<code>` and `operator_unknown_<code>` are this module's own "I could
//! not read this" markers, so emitting them is the fabrication class swept at iter
//! 75. An unrecognised `_`-prefixed **type** code now declines, which is what the
//! rest of the crate does with an unreadable construct.
//!
//! ### What is still open, and why it is not fabrication
//!
//! Four gaps remain and all are honest: `??_8A@@7B@` decodes its cv byte as
//! `volatile` where the oracle says `const`, and `$D0` (template-parameter),
//! `??_9` (vcall thunk) and `??_B` (local static guard) are unimplemented and
//! **decline**. Missing capability, not invented output.

mod msvc_oracle;

use msvc_demangler::{demangle as oracle, DemangleFlags};
use msvc_oracle::normalise;

/// The fixes, asserted individually so a regression names itself.
#[test]
fn the_four_fabrications_are_fixed() {
    let cases = [
        ("?f@?A0x12345678@@YAXXZ", "anonymous namespace"),
        ("?f@@YAX_L@Z", "__int128"),
        ("?f@@YAX_M@Z", "unsigned __int128"),
        ("??_DA@@QEAAXXZ", "vbase destructor"),
    ];
    let mut checked = 0;
    for (sym, what) in cases {
        let want = oracle(sym, DemangleFlags::COMPLETE)
            .unwrap_or_else(|_| panic!("{sym} must be valid MSVC"));
        let got = rustre_demangle::demangle(sym).map(|r| r.demangled);
        assert_eq!(
            got.as_deref().map(normalise),
            Some(normalise(&want)),
            "{what}: {sym}\n  oracle: {want}\n  ours:   {got:?}"
        );
        // And the markers must be gone, not merely rearranged.
        let d = got.expect("must decode");
        assert!(
            !d.contains("_unknown_") && !d.contains("operator["),
            "{what}: a marker survived: {d}"
        );
        checked += 1;
    }
    assert!(checked == 4, "expected 4 cases, checked {checked}");
}

/// The broad sweep, as a floor. Improvements re-baseline; regressions fail.
#[test]
fn msvc_grammar_agreement_is_pinned() {
    let mut cases: Vec<String> = Vec::new();
    for cc in ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J"] {
        cases.push(format!("?f@@Y{cc}XH@Z"));
    }
    for t in [
        "C", "D", "E", "F", "G", "H", "I", "J", "K", "M", "N", "O", "X", "Z", "_D", "_E", "_F",
        "_G", "_H", "_I", "_J", "_K", "_L", "_M", "_N", "_S", "_U", "_W",
    ] {
        cases.push(format!("?f@@YAX{t}@Z"));
    }
    for p in [
        "PEA", "PEB", "QEA", "REA", "SEA", "AEA", "AEB", "PEAPEA", "PEAY", "P6A",
    ] {
        cases.push(format!("?f@@YAX{p}H@Z"));
    }
    for a in [
        "$0A@", "$00", "$0?0", "$0M@", "$0BAA@", "$D0", "$F0A@", "$G0A@A@", "$H0A@", "$I0A@A@",
    ] {
        cases.push(format!("??$f@{a}@@YAXXZ"));
    }
    for sc in ["0", "1", "2", "3", "4"] {
        cases.push(format!("?x@@{sc}HA"));
    }
    for s in [
        "?f@?A0x12345678@@YAXXZ",
        "??_7A@@6B@",
        "??_8A@@7B@",
        "??_9A@@$BAA@AA",
        "??_B?1??f@@9@51",
        "??_C@_02ABCD@ab@",
        "??_DA@@QEAAXXZ",
        "?f@A@@UEAA@XZ",
        "??0A@@QEAA@XZ",
        "??1A@@QEAA@XZ",
    ] {
        cases.push(s.to_owned());
    }

    let (mut compared, mut identical) = (0, 0);
    let mut divergences: Vec<String> = Vec::new();
    for sym in &cases {
        let Ok(want) = oracle(sym, DemangleFlags::COMPLETE) else {
            continue; // no ground truth
        };
        compared += 1;
        match rustre_demangle::demangle(sym).map(|r| r.demangled) {
            Some(g) if normalise(&g) == normalise(&want) => identical += 1,
            other => divergences.push(format!("{sym}\n  oracle: {want}\n  ours:   {other:?}")),
        }
    }

    assert!(compared >= 50, "vacuous: only {compared} shapes had ground truth");
    assert!(
        identical >= 50,
        "MSVC grammar agreement regressed: {identical} of {compared} (was 50)\n{:#?}",
        &divergences[..divergences.len().min(5)]
    );
}

/// Second grammar batch (iter 91): the corners the first sweep did not reach.
///
/// Batch 1 covered calling conventions, basic types, pointers, template numbers,
/// storage classes and RTTI, reaching 50 of 54. This batch covers what was left:
/// member function pointers, `__restrict`/`__unaligned`, arrays with dimensions,
/// the `$$` type modifiers, `std::nullptr_t`, string literals, thread-safe-static
/// guards, dynamic initialisers, and the array allocation operators.
///
/// Agreement started at **16 of 31** — far worse than batch 1, which is the point of
/// probing corners. Four of the gaps were fabrications, all fixed here, taking it to
/// **20 of 31**:
///
/// | symbol | was | now |
/// |---|---|---|
/// | `??_UA@@SAPEAX_K@Z` | `A::operator_unknown_U(…)` | `A::operator new[](…)` |
/// | `??_VA@@SAXPEAX@Z` | `A::operator_unknown_V(…)` | `A::operator delete[](…)` |
/// | `??__Ex@@YAXXZ` | `Ex::operator_unknown__(void)` | `` x::`dynamic initializer'(void) `` |
/// | `??__Fx@@YAXXZ` | `Fx::operator_unknown__(void)` | `` x::`dynamic atexit destructor'(void) `` |
///
/// The `??__E`/`??__F` pair is worth noting: the name that follows is the **object**
/// being initialised, not a class, and folding it into the qualified name produced
/// `Ex::` — a class that does not exist.
///
/// ### The eleven that remain are honest
///
/// Nine **decline** (member function pointers `P8`, `$$T` nullptr, `$$A`/`$$B`/`$$C`
/// modifiers, string literals, `$$CBH` in template args) — missing capability, not
/// invented output. Two differ without fabricating: the thread-safe-static guard
/// `?$TSS0@…` renders with the components in a different order, and
/// `?f@A@@QEIAAXXZ` **silently drops `__restrict`**. That last one is a lost
/// qualifier and the most substantive remaining gap in this file.
#[test]
fn the_second_batch_fabrications_are_fixed() {
    let cases = [
        ("??_UA@@SAPEAX_K@Z", "operator new[]"),
        ("??_VA@@SAXPEAX@Z", "operator delete[]"),
        ("??__Ex@@YAXXZ", "dynamic initializer"),
        ("??__Fx@@YAXXZ", "dynamic atexit destructor"),
    ];
    let mut checked = 0;
    for (sym, what) in cases {
        let want = oracle(sym, DemangleFlags::COMPLETE)
            .unwrap_or_else(|_| panic!("{sym} must be valid MSVC"));
        let got = rustre_demangle::demangle(sym).map(|r| r.demangled);
        assert_eq!(
            got.as_deref().map(normalise),
            Some(normalise(&want)),
            "{what}: {sym}\n  oracle: {want}\n  ours:   {got:?}"
        );
        let d = got.expect("must decode");
        assert!(
            !d.contains("_unknown_"),
            "{what}: a marker survived: {d}"
        );
        checked += 1;
    }
    assert!(checked == 4, "expected 4 cases, checked {checked}");
}

/// The batch-2 floor, and a guard that the remaining gaps stay *declines*.
#[test]
fn the_second_batch_agreement_is_pinned() {
    const BATCH2: &[&str] = &[
        "?f@@YAXPEQA@@H@Z", "?f@@YAXP8A@@EAAXXZ@Z", "?f@@YAXP8A@@EAAHH@Z@Z",
        "?f@@YAXPEIAH@Z", "?f@@YAXPEFAH@Z", "?f@@YAXPEIFAH@Z",
        "?a@@3PAY09HA", "?a@@3PAY0BA@HA", "?f@@YAXQAY09H@Z",
        "?f@@YAX$$T@Z", "?f@@YAX$$A6AXXZ@Z", "?f@@YAX$$BY0A@H@Z", "?f@@YAX$$CAH@Z",
        "??_C@_02DPKJ@ab?$AA@", "??_C@_05KAAA@hello?$AA@",
        "?$TSS0@?1??f@@9@4HA", "??__Ex@@YAXXZ", "??__Fx@@YAXXZ",
        "??_R2A@@8", "??_R3A@@8", "??_R4A@@6B@",
        "??$f@PEAH@@YAXPEAH@Z", "??$g@VA@@@@YAXXZ", "??$h@$$CBH@@YAXXZ",
        "?f@A@@QEBAXXZ", "?f@A@@QEIAAXXZ", "?f@A@@KEAAXXZ",
        "??8A@@QEAA_NXZ", "??9A@@QEAA_NXZ", "??AA@@QEAAAEAHH@Z",
        "??EA@@QEAAAEAV0@XZ", "??FA@@QEAAAEAV0@XZ", "??GA@@QEAA?AV0@XZ",
        "??_UA@@SAPEAX_K@Z", "??_VA@@SAXPEAX@Z",
    ];

    let (mut compared, mut identical) = (0, 0);
    let mut fabrications: Vec<String> = Vec::new();
    for sym in BATCH2 {
        let Ok(want) = oracle(sym, DemangleFlags::COMPLETE) else {
            continue;
        };
        compared += 1;
        match rustre_demangle::demangle(sym).map(|r| r.demangled) {
            Some(g) if normalise(&g) == normalise(&want) => identical += 1,
            // A gap must be a decline or an honest difference — never a marker.
            Some(g) if g.contains("_unknown_") => {
                fabrications.push(format!("{sym} -> {g}"));
            }
            Some(_) | None => {}
        }
    }

    assert!(compared >= 28, "vacuous: only {compared} shapes had ground truth");
    assert!(
        identical >= 20,
        "batch-2 agreement regressed: {identical} of {compared} (was 20)"
    );
    assert!(
        fabrications.is_empty(),
        "a gap is rendering a marker instead of declining: {fabrications:#?}"
    );
}

/// `__restrict` on the `this` pointer must reach the output (iter 92).
///
/// `parse_msvc_qualifiers` consumed the `this`-pointer modifiers `E`/`F`/`I` and
/// discarded all three. Consuming them is required — the comment there explains
/// that leaving one would decode every following field a byte out of alignment —
/// but `I` is `__restrict` and carries meaning:
///
/// ```text
/// ?f@A@@QEIAAXXZ   oracle: public: void __cdecl A::f(void) __restrict
///                  ours:   public: void __cdecl A::f(void)
/// ```
///
/// A lost qualifier rather than an invented one, but a caller comparing signatures
/// would see two different functions as identical — the same "distinct inputs, one
/// output" failure as the collisions fixed at iters 60-65, in a different field.
///
/// ### Only `I` is surfaced, and that is a measurement not a preference
///
/// * `E` is `__ptr64`, which `undname` does not print on x64.
/// * `F` is `__unaligned`, and **`msvc-demangler` does not print it either**:
///   `?f@A@@QEFAAXXZ` gives `A::f(void)`. My first attempt rendered it and this
///   test caught the disagreement. With no ground truth saying it should appear,
///   rendering it would be inventing output — so `F` is still consumed and dropped.
///
/// The paired cases are what make this discriminating: `QEIAA` and `QEFAA` differ by
/// one byte and must render *differently*, while `QEAA` must stay unchanged.
#[test]
fn this_pointer_restrict_is_rendered_and_unaligned_is_not() {
    let cases = [
        "?f@A@@QEIAAXXZ",  // __restrict
        "?f@A@@QEFAAXXZ",  // __unaligned — not printed by the oracle
        "?f@A@@QEIFAAXXZ", // both
        "?f@A@@QEBAXXZ",   // const, no modifier
        "?f@A@@QEIBAXXZ",  // const + __restrict
        "?f@A@@QEAAXXZ",   // neither
        "?f@A@@SAXXZ",     // static: no `this`, so no modifiers at all
        "?f@A@@UEAAXXZ",   // virtual
    ];

    let mut checked = 0;
    for sym in cases {
        let want = oracle(sym, DemangleFlags::COMPLETE)
            .unwrap_or_else(|_| panic!("{sym} must be valid MSVC"));
        let got = rustre_demangle::demangle(sym).map(|r| r.demangled);
        assert_eq!(
            got.as_deref().map(normalise),
            Some(normalise(&want)),
            "{sym}\n  oracle: {want}\n  ours:   {got:?}"
        );
        checked += 1;
    }
    assert!(checked == 8, "expected 8 cases, checked {checked}");

    // Discriminating pair, asserted directly: one byte apart, and the renderings
    // must differ. Without this, dropping `__restrict` again would still satisfy
    // every equality above only if the oracle also dropped it — which it does not.
    let restrict = rustre_demangle::demangle("?f@A@@QEIAAXXZ").expect("decodes").demangled;
    let plain = rustre_demangle::demangle("?f@A@@QEAAXXZ").expect("decodes").demangled;
    assert_ne!(restrict, plain, "`QEIAA` and `QEAA` must not render alike");
    assert!(restrict.ends_with("__restrict"), "got {restrict}");

    // And the alignment property the modifiers were skipped for: everything after
    // them must still decode. A dropped or double-consumed modifier shifts the
    // calling convention and return type.
    assert!(
        restrict.contains("__cdecl") && restrict.contains("void"),
        "fields after the modifiers decoded wrong: {restrict}"
    );
}

/// Member function pointers (iter 93): the largest remaining capability gap.
///
/// `P8<class>@<this-modifiers><cv><cc><return><params>@Z`. `parse_msvc_pointer`
/// handled `P6` (a plain function pointer) but not `P8`, so the `8` was read as a cv
/// byte and the whole symbol declined. Member function pointers are ordinary in real
/// C++, and a decline is honest — so unlike iters 90-92 this is **added capability
/// rather than a fabrication fix**.
///
/// Six shapes validated against `msvc-demangler`, covering the parts that could each
/// go wrong independently: a nested class in the pointee (`A::B::*`), a `const`
/// member, non-void returns and parameters, and the plain `P6` form as a control
/// that the new branch did not capture it.
///
/// ### One thing deliberately NOT claimed as validated
///
/// The cv-qualified sigils render as `A::* const` for `Q8`, `* volatile` for `R8`,
/// following the pattern `parse_msvc_function_pointer` already uses for `Q6`/`R6`.
/// **The oracle has no opinion on any of them** — measured: it rejects `Q6AXXZ` and
/// `R6AXXZ` as well as `Q8`. So that rendering was already unvalidated before this
/// change and remains so; extending the existing pattern is consistent, not
/// verified. Recorded rather than asserted, because a test comparing it to nothing
/// would just be my expectation dressed as a check.
#[test]
fn member_function_pointers_match_the_oracle() {
    let cases = [
        ("?f@@YAXP8A@@EAAXXZ@Z", "void (void) member"),
        ("?f@@YAXP8A@@EAAHH@Z@Z", "int (int) member"),
        ("?f@@YAXP8A@@EBAXXZ@Z", "const member"),
        ("?f@@YAXP8B@A@@EAAXXZ@Z", "nested class A::B"),
        ("?f@@YAXP8A@@EAAPEAHPEAD@Z@Z", "pointer return and parameter"),
        ("?f@@YAXP6AXXZ@Z", "plain function pointer, unchanged"),
    ];

    let mut checked = 0;
    for (sym, what) in cases {
        let want = oracle(sym, DemangleFlags::COMPLETE)
            .unwrap_or_else(|_| panic!("{sym} [{what}] must be valid MSVC"));
        let got = rustre_demangle::demangle(sym).map(|r| r.demangled);
        assert_eq!(
            got.as_deref().map(normalise),
            Some(normalise(&want)),
            "{what}: {sym}\n  oracle: {want}\n  ours:   {got:?}"
        );
        checked += 1;
    }
    assert!(checked == 6, "expected 6 cases, checked {checked}");

    // The discriminating pair: `P6` and `P8` differ by one byte and must render
    // differently — a member pointer names its class, a plain one does not.
    let member = rustre_demangle::demangle("?f@@YAXP8A@@EAAXXZ@Z")
        .expect("decodes")
        .demangled;
    let plain = rustre_demangle::demangle("?f@@YAXP6AXXZ@Z")
        .expect("decodes")
        .demangled;
    assert_ne!(member, plain);
    assert!(member.contains("A::*"), "member pointer must name its class: {member}");
    assert!(!plain.contains("::*"), "plain pointer must not: {plain}");
}

/// The cv-qualified function-pointer sigils have no ground truth, in either form.
///
/// Pinned as a *measurement*, not a correctness claim: `msvc-demangler` rejects
/// `Q6`, `R6` and `Q8` alike, so the `* const` / `* volatile` rendering — which
/// predates iter 93 for the `6` forms — is unverified. If a future oracle accepts
/// them, this test fails and the renderings can finally be checked.
#[test]
fn the_cv_qualified_function_pointer_sigils_are_unvalidated() {
    for sym in ["?f@@YAXQ6AXXZ@Z", "?f@@YAXR6AXXZ@Z", "?f@@YAXQ8A@@EAAXXZ@Z"] {
        assert!(
            oracle(sym, DemangleFlags::COMPLETE).is_err(),
            "{sym} now has ground truth — check the `* const`/`* volatile` rendering \
             against it and turn this into a real assertion"
        );
        // Whatever we render, it must not be a marker.
        if let Some(d) = rustre_demangle::demangle(sym).map(|r| r.demangled) {
            assert!(!d.contains("_unknown_"), "{sym} renders a marker: {d}");
        }
    }
}

/// The `$$` type family (iter 94): four of the six remaining declines.
///
/// `$$Q` (rvalue reference) was the only member handled, so the rest declined —
/// honestly, but they are ordinary in templated code and the oracle has ground truth
/// for all of them:
///
/// | encoding | means |
/// |---|---|
/// | `$$T` | `std::nullptr_t` |
/// | `$$A<cc>…@Z` | a function **type**, not a pointer to one |
/// | `$$B<array>` | an array type |
/// | `$$C<cv><type>` | a type carrying cv qualifiers |
///
/// Two things had to be right and neither was obvious:
///
/// * **`$$A` is not the pointer form with the `*` removed.** `undname` puts the
///   calling convention *before* the parameter list here — `void __cdecl (void)` —
///   where the pointer form puts it inside: `void (__cdecl *)(void)`. My first
///   attempt did string surgery on the pointer rendering and produced
///   `void (__cdecl)(void)`.
/// * **`$$C` in template-argument position was unreachable.** That loop handled
///   `$0<number>` by consuming the `$` and then demanding a `0`, so `$$CBH` lost its
///   first `$` and declined. It now peeks at the second byte before committing, which
///   is why the numeric-template control below matters: the change touches the path
///   every `$0` argument takes.
#[test]
fn the_dollar_dollar_type_family_matches_the_oracle() {
    let cases = [
        ("?f@@YAX$$T@Z", "std::nullptr_t"),
        ("?f@@YAX$$A6AXXZ@Z", "bare function type"),
        ("?f@@YAX$$BY0A@H@Z", "array type"),
        ("?f@@YAX$$CAH@Z", "cv wrapper, no qualifier"),
        ("??$h@$$CBH@@YAXXZ", "const in a template argument"),
        ("??$h@$$CCH@@YAXXZ", "volatile in a template argument"),
        ("?f@@YAX$$QEAH@Z", "rvalue reference, unchanged"),
        ("?f@@YAXH@Z", "plain int, unchanged"),
    ];

    let mut checked = 0;
    for (sym, what) in cases {
        let want = oracle(sym, DemangleFlags::COMPLETE)
            .unwrap_or_else(|_| panic!("{sym} [{what}] must be valid MSVC"));
        let got = rustre_demangle::demangle(sym).map(|r| r.demangled);
        assert_eq!(
            got.as_deref().map(normalise),
            Some(normalise(&want)),
            "{what}: {sym}\n  oracle: {want}\n  ours:   {got:?}"
        );
        checked += 1;
    }
    assert!(checked == 8, "expected 8 cases, checked {checked}");

    // `$$A` must NOT render like the pointer form. Asserted directly because the
    // difference is one space and a paren, and a regression would look plausible.
    let bare = rustre_demangle::demangle("?f@@YAX$$A6AXXZ@Z").expect("decodes").demangled;
    let ptr = rustre_demangle::demangle("?f@@YAXP6AXXZ@Z").expect("decodes").demangled;
    assert_ne!(bare, ptr, "a function type and a pointer to one must differ");
    assert!(!bare.contains('*'), "a function TYPE has no pointer: {bare}");
    assert!(ptr.contains('*'), "a function POINTER has one: {ptr}");

    // An unrecognised `$$C` cv byte declines rather than guessing which qualifier
    // was meant.
    assert!(rustre_demangle::demangle("?f@@YAX$$CZH@Z").is_none());
}

/// Numeric template arguments still work after the `$` lookahead change.
///
/// The `$0<number>` branch previously consumed the `$` before checking, and now peeks
/// instead. That is the path every numeric template argument takes, so it is the
/// control for the `$$C` fix above — without it, the change could have silently
/// broken the far commoner form.
#[test]
fn numeric_template_arguments_survive_the_lookahead_change() {
    let mut checked = 0;
    for sym in [
        "??$f@$0A@@@YAXXZ",
        "??$f@$00@@YAXXZ",
        "??$f@$0?0@@YAXXZ",
        "??$f@$0M@@@YAXXZ",
        "??$f@$0BAA@@@YAXXZ",
    ] {
        let Ok(want) = oracle(sym, DemangleFlags::COMPLETE) else {
            continue;
        };
        let got = rustre_demangle::demangle(sym).map(|r| r.demangled);
        assert_eq!(
            got.as_deref().map(normalise),
            Some(normalise(&want)),
            "{sym}\n  oracle: {want}\n  ours:   {got:?}"
        );
        checked += 1;
    }
    assert!(checked >= 4, "vacuous: only {checked} numeric arguments checked");
}

/// vtable cv qualifiers: 7 of 8 combinations were wrong, and the 8th was right by
/// luck (iter 95).
///
/// `??_7<class>@@<marker><cv>@` is a vftable and `??_8…` a vbtable. The `6`/`7` after
/// the class name is the **table-kind marker**; the cv qualifier is the byte *after*
/// it, in the same encoding used everywhere else in this file — `A` none, `B` const,
/// `C` volatile, `D` const volatile.
///
/// `demangle_msvc_special_data` read the *marker* as the cv, mapping `6`->const and
/// `7`->volatile. That produces a **constant answer per table kind**, so it was right
/// for exactly one of four cases in each family:
///
/// ```text
/// ??_7A@@6A@   ours: const A::`vftable'     oracle: A::`vftable'
/// ??_7A@@6B@   ours: const A::`vftable'     oracle: const A::`vftable'      <- agreed
/// ??_7A@@6C@   ours: const A::`vftable'     oracle: volatile A::`vftable'
/// ??_8A@@7B@   ours: volatile A::`vbtable'  oracle: const A::`vbtable'
/// ```
///
/// **`??_7A@@6B@` was the only shape under test**, and it passed because `6`->const
/// and `B`->const happen to agree. A single test vector chosen at the point where two
/// wrong mappings coincide — the sharpest example this session of a green test that
/// could not fail for the reason it claimed.
///
/// The remaining difference is that the oracle appends `{for `'}` to a vbtable, naming
/// the base class the table is for. We omit it: a **missing** element, not a wrong
/// one, and with an empty base name the oracle's own output is `{for `'}` — odd enough
/// that guessing the rule would be inventing. Recorded, not fixed.
#[test]
fn vtable_cv_qualifiers_come_from_the_byte_after_the_marker() {
    let cases = [
        ("??_7A@@6A@", ""),
        ("??_7A@@6B@", "const "),
        ("??_7A@@6C@", "volatile "),
        ("??_7A@@6D@", "const volatile "),
        ("??_8A@@7A@", ""),
        ("??_8A@@7B@", "const "),
        ("??_8A@@7C@", "volatile "),
        ("??_8A@@7D@", "const volatile "),
    ];

    let mut checked = 0;
    for (sym, cv) in cases {
        let want = oracle(sym, DemangleFlags::COMPLETE)
            .unwrap_or_else(|_| panic!("{sym} must be valid MSVC"));
        let got = rustre_demangle::demangle(sym)
            .unwrap_or_else(|| panic!("{sym} must decode"))
            .demangled;

        // The cv prefix is the point of this test, asserted against the oracle's.
        let want_cv = want.starts_with(cv.trim_end()) && !cv.is_empty()
            || cv.is_empty() && !want.starts_with("const") && !want.starts_with("volatile");
        assert!(want_cv, "premise wrong for {sym}: oracle says {want}");
        assert!(
            got.starts_with(cv),
            "{sym}: expected cv {cv:?}\n  oracle: {want}\n  ours:   {got}"
        );
        // And the qualifier must not be over-applied.
        if cv.is_empty() {
            assert!(
                !got.starts_with("const") && !got.starts_with("volatile"),
                "{sym} invented a qualifier: {got}"
            );
        }
        checked += 1;
    }
    assert!(checked == 8, "expected 8 combinations, checked {checked}");

    // Discriminating within each family: the four cv bytes must give four different
    // renderings. Under the old code all four collapsed to one.
    let vft: Vec<String> = ["6A@", "6B@", "6C@", "6D@"]
        .iter()
        .map(|t| {
            rustre_demangle::demangle(&format!("??_7A@@{t}"))
                .expect("decodes")
                .demangled
        })
        .collect();
    let mut uniq = vft.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(uniq.len(), 4, "the four cv bytes must render distinctly: {vft:?}");

    // And the table KIND must still be distinguished — the marker is consumed, not
    // ignored.
    let a = rustre_demangle::demangle("??_7A@@6B@").expect("decodes").demangled;
    let b = rustre_demangle::demangle("??_8A@@7B@").expect("decodes").demangled;
    assert!(a.contains("vftable") && b.contains("vbtable"), "{a} / {b}");
}

/// All 24 access/storage letters, not the six that happened to be tested (iter 96).
///
/// The access char encodes access *and* storage: `A`..`X`, in three groups of eight
/// (private/protected/public), and within each group four pairs
/// (normal/static/virtual/**thunk**). Iter 90 tested six of the twenty-four. The other
/// eighteen were fine; **all six thunk letters — `G`, `H`, `O`, `P`, `W`, `X` — were
/// wrong, and wrong identically.**
///
/// A thunk carries a vtable displacement immediately after the access char.
/// `parse_msvc_qualifiers` did not consume it, so every following field decoded from
/// the wrong byte:
///
/// ```text
/// ?f@A@@GA@AEXXZ
///   oracle: [thunk]: private: virtual void __thiscall A::f(void)
///   ours:   private: virtual void& __cdecl A::f(void)
/// ```
///
/// Three errors from one unconsumed field: the `[thunk]: ` prefix missing, a
/// **fabricated `&`** on the return type, and `__cdecl` for `__thiscall`. The
/// access/storage arithmetic itself (`idx / 8`, `(idx % 8) / 2`) was correct
/// throughout — the mapping was never the problem.
///
/// This is iter 95's lesson applied a second time and paying out a second time: **a
/// table with N inputs needs N vectors.** The vtable cv table had 4 inputs and 1
/// vector; this one had 24 and 6.
#[test]
fn all_twenty_four_access_letters_match_the_oracle() {
    // Several spellings per letter, since static members take no cv byte and thunks
    // take a displacement. The first one the oracle accepts is the test vector.
    let spellings = |a: char| {
        [
            format!("?f@A@@{a}EAAXXZ"),
            format!("?f@A@@{a}AXXZ"),
            format!("?f@A@@{a}EBAXXZ"),
            format!("?f@A@@{a}BAXXZ"),
            format!("?f@A@@{a}EAAAXXZ"),
            format!("?f@A@@{a}A@AEXXZ"),
            format!("?f@A@@{a}EAA@AEXXZ"),
        ]
    };

    let mut compared = 0;
    let mut without_truth = Vec::new();

    for ch in b'A'..=b'X' {
        let a = ch as char;
        let mut found = false;
        for sym in spellings(a) {
            let Ok(want) = oracle(&sym, DemangleFlags::COMPLETE) else {
                continue;
            };
            found = true;
            let got = rustre_demangle::demangle(&sym).map(|r| r.demangled);
            assert_eq!(
                got.as_deref().map(normalise),
                Some(normalise(&want)),
                "access letter {a}: {sym}\n  oracle: {want}\n  ours:   {got:?}"
            );
            compared += 1;
            break;
        }
        if !found {
            without_truth.push(a);
        }
    }

    assert!(
        without_truth.is_empty(),
        "no ground truth found for {without_truth:?} — widen the spelling set rather \
         than leaving those letters unchecked, which is how the thunks hid"
    );
    assert_eq!(compared, 24, "expected all 24 letters, compared {compared}");
}

/// The thunk letters specifically, and what each part of the fix contributes.
///
/// Separate from the sweep so a regression says *which* of the three errors returned.
#[test]
fn thunk_access_letters_consume_their_displacement() {
    let mut checked = 0;
    for a in ['G', 'H', 'O', 'P', 'W', 'X'] {
        let sym = format!("?f@A@@{a}A@AEXXZ");
        let got = rustre_demangle::demangle(&sym)
            .unwrap_or_else(|| panic!("{sym} must decode"))
            .demangled;

        assert!(got.starts_with("[thunk]: "), "missing thunk prefix: {got}");
        // The fabricated `&` came from reading the displacement as part of the
        // return type.
        assert!(!got.contains("void&"), "fabricated reference return: {got}");
        // And the calling convention must be read from the right byte.
        assert!(got.contains("__thiscall"), "wrong calling convention: {got}");
        assert!(got.contains("virtual"), "a thunk is virtual: {got}");
        checked += 1;
    }
    assert!(checked == 6, "expected 6 thunk letters, checked {checked}");

    // Control: the non-thunk letter in the same group must NOT gain the prefix, so
    // the displacement is consumed only where it exists.
    for a in ['E', 'F', 'M', 'N', 'U', 'V'] {
        let sym = format!("?f@A@@{a}EAAXXZ");
        if let Some(d) = rustre_demangle::demangle(&sym).map(|r| r.demangled) {
            assert!(
                !d.starts_with("[thunk]"),
                "{sym} is virtual but not a thunk: {d}"
            );
        }
    }
}

/// The whole operator/special-name table, not the codes that happened to be tested
/// (iter 97).
///
/// Third application of iter 95's rule — **a table with N inputs needs N vectors** —
/// and the biggest payout. The table has ~66 codes with oracle ground truth (`??0`…
/// `??Z`, `??_0`…`??_Z`). Spot-checks at iters 90-91 had caught `_D`, `_U` and `_V`.
/// Sweeping all of them: **47 of 66 agreed, and 15 of the 19 disagreements were the
/// same fabrication repeated** — `operator_unknown_<code>` for every special name from
/// `??_A` to `??_Y` that nobody had written a vector for:
///
/// ```text
/// ??_HA@@QEAAXXZ
///   oracle: public: void __cdecl A::`vector constructor iterator'(void)
///   ours:   public: void __cdecl A::operator_unknown_H(void)
/// ```
///
/// Fifteen entries added, strings taken verbatim from `msvc-demangler` rather than
/// invented: `` `typeof' ``, `` `string' ``, `` `vector deleting destructor' ``,
/// `` `default constructor closure' ``, `` `scalar deleting destructor' ``, the three
/// vector iterators, `` `virtual displacement map' ``, the three eh-vector iterators,
/// `` `copy constructor closure' ``, `` `local vftable' `` and its constructor closure,
/// and the two placement-delete closures.
///
/// Also removed a spurious `operator` prefix from `??_7`/`??_8`/`??_9`: those are
/// compiler-generated table names, so `` A::`vcall'(void) `` and not
/// `` A::operator`vcall'(void) ``.
///
/// **47 -> 63 of 66.** The three that remain are shapes MSVC does not emit — a
/// vftable with a function signature — and the oracle's own output for one of them is
/// malformed (`` `vbtable'{for `(void) ``), so there is nothing to match.
/// `??B` (conversion operator) renders `operator conversion` where the oracle names
/// the target type; a real gap, recorded not fixed, because the target type is not
/// available at that point in the parse.
#[test]
fn the_whole_operator_table_matches_the_oracle() {
    let codes: Vec<String> = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        .chars()
        .map(|c| c.to_string())
        .chain("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().map(|c| format!("_{c}")))
        .collect();

    // Several signatures per code, since arity differs; the first the oracle accepts
    // is the vector.
    let spellings = |code: &str| {
        [
            format!("??{code}A@@QEAAXXZ"),
            format!("??{code}A@@QEAAHH@Z"),
            format!("??{code}A@@QEAAXH@Z"),
            format!("??{code}A@@SAPEAX_K@Z"),
            format!("??{code}A@@QEAA@XZ"),
            format!("??{code}A@@YAXXZ"),
        ]
    };

    let (mut compared, mut identical) = (0, 0);
    let mut fabrications: Vec<String> = Vec::new();
    let mut divergences: Vec<String> = Vec::new();

    for code in &codes {
        for sym in spellings(code) {
            let Ok(want) = oracle(&sym, DemangleFlags::COMPLETE) else {
                continue;
            };
            compared += 1;
            match rustre_demangle::demangle(&sym).map(|r| r.demangled) {
                Some(g) if normalise(&g) == normalise(&want) => identical += 1,
                Some(g) => {
                    if g.contains("_unknown_") {
                        fabrications.push(format!("??{code}: {g}"));
                    }
                    divergences.push(format!("??{code}\n  oracle: {want}\n  ours:   {g}"));
                }
                None => divergences.push(format!("??{code} declined; oracle: {want}")),
            }
            break;
        }
    }

    assert!(compared >= 60, "vacuous: only {compared} codes had ground truth");
    // The point of the iteration: not one code may render the marker.
    assert!(
        fabrications.is_empty(),
        "{} operator codes still fabricate: {:#?}",
        fabrications.len(),
        fabrications
    );
    assert!(
        identical >= 63,
        "operator table agreement regressed: {identical} of {compared} (was 63)\n{:#?}",
        &divergences[..divergences.len().min(5)]
    );
}

/// The fifteen added special names, asserted individually.
///
/// The sweep above would pass if a future change replaced them all with one wrong
/// string that happened to normalise equal; this pins each one, and names the code in
/// the failure message so a regression is one grep away.
#[test]
fn each_added_special_name_is_correct() {
    let expected = [
        ('A', "`typeof'"),
        ('C', "`string'"),
        ('E', "`vector deleting destructor'"),
        ('F', "`default constructor closure'"),
        ('G', "`scalar deleting destructor'"),
        ('H', "`vector constructor iterator'"),
        ('I', "`vector destructor iterator'"),
        ('J', "`vector vbase constructor iterator'"),
        ('K', "`virtual displacement map'"),
        ('L', "`eh vector constructor iterator'"),
        ('M', "`eh vector destructor iterator'"),
        ('N', "`eh vector vbase constructor iterator'"),
        ('O', "`copy constructor closure'"),
        ('S', "`local vftable'"),
        ('T', "`local vftable constructor closure'"),
        ('X', "`placement delete closure'"),
        ('Y', "`placement delete[] closure'"),
    ];

    let mut checked = 0;
    for (code, name) in expected {
        let sym = format!("??_{code}A@@QEAAXXZ");
        let got = rustre_demangle::demangle(&sym)
            .unwrap_or_else(|| panic!("??_{code} must decode"))
            .demangled;
        assert!(
            got.contains(name),
            "??_{code} must render {name:?}, got {got}"
        );
        assert!(!got.contains("_unknown_"), "??_{code} fabricates: {got}");
        checked += 1;
    }
    assert!(checked == 17, "expected 17 names, checked {checked}");

    // And the three table names must NOT carry an `operator` prefix.
    for (code, name) in [('7', "`vftable'"), ('8', "`vbtable'"), ('9', "`vcall'")] {
        let sym = format!("??_{code}A@@QEAAHH@Z");
        if let Some(d) = rustre_demangle::demangle(&sym).map(|r| r.demangled) {
            assert!(
                !d.contains(&format!("operator{name}")),
                "??_{code} keeps a spurious `operator` prefix: {d}"
            );
        }
    }
}

/// String literals (iter 99): `??_C@_<width><length><checksum>@<payload>@`.
///
/// `_0` is narrow, `_1` wide. Both `undname` and `msvc-demangler` render the whole
/// thing as `` `string' `` — they do **not** decode the payload — so that is the answer
/// here, and no part of the content is interpreted.
///
/// Previously declined. The iter-97 table sweep added `??_C` to the special-name
/// table, which was not enough: a string literal has its own shape (width marker,
/// length, checksum, encoded payload) rather than a class name and function tail, so
/// it never reached that path. **A table entry is not a parser** — worth noting,
/// because the entry made the code *look* handled.
///
/// The structure is validated rather than prefix-matched: without requiring the
/// `@`-delimited checksum and a payload closed by `@`, this would claim `??_C@`
/// followed by anything, which is the over-claiming shape the crate's CLAUDE.md
/// records for `_R`/`_T`/`_D`.
///
/// ### One deliberate permissiveness, measured
///
/// The oracle also validates the **declared length against the payload**: it rejects
/// `??_C@_1M@KDLDKPCK@?$AAh?$AAi?$AA?$AA@`, where the hex length `M@` does not match
/// the encoded bytes. We accept it. Checking that would mean decoding the payload
/// escapes to count bytes — inferring a rule rather than reading one — and the
/// consequence is mild: the output is `` `string' ``, which is what a string literal
/// renders as anyway. Recorded so the difference is known rather than discovered.
///
/// My first wide-form example used a hex length and the oracle rejected it, which
/// briefly looked like `_1` being unsupported. Real wide literals use a single-digit
/// length (`_13`, `_15`, `_11`) and all match. **The malformed input was mine.**
#[test]
fn msvc_string_literals_render_as_string() {
    let cases = [
        ("??_C@_02DPKJ@ab?$AA@", "narrow, 2 bytes"),
        ("??_C@_05KAAA@hello?$AA@", "narrow, 5 bytes"),
        ("??_C@_00A@?$AA@", "narrow, empty"),
        ("??_C@_0BA@ABCDEFGH@abcdefghijklmno?$AA@", "narrow, hex length"),
        ("??_C@_13KDLDKPCK@?$AAh?$AAi?$AA?$AA@", "wide, 3 bytes"),
        ("??_C@_15GANGMFKL@?$AAa?$AAb?$AAc?$AA?$AA@", "wide, 5 bytes"),
        ("??_C@_11LOCGONAA@?$AA?$AA@", "wide, empty"),
    ];

    let mut checked = 0;
    for (sym, what) in cases {
        let want = oracle(sym, DemangleFlags::COMPLETE)
            .unwrap_or_else(|_| panic!("{sym} [{what}] must be valid MSVC"));
        assert_eq!(want, "`string'", "premise: the oracle renders these uniformly");
        assert_eq!(
            rustre_demangle::demangle(sym).map(|r| r.demangled).as_deref(),
            Some("`string'"),
            "{what}: {sym}"
        );
        checked += 1;
    }
    assert!(checked == 7, "expected 7 literals, checked {checked}");
}

/// The shape must be validated, or `??_C@` would claim anything after it.
#[test]
fn a_malformed_string_literal_declines() {
    let mut checked = 0;
    for sym in [
        "??_C@",              // nothing at all
        "??_C@_",             // no width marker
        "??_C@_2AB@ab?$AA@",  // width marker is neither 0 nor 1
        "??_C@_0",            // no length
        "??_C@_02@ab?$AA@",   // empty checksum
        "??_C@_02DPKJ@ab",    // payload not closed
        "??_C@_02DP-J@ab?$AA@", // non-alphanumeric checksum
    ] {
        let got = rustre_demangle::demangle(sym).map(|r| r.demangled);
        assert!(
            got.is_none(),
            "{sym} is malformed and must decline, got {got:?}"
        );
        checked += 1;
    }
    assert!(checked == 7, "expected 7 malformed inputs, checked {checked}");
}

/// Every `??_<code>` special name in every real shape, not just the function one
/// (iter 100).
///
/// Iter 97 swept the operator *table* and added fifteen entries. Iter 99 found that a
/// table entry is not a parser. This closes the loop: **the entries only worked in
/// function shape.** In data shape they declined, because
/// `demangle_msvc_special_data` had its own hardcoded four (`_7`, `_8`, `_E`, `_G`)
/// and never consulted the table:
///
/// ```text
/// ??_HA@@QEAAXXZ   ours: A::`vector constructor iterator'(void)   correct
/// ??_HA@@8         ours: None                oracle: A::`vector constructor iterator'
/// ??_HA@@6B@       ours: None                oracle: const A::`…iterator'
/// ```
///
/// Measured: of 120 shapes with ground truth, **38 differed** — every one a
/// data-shaped special name. One rule, two copies, only one complete: the crate's
/// recurring shape, and the third time this session that consolidating two mappings
/// closed a batch of gaps at once.
///
/// Fixed by extracting `msvc_underscore_special_name` and having **both** paths use
/// it, with `is_data` decided from what follows the class name (a `6`/`7`/`8` table
/// marker) rather than from the code. That is what lets one table serve both shapes.
/// **120 of 120 now.**
#[test]
fn special_names_work_in_data_shape_as_well_as_function_shape() {
    let codes = "ACDEFGHIJKLMNOSTUVXY";
    let shapes = |c: char| {
        [
            format!("??_{c}A@@QEAAXXZ"),  // member function
            format!("??_{c}A@@8"),        // data, no cv
            format!("??_{c}A@@6B@"),      // data, const
            format!("??_{c}A@@3HA"),      // data with storage class
            format!("??_{c}A@@UEAAPEAXI@Z"), // virtual member function
            format!("??_{c}A@@YAXXZ"),    // free function
        ]
    };

    let (mut compared, mut identical) = (0, 0);
    let mut divergences: Vec<String> = Vec::new();
    for c in codes.chars() {
        for sym in shapes(c) {
            let Ok(want) = oracle(&sym, DemangleFlags::COMPLETE) else {
                continue;
            };
            compared += 1;
            match rustre_demangle::demangle(&sym).map(|r| r.demangled) {
                Some(g) if normalise(&g) == normalise(&want) => identical += 1,
                other => divergences.push(format!("{sym}\n  oracle: {want}\n  ours:   {other:?}")),
            }
        }
    }

    assert!(compared >= 110, "vacuous: only {compared} shapes had ground truth");
    assert_eq!(
        identical, compared,
        "{} of {compared} shapes disagree:\n{:#?}",
        compared - identical,
        &divergences[..divergences.len().min(6)]
    );
}

/// The two paths must agree on the label for the same code.
///
/// The defect above existed because two places mapped `??_<code>` to a name and only
/// one had the full table. This asserts they now give the same label, so a future
/// edit to one cannot silently diverge — which is how the gap opened in the first
/// place.
#[test]
fn both_msvc_paths_give_the_same_special_name() {
    let mut checked = 0;
    for c in "ACDEFGHIJKLMNOSTUVXY".chars() {
        let as_function = rustre_demangle::demangle(&format!("??_{c}A@@QEAAXXZ"))
            .map(|r| r.demangled);
        let as_data = rustre_demangle::demangle(&format!("??_{c}A@@8")).map(|r| r.demangled);

        // Both must decode, and the data form's label must appear in the function
        // form's rendering — the function form adds access, return type and params.
        let (Some(f), Some(d)) = (as_function, as_data) else {
            panic!("??_{c} must decode in both shapes");
        };
        let label = d.rsplit("::").next().unwrap_or(&d);
        assert!(
            f.contains(label),
            "??_{c}: function shape {f:?} does not carry the data shape's label {label:?}"
        );
        checked += 1;
    }
    assert!(checked == 20, "expected 20 codes, checked {checked}");
}

/// The recent fixes, tested NESTED rather than at the top of a parameter list
/// (iter 101).
///
/// Iters 92-99 each fixed something and tested it in one position: a parameter at the
/// top level of a signature. This sweeps the same constructs *inside* other
/// constructs — `$$C` under a pointer, a member function pointer as a template
/// argument, `nullptr_t` behind a pointer, `__restrict` on a template class member, a
/// thunk with a non-zero displacement, a vftable of a template class.
///
/// **12 of 14 composed correctly**, which is the useful headline: the fixes were not
/// position-dependent hacks. One real defect fell out.
///
/// ### The defect: a function pointer is a declarator, not a type
///
/// `PEAP8A@@EAAXXZ` is a pointer to a member-function pointer. `undname` weaves the
/// outer `*` in beside the inner one; appending it gives something that is not valid
/// C++ and reads as a pointer to the whole function type:
///
/// ```text
/// oracle: void (__cdecl A::* *)(void)
/// ours:   void (__cdecl A::*)(void)*
/// ```
///
/// `parse_msvc_pointer_to_array` already weaves for exactly this reason. This is the
/// function-pointer half of the same rule, and it was invisible until the member
/// pointer from iter 93 was placed *under* another pointer.
///
/// The one remaining divergence is unrelated to these fixes: a local scope renders the
/// enclosing function by name where the oracle renders its full signature. Left alone
/// — the test symbol is artificial (the oracle reads `??_HA@@QEAAXXZ` inside a scope as
/// a function *named* `_HA`, not as a special name), so it is a poor basis for
/// changing local-scope rendering.
#[test]
fn recent_fixes_compose_when_nested() {
    let cases: &[(&str, &str)] = &[
        ("?f@@YAXPEA$$CBH@Z", "$$C under a pointer"),
        ("?f@@YAXQEA$$CBH@Z", "$$C under a const pointer"),
        ("?f@@YAXP6AX$$CBH@Z@Z", "$$C as a fn-ptr parameter"),
        ("??$g@PEA$$CBH@@YAXXZ", "$$C under a pointer, in a template arg"),
        ("?f@@YAXPEAP8A@@EAAXXZ@Z", "pointer to member fn pointer"),
        ("??$g@P8A@@EAAXXZ@@YAXXZ", "member fn pointer as template arg"),
        ("?f@@YAXP6AXP8A@@EAAXXZ@Z@Z", "member fn ptr as fn-ptr parameter"),
        ("?f@@YAXPEA$$T@Z", "pointer to nullptr_t"),
        ("??$g@$$T@@YAXXZ", "nullptr_t as template arg"),
        ("?f@?$A@H@@QEIBAXXZ", "__restrict on a template class member"),
        ("?f@A@@GBA@AEXXZ", "thunk, displacement 16"),
        ("?f@A@@G7AEXXZ", "thunk, displacement 6"),
        ("??_7?$A@H@@6B@", "vftable of a template class"),
    ];

    let mut checked = 0;
    for (sym, what) in cases {
        let want = oracle(sym, DemangleFlags::COMPLETE)
            .unwrap_or_else(|_| panic!("{sym} [{what}] must be valid MSVC"));
        let got = rustre_demangle::demangle(sym).map(|r| r.demangled);
        assert_eq!(
            got.as_deref().map(normalise),
            Some(normalise(&want)),
            "{what}: {sym}\n  oracle: {want}\n  ours:   {got:?}"
        );
        checked += 1;
    }
    assert!(checked == 13, "expected 13 nested cases, checked {checked}");
}

/// A pointer to a function pointer must weave, not append.
///
/// Separate from the sweep so the declarator rule is pinned on its own, with the
/// unnested forms as controls: appending is correct for an ordinary pointee and wrong
/// only when the pointee is a declarator.
#[test]
fn a_pointer_to_a_function_pointer_weaves_the_star() {
    // Nested: the outer `*` belongs inside the parens.
    let nested = rustre_demangle::demangle("?f@@YAXPEAP8A@@EAAXXZ@Z")
        .expect("decodes")
        .demangled;
    assert!(
        nested.contains("A::* *)"),
        "outer pointer must weave in beside the member pointer: {nested}"
    );
    assert!(
        !nested.contains(")*"),
        "the star must not be appended after the parameter list: {nested}"
    );

    // Control: a pointer to an ordinary type still appends.
    let plain = rustre_demangle::demangle("?f@@YAXPEAPEAH@Z")
        .expect("decodes")
        .demangled;
    assert!(plain.contains("int**"), "ordinary pointees append: {plain}");

    // Control: the unnested member pointer is unchanged.
    let single = rustre_demangle::demangle("?f@@YAXP8A@@EAAXXZ@Z")
        .expect("decodes")
        .demangled;
    assert!(
        single.contains("A::*)") && !single.contains("A::* *)"),
        "one level must not gain a second star: {single}"
    );
}
