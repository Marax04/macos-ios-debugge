//! Differential testing of the MSVC demangler against the `msvc-demangler`
//! reference crate (the same engine used by `symbolic`/Sentry, modelled on
//! LLVM's `undname`).
//!
//! Until now MSVC was the only ABI without an external oracle: it was guarded
//! solely by `msvc_public_paths_agree`, which checks that our two public
//! parsers agree with *each other* — a check that cannot detect a mistake both
//! copies share. Both historical MSVC bugs (the `this`-modifier byte
//! misalignment and the lost data-symbol types) were exactly that kind of
//! shared-blind-spot error.
//!
//! Symbols the reference itself rejects are skipped (no ground truth), and an
//! acceptance guard asserts the corpus stays overwhelmingly accepted so the
//! suite cannot silently become vacuous.

mod msvc_oracle;
use msvc_oracle::{compare, normalise, reference};

/// MSVC symbols spanning free functions, member functions with access
/// specifiers and cv-qualifiers, ctors/dtors, operators, data symbols,
/// templates and vftables.
const MSVC_CORPUS: &[&str] = &[
    // Free functions.
    "?foo@@YAHH@Z",
    "?value@@YAHXZ",
    "?print@@YAXPEBD@Z",
    "?calc@@YANNN@Z",
    "?mix@@YAXHNPEAD@Z",
    // Member functions, access specifiers, cv-qualifiers.
    "?foo@bar@@QEAAHXZ",
    "?func@MyClass@@QEAAHH@Z",
    "?name@Person@@QEBAPEBDXZ",
    "?bar@Foo@ns@@QEAAXXZ",
    "?GetValue@Widget@ns@@QEBAHXZ",
    "?update@Engine@@IEAAXN@Z",
    "?reset@State@@AEAAXXZ",
    // Static / virtual members.
    "?instance@Singleton@@SAPEAV1@XZ",
    "?draw@Shape@@UEAAXXZ",
    // Constructors / destructors.
    "??0Foo@@QEAA@XZ",
    "??0Point@@QEAA@HH@Z",
    "??1Foo@@QEAA@XZ",
    // Operators.
    "??2@YAPEAX_K@Z",
    "??3@YAXPEAX@Z",
    "??HFoo@@QEAA?AV0@AEBV0@@Z",
    "??8Foo@@QEBA_NAEBV0@@Z",
    // Data symbols.
    "?x@@3HA",
    "?counter@@3JA",
    "?g_name@@3PEBDEB",
    "?value@Config@@2HA",
    // Templates: function templates and class templates in types.
    "??$max@H@@YAHHH@Z",
    "??$min@N@@YANNN@Z",
    "?push_back@?$vector@H@std@@QEAAXH@Z",
    "?size@?$vector@N@std@@QEBA_KXZ",
    // Non-type (integer) template arguments: `$0<encoded>`.
    "?get@?$array@H$09@std@@QEAAHXZ",
    "?get@?$array@H$0L@@std@@QEAAHXZ",
    "?get@?$array@H$0BAA@@std@@QEAAHXZ",
    "?f@?$A@$0?4@@QEAAHXZ",
    // NOTE: `$1<symbol>` (address-of) template arguments are NOT here: the
    // reference itself rejects them, so there is no ground truth to compare
    // against (verified 2026-07-21).
    // Vftables / RTTI.
    "??_7Foo@@6B@",
    "??_7Widget@ns@@6B@",
    // Function-local statics: `?<name>@?<N>?<enclosing symbol>@<storage><type>`.
    // Real CRT symbols from the corpus Rust binaries. Checked here against the
    // oracle as well as in tests/msvc_local_scope.rs, because that suite
    // asserts a hand-derived string and only the reference can confirm the
    // derivation — including that the scope index renders as `N+1`.
    "?_OptionsStorage@?1??__local_stdio_printf_options@@9@4_KA",
    "?_OptionsStorage@?1??__local_stdio_scanf_options@@9@4_KA",
];

#[test]
fn differential_msvc_matches_reference() {
    let mut mismatches = Vec::new();
    let mut compared = 0usize;
    let mut skipped = 0usize;

    for sym in MSVC_CORPUS {
        let Some(reference) = reference(sym) else {
            skipped += 1;
            continue;
        };
        compared += 1;
        match rustre_demangle::demangle(sym) {
            Some(ours) if normalise(&ours.demangled) == normalise(&reference) => {}
            Some(ours) => mismatches.push(format!(
                "  {sym}\n    reference: {reference}\n    ours:      {}",
                ours.demangled
            )),
            None => mismatches.push(format!(
                "  {sym}\n    reference: {reference}\n    ours:      <None>"
            )),
        }
    }

    println!("msvc differential: {compared} compared, {skipped} skipped (reference rejects)");
    assert!(
        mismatches.is_empty(),
        "{} of {compared} MSVC symbols differ from msvc-demangler:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

/// Anti-vacuity guard: if the corpus (or a future edit to it) contained
/// symbols the reference rejects, those cases would be silently skipped and
/// the differential test could pass while comparing nothing. Require that the
/// reference accepts at least 95% of the corpus.
#[test]
fn corpus_is_accepted_by_the_reference() {
    let accepted = MSVC_CORPUS.iter().filter(|s| reference(s).is_some()).count();
    println!("reference acceptance: {accepted}/{}", MSVC_CORPUS.len());
    // Integer form of `accepted / len >= 0.95`, avoiding float casts.
    assert!(
        accepted * 100 >= MSVC_CORPUS.len() * 95,
        "only {accepted}/{} corpus symbols accepted by msvc-demangler — the differential suite is going vacuous",
        MSVC_CORPUS.len()
    );
}

/// The oracle's one-shot [`compare`] must reach the same verdict as the
/// explicit `reference`/`normalise` comparison above.
///
/// Running it here also keeps every item of the shared oracle module exercised
/// by this target and not only by the generative suite, which is what the
/// module's former blanket `dead_code` exemption was standing in for.
#[test]
fn shared_compare_helper_agrees_on_the_fixed_corpus() {
    let failures: Vec<String> = MSVC_CORPUS.iter().filter_map(|s| compare(s).err()).collect();
    assert!(
        failures.is_empty(),
        "{} of {} corpus symbols diverge from the reference via `compare`:\n{}",
        failures.len(),
        MSVC_CORPUS.len(),
        failures.join("\n")
    );
}
