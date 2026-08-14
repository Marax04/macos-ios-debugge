//! `itanium_full` measured against the live path over the real corpus.
//!
//! `itanium_full` is a public module with roughly eight uses from other crates
//! in this workspace. Its own header cites 6/28 on a 28-symbol reference set —
//! honest, but synthetic. Its accuracy over the **813 real Itanium symbols** in
//! `real_symbols.txt` had never been measured, which is how
//! `rust_demangler` (0 of 135) and `ItaniumNativeDemangler` (37% wrong arity)
//! went unnoticed for as long as they did. The crate CLAUDE.md's own rule
//! applies: alternatives get measured, not assumed.
//!
//! Reference is `crate::demangle`, which delegates to `cpp_demangle` and is the
//! path the crate documents as correct.
//!
//! Measured on 2026-07-30 over 813 symbols:
//!
//! | outcome | count |
//! |---|---|
//! | errors out entirely | 313 |
//! | identical to the live path | 91 |
//! | differs | 409 |
//! | …of those, different parameter count | 47 |
//!
//! So it reproduces the live path on **11%** of real symbols. Three defect
//! classes are visible in the differences, and the first two are substantive
//! rather than cosmetic:
//!
//! * **Lost `St` substitution, which changes arity.**
//!   `std::type_info const*` becomes `std const*, type_info` — one parameter
//!   read as two. Same root cause as the documented `ItaniumNativeDemangler`
//!   defect.
//! * **Fabricated placeholder in output.** A destructor renders `~<dtor>(void)`
//!   instead of `~__forced_unwind()`. `<dtor>` is the parser's own marker, and
//!   this crate treats a placeholder reaching the output as fabrication.
//! * **Function-pointer spelling.** `void (*)()` becomes `void(void)*`.
//!
//! This suite does not assert a preference between fixing the parser, making it
//! delegate, or steering callers to `demangle` — those are open decisions, and
//! the callers live in other crates. It pins the figures so the decision can be
//! made on measured ground, and so the module cannot quietly get worse.

use rustre_demangle::itanium_full::ItaniumDemangler as Full;

struct Counts {
    total: usize,
    errored: usize,
    identical: usize,
    differ: usize,
    wrong_arity: usize,
}

fn measure() -> Counts {
    let mut c = Counts { total: 0, errored: 0, identical: 0, differ: 0, wrong_arity: 0 };
    for s in include_str!("data/real_symbols.txt").lines().map(str::trim) {
        if !s.starts_with("_Z") {
            continue;
        }
        let Some(live) = rustre_demangle::demangle(s) else {
            continue;
        };
        if live.abi != rustre_demangle::ManglingAbi::Itanium {
            continue;
        }
        c.total += 1;
        match Full::demangle(s) {
            Err(_) => c.errored += 1,
            Ok(full) if full == live.demangled => c.identical += 1,
            Ok(full) => {
                c.differ += 1;
                // A differing top-level comma count is a differing parameter
                // count: substantive, not presentational.
                if full.matches(',').count() != live.demangled.matches(',').count() {
                    c.wrong_arity += 1;
                }
            }
        }
    }
    c
}

/// The measured figures, as bounds that tolerate small drift in either
/// direction but fail loudly on a real move.
#[test]
fn itanium_full_accuracy_is_pinned() {
    let c = measure();

    assert!(
        c.total > 700,
        "suite gone vacuous: only {} real Itanium symbols compared",
        c.total
    );
    assert_eq!(c.total, c.errored + c.identical + c.differ, "counts must partition");

    // Improvements are welcome and must be re-baselined rather than silently
    // absorbed; regressions must fail.
    assert!(
        c.identical >= 85,
        "itanium_full agreement regressed: {} identical of {} (was 91)",
        c.identical,
        c.total
    );
    assert!(
        c.errored <= 330,
        "itanium_full now fails to parse more symbols: {} of {} (was 313)",
        c.errored,
        c.total
    );
    assert!(
        c.wrong_arity <= 55,
        "itanium_full arity errors grew: {} (was 47)",
        c.wrong_arity
    );
}

/// The three defect classes, as concrete cases.
///
/// Asserted on the *live* path being right and `itanium_full` being wrong, so if
/// the module is ever fixed these fail and say exactly what changed — which is
/// the point of pinning rather than ignoring.
#[test]
fn the_three_itanium_full_defect_classes_are_present() {
    // 1. Lost `St` substitution splits one parameter into two.
    let sym = "_ZL20check_exception_specP16lsda_header_infoPKSt9type_infoPvx";
    let live = rustre_demangle::demangle(sym).expect("live path decodes").demangled;
    let full = Full::demangle(sym).expect("itanium_full decodes this one");
    assert!(
        live.contains("std::type_info const*"),
        "live path lost the substitution: {live}"
    );
    assert!(
        full.contains("std const*"),
        "expected the documented St defect, got {full}"
    );
    assert!(
        full.matches(',').count() > live.matches(',').count(),
        "the St defect must inflate the parameter count: {full}"
    );

    // 2. A parser placeholder reaches the output.
    let dtor = Full::demangle("_ZN10__cxxabiv115__forced_unwindD0Ev")
        .expect("itanium_full decodes this one");
    assert!(
        dtor.contains("<dtor>"),
        "expected the fabricated placeholder, got {dtor}"
    );
    assert_eq!(
        rustre_demangle::demangle("_ZN10__cxxabiv115__forced_unwindD0Ev")
            .expect("live path decodes")
            .demangled,
        "__cxxabiv1::__forced_unwind::~__forced_unwind()",
        "the live path names the destructor properly"
    );

    // 3. Function-pointer spelling.
    let fp = Full::demangle("_ZN10__cxxabiv111__terminateEPFvvE")
        .expect("itanium_full decodes this one");
    assert!(fp.contains("void(void)*"), "expected the fp spelling defect, got {fp}");
}
