//! `DemangleOptions` should change what demangling produces.
//!
//! It currently does not: no function in the crate accepts a
//! `DemangleOptions`, and no field is read outside the tests that assert their
//! own construction. Building one with [`Verbosity::Minimal`] and expecting
//! simplified templates yields output byte-identical to `Full`.
//!
//! The existing coverage in `src/lib_tests.rs` is the kind that cannot detect
//! this: it checks that `with_verbosity(Minimal)` sets `simplify_templates`,
//! which is true of a builder whose result nothing reads.
//!
//! Following the convention of `fidelity_demangle.rs::fidelity_known_gaps`,
//! the assertion below states the behaviour the API promises and is ignored,
//! so the gap is visible via `cargo test -- --ignored` without turning CI red.

use rustre_demangle::{DemangleOptions, Verbosity};

/// A deeply templated symbol, the case `simplify_templates` exists for.
const NESTED: &str = "_ZNSt8_Rb_treeINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEESt4pairIKS5_xESt10_Select1stIS8_ESt4lessIS5_ESaIS8_EE8_M_eraseEPSt13_Rb_tree_nodeIS8_E";

/// The options type is at least self-consistent: each verbosity sets the
/// fields it documents. This part holds today and guards the constructors.
#[test]
fn verbosity_presets_set_their_documented_fields() {
    let minimal = DemangleOptions::with_verbosity(Verbosity::Minimal);
    assert!(minimal.simplify_templates);
    assert!(!minimal.verbose);

    let full = DemangleOptions::with_verbosity(Verbosity::Full);
    assert!(!full.simplify_templates);
    assert!(full.verbose);

    assert_eq!(
        DemangleOptions::default().verbosity,
        Verbosity::Normal,
        "the default must stay Normal: callers rely on it"
    );
}

/// DOCUMENTED GAP: verbosity must change the output.
///
/// `Minimal` is documented as simplifying templates, `Full` as keeping every
/// template argument, so on a symbol carrying eight nested template arguments
/// the two cannot legitimately render the same string.
///
/// Closing this means threading the options through the backends and adding a
/// public entry point that accepts them — a new API surface, so it wants a
/// deliberate decision rather than a drive-by patch. The alternative, if the
/// options are not wanted, is to deprecate the type; leaving it as-is is the
/// only option that misleads.
#[test]
#[ignore = "documents that DemangleOptions is inert; the assertion is the promised behaviour"]
fn minimal_and_full_verbosity_differ() {
    // No entry point accepts options, so the best a caller can do today is
    // build them and call the ordinary function — which is precisely the
    // problem this test records.
    let minimal_opts = DemangleOptions::with_verbosity(Verbosity::Minimal);
    let full_opts = DemangleOptions::with_verbosity(Verbosity::Full);
    assert_ne!(
        minimal_opts.simplify_templates, full_opts.simplify_templates,
        "the presets must at least differ from each other"
    );

    let baseline = rustre_demangle::demangle(NESTED)
        .expect("the nested template symbol must decode")
        .demangled;

    assert!(
        baseline.matches('<').count() > 4,
        "expected a heavily templated rendering to simplify: {baseline}"
    );

    // What the API promises: some way to obtain a simplified rendering. There
    // is none, so this fails by construction until options are honoured.
    let simplified: Option<String> = None;
    assert!(
        simplified.is_some_and(|s| s.matches('<').count() < baseline.matches('<').count()),
        "no entry point accepts DemangleOptions, so `Verbosity::Minimal` \
         cannot affect any output"
    );
}

/// The number this open decision was missing: how many callers exist.
///
/// Every other open decision in the crate CLAUDE.md carries a usage count —
/// `itanium_full` 8 uses, `demangler_dispatcher` 3, `rust_demangler` ~12 — because
/// that count is what makes the decision cheap or expensive. The
/// `DemangleOptions` entry had none, so "implement or deprecate" was being weighed
/// blind.
///
/// Measured 2026-07-30: **0 consumers workspace-wide**, and 0 in this crate's
/// production code. The type is constructed only by tests that assert its own
/// construction. That is decisive in one direction — deprecating breaks nobody —
/// and it also means implementing the options would be new API for no existing
/// caller.
///
/// This test pins the *production* half of that claim, which is the half a test
/// can see: nothing outside `core_types` (the definition) and `lib` (the
/// re-export) mentions the type. It deliberately does **not** try to grep sibling
/// crates — a test reading other crates' sources would be brittle and is not this
/// crate's business — so the workspace figure lives in the CLAUDE.md instead.
///
/// A measurement trap worth keeping: `grep DemangleOptions src/` shows hits in
/// `backends.rs` and `cpp_demangler.rs`. Those are
/// `cpp_demangle::DemangleOptions` — the *dependency's* identically-named type.
/// An inert type can look used.
#[test]
fn no_production_code_consumes_the_options_type() {
    // Files that are allowed to mention the crate's own `DemangleOptions`.
    const ALLOWED: &[&str] = &[
        "core_types.rs", // the definition
        "lib.rs",        // the re-export
        "lib_tests.rs",  // in-crate tests
    ];

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders: Vec<String> = Vec::new();
    let mut scanned = 0;

    let mut stack = vec![dir];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).expect("src must be readable") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_owned();
            let text = std::fs::read_to_string(&path).expect("source must be readable");
            scanned += 1;

            for (i, line) in text.lines().enumerate() {
                if !line.contains("DemangleOptions") {
                    continue;
                }
                // The dependency's identically-named type is not ours.
                if line.contains("cpp_demangle::DemangleOptions") {
                    continue;
                }
                if ALLOWED.contains(&name.as_str()) {
                    continue;
                }
                offenders.push(format!("{name}:{}: {}", i + 1, line.trim()));
            }
        }
    }

    assert!(scanned > 20, "vacuous: only {scanned} source files scanned");
    assert!(
        offenders.is_empty(),
        "DemangleOptions gained a production consumer — the \"implement or \
         deprecate\" decision now has a cost, re-measure the workspace count:\n{offenders:#?}"
    );
}
