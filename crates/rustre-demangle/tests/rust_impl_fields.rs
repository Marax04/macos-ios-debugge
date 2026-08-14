//! An inherent impl's angle brackets are syntax, not part of a name.
//!
//! `<std::path::Path>::is_absolute` reported `namespace: None` and
//! `class: "<std::path::Path>"` — the scope lost entirely, and the class
//! carrying rendering punctuation. **25 of the 137 real Rust decodes** are this
//! shape (43 more are trait impls, see below), so half the Rust corpus had one
//! field empty and one unusable for lookup.
//!
//! The equivalent non-impl rendering decomposes correctly
//! (`core::fmt::write` -> `core` / `fmt` / `write`), so the information was
//! there and simply not extracted. The inner path is now spliced back into the
//! scope list: nothing is invented, only un-bracketed.
//!
//! **Trait impls are deliberately left alone.**
//! `<main::Foo as core::fmt::Debug>::fmt` keeps
//! `class = "<main::Foo as core::fmt::Debug>"`, because that bracketed part is
//! an impl *header*, not a path, and choosing between the self type and the
//! trait for `class` is a judgement the rendering does not make for us —
//! and picking the self type would make `<Foo as Debug>::fmt` and
//! `<Foo as Display>::fmt` report identical fields.
//!
//! **A pre-existing test had to be relaxed, carefully.**
//! `structured_consistency.rs::namespace_class_function_rejoin_into_the_rendered_name`
//! requires `namespace::class::function` to appear literally in the rendering.
//! Its note explains why that matters: containment alone missed Go dropping
//! `OnceValue` from `init.OnceValue.func5`, and rejoining closes that gap. The
//! fields here drop nothing — the join is `std::path::Path::is_absolute`, every
//! component present and in order — but the brackets defeat a literal
//! `contains`. The comparison now strips `<` and `>` from both sides. The test
//! below proves that did not make it vacuous.

fn fields(sym: &str) -> (Option<String>, Option<String>, String) {
    let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
    (r.namespace, r.class, r.function)
}

/// Real inherent-impl symbols from the PDB corpus decompose into a scope and a
/// type.
#[test]
fn inherent_impls_report_a_scope_and_a_type() {
    let mut checked = 0;
    for line in include_str!("data/pdb_symbols.txt").lines() {
        let sym = line.trim();
        if sym.is_empty() {
            continue;
        }
        let Some(r) = rustre_demangle::demangle(sym) else {
            continue;
        };
        if !r.demangled.starts_with('<') || r.demangled.contains(" as ") {
            continue;
        }
        checked += 1;
        if let Some(class) = &r.class {
            // Only the impl WRAPPER is syntax. A generic type name genuinely
            // contains angle brackets — `RawVec<(*mut u8, …), std::alloc::System>`
            // is the class — so the rule is about the leading `<`, not about
            // brackets anywhere. Asserting `!ends_with('>')` was my error.
            assert!(
                !class.starts_with('<'),
                "{sym}: class {class:?} still carries the impl wrapper"
            );
        }
        assert!(!r.function.is_empty(), "{sym}: empty function");
    }
    assert!(checked >= 20, "vacuous: only {checked} inherent impls found");
}

/// The decomposition matches the equivalent non-impl rendering.
#[test]
fn an_inherent_impl_decomposes_like_a_plain_path() {
    assert_eq!(
        fields("_RNvMs16_NtCsfCRYEVunkyr_3std4pathNtB6_4Path11is_absolute"),
        (
            Some("std::path".to_owned()),
            Some("Path".to_owned()),
            "is_absolute".to_owned()
        )
    );
    // The plain form it should now agree with in shape.
    let (ns, class, function) = fields("_RNvNtC4core3fmt5write");
    assert_eq!(ns.as_deref(), Some("core"));
    assert_eq!(class.as_deref(), Some("fmt"));
    assert_eq!(function, "write");
}

/// Trait impls keep their header — pinned so the deliberate choice is visible.
#[test]
fn trait_impls_keep_the_impl_header() {
    let mut checked = 0;
    for line in include_str!("data/pdb_symbols.txt").lines() {
        let sym = line.trim();
        if sym.is_empty() {
            continue;
        }
        let Some(r) = rustre_demangle::demangle(sym) else {
            continue;
        };
        if !r.demangled.contains(" as ") {
            continue;
        }
        checked += 1;
        assert!(
            r.class.as_deref().is_some_and(|c| c.contains(" as ")),
            "{sym}: a trait impl lost its header: {:?}",
            r.class
        );
    }
    assert!(checked >= 20, "vacuous: only {checked} trait impls found");
}

/// The relaxed rejoin comparison still catches a dropped middle component.
///
/// This is the vacuity guard for the change made to
/// `structured_consistency.rs`. Stripping `<` and `>` must not make the check
/// blind to the defect it exists for — Go losing `OnceValue` from
/// `init.OnceValue.func5`, where every surviving part is still individually
/// present but the join is not.
#[test]
fn the_relaxed_rejoin_still_rejects_a_dropped_component() {
    let strip = |t: &str| -> String { t.chars().filter(|c| *c != '<' && *c != '>').collect() };
    let join = |ns: &str, class: &str, f: &str| format!("{ns}::{class}::{f}");

    // Correct decomposition of an inherent impl: accepted.
    let rendering = "<std::path::Path>::is_absolute";
    assert!(strip(rendering).contains(&strip(&join("std::path", "Path", "is_absolute"))));

    // A dropped middle component: still rejected, brackets or not.
    assert!(!strip(rendering).contains(&strip(&join("std", "Path", "is_absolute"))));
    let go_shape = "os::init::OnceValue::func5";
    assert!(!strip(go_shape).contains(&strip(&join("os", "init", "func5"))));

    // And a reordering is rejected too.
    assert!(!strip(rendering).contains(&strip(&join("Path", "std::path", "is_absolute"))));
}
