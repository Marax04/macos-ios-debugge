//! MSVC constant-pool symbols are linker artifacts, not names.
//!
//! `__real@3ff0000000000000`, `__xmm@0000…`, `__ymm@…` name a constant by
//! writing its value in hex. There is no identifier to recover — the payload
//! *is* the datum — so the honest classification is `LinkerArtifact`, the
//! bucket this crate already uses for the LLVM equivalent (`$f32.deadbeef`).
//!
//! Two separate defects met here, and the collision search over the real PDB
//! corpus is what surfaced them:
//!
//! 1. `__xmm@0000000000000001…` and `__xmm@0101…` both decoded to `_xmm`.
//!    Two distinct constants, one rendering — and `_xmm` is not a demangling
//!    at all, it is the symbol with its value deleted. The cause was
//!    `detect_c_decorated`, which claims Windows stdcall decorations
//!    (`_MessageBoxA@16`) and accepted *any* run of digits after the `@`. A
//!    constant-pool payload happens to be numeric, so it matched. That is the
//!    same shape as the `_R`/`_T`/`_D` prefix rules this crate removed: a
//!    detector looser than the thing it detects invents symbols.
//!
//! 2. `__real@…` contains hex letters, so it failed that all-digits test and
//!    fell through to `DeclineReason::Unknown` — the variant this crate keeps
//!    **locked at zero**. It escaped the census only because no corpus
//!    contains one.
//!
//! The discriminating property for the first fix is *zero padding*: a stdcall
//! decoration counts argument bytes and is written plainly (`@0`, `@4`, `@16`),
//! never padded. `_foo@0` and `_g@100` must therefore keep working, which is
//! what separates the fix from simply rejecting long digit runs.

use rustre_demangle::decline::{DeclineReason, decline_reason};

const CONSTANT_POOL: &[&str] = &[
    "__xmm@00000000000000010000000000000001",
    "__xmm@01010101010101010101010101010101",
    "__real@3ff0000000000000",
    "__ymm@0000000000000000",
    // The LLVM form, which was already classified correctly.
    "$f32.deadbeef",
];

#[test]
fn constant_pool_symbols_are_linker_artifacts() {
    let mut checked = 0;
    for sym in CONSTANT_POOL {
        assert!(
            rustre_demangle::demangle(sym).is_none(),
            "{sym} has no name to recover and must not decode"
        );
        assert_eq!(
            decline_reason(sym),
            DeclineReason::LinkerArtifact,
            "{sym} must be classified as a linker artifact"
        );
        checked += 1;
    }
    assert!(checked > 4, "vacuous: only {checked} checked");
}

/// Neither `Unknown` nor `UnsupportedAbi` — the two variants this crate keeps
/// at zero — may be reached by a constant-pool symbol.
///
/// `__real@…` used to land in `Unknown`, and only the absence of such a symbol
/// from either corpus kept the census green.
#[test]
fn constant_pool_symbols_never_count_as_defects() {
    for sym in CONSTANT_POOL {
        let reason = decline_reason(sym);
        assert!(
            !reason.is_defect(),
            "{sym} classified as a defect: {reason:?}"
        );
        assert_ne!(reason, DeclineReason::Unknown, "{sym} fell through to Unknown");
    }
}

/// Two constants that differ only in their payload must not collapse into one
/// rendering.
///
/// This is the property the collision sweep tested, stated directly: distinct
/// linker symbols that decode identically are indistinguishable to any
/// consumer. Written so it still holds if these ever *do* decode — what is
/// forbidden is the collision, not the decoding.
#[test]
fn two_constants_do_not_share_a_rendering() {
    let a = rustre_demangle::demangle("__xmm@00000000000000010000000000000001")
        .map(|r| r.demangled);
    let b = rustre_demangle::demangle("__xmm@01010101010101010101010101010101")
        .map(|r| r.demangled);
    assert!(
        a.is_none() || a != b,
        "two different constants share the rendering {a:?}"
    );
}

/// Control: genuine Windows decorations still decode.
///
/// A fix that rejected any `@`-suffixed digit run would satisfy every test
/// above while destroying the detector's actual purpose. `_foo@0` (a single
/// zero, which *is* a valid byte count) and the multi-digit counts are the
/// cases that separate "not zero-padded" from "not long".
#[test]
fn stdcall_and_fastcall_decorations_are_unaffected() {
    for (sym, want) in [
        ("_MessageBoxA@16", "MessageBoxA"),
        ("_foo@0", "foo"),
        ("@bar@8", "bar"),
        ("_f@4", "f"),
        ("_g@100", "g"),
        ("_h@1024", "h"),
    ] {
        assert_eq!(
            rustre_demangle::demangle(sym).map(|r| r.demangled),
            Some((*want).to_owned()),
            "{sym} is a genuine decoration and must still decode"
        );
    }
}

/// No two symbols in either real corpus may decode to the same string within
/// the same ABI — except where the ABI genuinely erases the difference.
///
/// The one legitimate exception is the Itanium **constructor and destructor
/// variants**: `C1`/`C2`/`C3` (complete-object, base-object, allocating) and
/// `D0`/`D1`/`D2` are separate entry points for a single entity, and both
/// `c++filt` and `cpp_demangle` render them identically. Verified against the
/// oracle rather than assumed — `_ZNSsC1ERKSs` and `_ZNSsC2ERKSs` both give
/// `std::string::string(std::string const&)` from `cpp_demangle` too.
///
/// It is expressed as a *normalisation of the mangled input*, not as an
/// ABI-wide skip. The first version of this guard excluded Itanium and Rust
/// wholesale, which exempted the two largest ABIs — roughly 2000 corpus
/// symbols — from the very check that found the Go defect. Narrowing the
/// exception to the thing that actually justifies it restores that coverage:
/// with ctor/dtor variants normalised the whole corpus has **zero**
/// unexplained collisions, Rust included, so the hash-stripping worry that
/// motivated the original exemption turned out not to need one.
#[test]
fn corpus_decodes_do_not_collide_unexpectedly() {
    use std::collections::HashMap;

    let mut by_output: HashMap<String, Vec<String>> = HashMap::new();
    let mut decoded = 0;
    for path in ["tests/data/real_symbols.txt", "tests/data/pdb_symbols.txt"] {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines() {
            let sym = line.trim();
            if sym.is_empty() {
                continue;
            }
            let Some(r) = rustre_demangle::demangle(sym) else {
                continue;
            };
            decoded += 1;
            let abi = format!("{:?}", r.abi);
            by_output
                .entry(format!("{abi}\u{1}{}", r.demangled))
                .or_default()
                .push(sym.to_owned());
        }
    }

    // Two symbols differing only in their ctor/dtor variant tag are the same
    // entity by design; anything else sharing a rendering is information loss.
    let collisions: Vec<_> = by_output
        .iter()
        .filter(|(_, syms)| syms.len() > 1)
        .filter(|(_, syms)| {
            let keys: Vec<String> = syms.iter().map(|s| strip_ctor_dtor_variant(s)).collect();
            !keys.windows(2).all(|w| w[0] == w[1])
        })
        .collect();
    assert!(
        collisions.is_empty(),
        "distinct symbols share a rendering: {collisions:?}"
    );
    assert!(
        decoded > 2000,
        "vacuity guard: only {decoded} decodes examined — did the corpora move?"
    );
}

/// **Fixed.** Kept as the regression guard for the collision this file found.
///
/// Found by the collision sweep above, in Go, the ABI where every
/// fabricated-output defect so far has been found and where no oracle can
/// contradict a wrong answer.
///
/// `runtime.init.6.func1` and `runtime.init.func1` both rendered
/// `runtime.init {closure-1 #1}`. The `.6` — the index distinguishing the
/// sixth package-init function from the unnumbered one — was dropped, so two
/// distinct runtime functions became one in the output.
///
/// This is information loss of the kind `tests/go_completeness.rs` exists to
/// catch, and it slipped past that check because the invariant there is defined
/// over *named* components: `6` is a number, not a name, so nothing required it
/// to reappear. Collision detection sees it because it compares whole symbols
/// against each other rather than each symbol against itself.
///
/// The cause was `parse_function_suffix` filtering *every* numeric component
/// out of the base name, while the depth calculation a few lines below already
/// applied the correct rule: a bare `.N` only means closure nesting once a
/// `funcN` has been seen. Two halves of one function, two different rules for
/// the same input.
#[test]
fn go_init_index_is_not_dropped() {
    let d = |s: &str| rustre_demangle::demangle(s).map(|r| r.demangled);

    // The two symbols that collided, with their correct renderings.
    assert_eq!(
        d("runtime.init.6.func1").as_deref(),
        Some("runtime.init.6 {closure-1 #1}"),
        "the package-init index belongs in the base name"
    );
    assert_eq!(
        d("runtime.init.func1").as_deref(),
        Some("runtime.init {closure-1 #1}"),
        "the unnumbered init must be unchanged"
    );
    assert_ne!(d("runtime.init.6.func1"), d("runtime.init.func1"));

    // The index is kept only *before* a `funcN`. After one it is closure
    // nesting, so it leaves the base NAME — but it is still information and
    // belongs in the closure path.
    //
    // This assertion previously expected `{closure-2 #3}`, dropping the
    // nesting index `1` entirely. That was the same defect this test exists
    // for, one level deeper: only the outermost `funcN` index was recorded, so
    // `main.f.func2.3` and `main.f.func2.5` — two different nested closures —
    // both rendered `{closure-2 #2}`. The whole index path is rendered now.
    assert_eq!(
        d("runtime.traceAdvance.func3.osyield.1").as_deref(),
        Some("runtime.traceAdvance.osyield {closure-2 #3.1}"),
        "a numeric segment after a closure marker is nesting, not a name —          but its value still distinguishes one nested closure from another"
    );

    // And a numeric segment with no closure at all is untouched.
    assert_eq!(d("runtime.init.6").as_deref(), Some("runtime.init.6"));
    assert_eq!(d("runtime.init.0").as_deref(), Some("runtime.init.0"));
}

/// Replace the first Itanium constructor/destructor variant tag with a
/// placeholder, so `…C1E…` and `…C2E…` compare equal.
///
/// Deliberately positional and first-match-only, so it cannot blur two symbols
/// that also differ elsewhere.
fn strip_ctor_dtor_variant(mangled: &str) -> String {
    let b = mangled.as_bytes();
    for i in 0..b.len().saturating_sub(1) {
        let constructor = b[i] == b'C' && matches!(b[i + 1], b'1' | b'2' | b'3');
        let destructor = b[i] == b'D' && matches!(b[i + 1], b'0' | b'1' | b'2');
        if constructor || destructor {
            let mut out = mangled.to_owned();
            out.replace_range(i..i + 2, "@@");
            return out;
        }
    }
    mangled.to_owned()
}

/// The normalisation must not be a blunt instrument.
///
/// If it merged symbols differing beyond the variant tag, the collision guard
/// would fall silent for the wrong reason — the vacuity failure this crate
/// warns about, where "no offenders because it is right" and "no offenders
/// because nothing was compared" look identical from a green test.
#[test]
fn the_variant_normalisation_is_not_over_broad() {
    // Same entity, different variant tag: must collapse.
    assert_eq!(
        strip_ctor_dtor_variant("_ZNSsC1ERKSs"),
        strip_ctor_dtor_variant("_ZNSsC2ERKSs")
    );
    // Different parameters: must stay distinct.
    assert_ne!(
        strip_ctor_dtor_variant("_ZNSsC1ERKSs"),
        strip_ctor_dtor_variant("_ZNSsC1EPKcRKSaIcE")
    );
    // Different class: must stay distinct.
    assert_ne!(
        strip_ctor_dtor_variant("_ZNSsC1ERKSs"),
        strip_ctor_dtor_variant("_ZNSt8bad_castC1ERKSs")
    );
    // No variant tag: returned unchanged.
    assert_eq!(strip_ctor_dtor_variant("_ZN3foo3barEi"), "_ZN3foo3barEi");
}
