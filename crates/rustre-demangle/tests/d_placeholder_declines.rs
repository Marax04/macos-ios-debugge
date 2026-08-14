//! A D symbol the parser could not read must decline, not decode.
//!
//! `d_demangler` writes `?(<code>)` when it meets a type code it does not
//! implement, and a bare `?` when a component ran out of input. Those
//! renderings were reaching callers as **successful decodes**:
//! `_D3fooQeFiZv` — which uses a `Q` back-reference, a D grammar feature this
//! crate does not implement — returned `Some("?(Q) foo")` and `decline_reason`
//! classified it `Decoded`.
//!
//! This is the same defect the Swift backend had (`?module`, see
//! `tests/swift_degenerate_inputs.rs`), and it is worth stating why it matters
//! more than the odd-looking string: this crate's authoritative metric is the
//! *classification*, not the decode count. A fabrication filed as `Decoded`
//! inflates the success total and, worse, hides the missing capability that
//! produced it — `UnsupportedAbi` exists precisely to surface "a recognised
//! sigil that no backend decoded".
//!
//! How it was found is the point of the technique: the broken fixture had been
//! sitting inside `tests/macho_prefix_equivalence.rs`, where the assertion
//! compared the ELF and Mach-O spellings *against each other*. Both produced
//! `?(Q) foo`, so the test passed while both sides agreed on a fabricated
//! answer. An agreement test is only as strong as a fixture that decodes.
//!
//! Note the direction: this **removes** output. The decode count goes down, and
//! by this crate's own history that is a fidelity gain, not a loss.

use rustre_demangle::decline::{DeclineReason, decline_reason};

/// Symbols that reach a placeholder, one per route into it.
const FABRICATING: &[(&str, &str)] = &[
    ("_D3fooQeFiZv", "`Q` back-reference: unimplemented grammar"),
    ("_D4main3fooFQeZv", "`Q` in parameter position"),
    ("_D4main3fooF@Zv", "`@` is not a type code at all"),
    ("_D4main1x@", "`@` as a data symbol's type"),
    ("_D4main3fooFiZ", "truncated: no return type after `Z`"),
];

#[test]
fn placeholder_renderings_are_not_reported_as_decodes() {
    let mut checked = 0;
    for (sym, why) in FABRICATING {
        let got = rustre_demangle::demangle(sym);
        assert!(
            got.is_none(),
            "{sym} ({why}) must decline, but decoded to {:?}",
            got.map(|r| r.demangled)
        );
        assert_ne!(
            decline_reason(sym),
            DeclineReason::Decoded,
            "{sym} must not be counted as a decode"
        );
        checked += 1;
    }
    assert!(checked > 4, "vacuous: only {checked} inputs checked");
}

/// `detect` must not promise what `demangle` will not deliver.
///
/// Tightening `demangle` alone converts a consistent error into a divergence,
/// and `if d.detect(s) { d.demangle(s).unwrap() }` then panics — the mistake
/// that once broke 89 corpus symbols in this crate. Checked on the `DDemangler`
/// wrapper as well as the live path, because this crate has repeatedly shipped
/// two copies of one dispatcher that disagreed.
#[test]
fn detect_and_demangle_stay_in_step() {
    use rustre_demangle::DDemangler;

    // Equality rather than `if detect { assert … }`. This loop *does* run today
    // — measured 5 of 5 — but only because `DDemangler::detect` still claims
    // these shapes. Tightening that detector, as was done for Swift and Go in
    // this crate, would take it to zero without a sound; two other tests went
    // quiet exactly that way. An equality cannot.
    let mut compared = 0usize;
    for (sym, why) in FABRICATING {
        assert_eq!(
            DDemangler::detect(sym),
            DDemangler::demangle(sym).is_some(),
            "detect and demangle disagree on {sym} ({why})"
        );
        compared += 1;
    }
    assert!(compared > 4, "vacuity guard: only {compared} inputs compared");

    // Positive control: a well-formed D symbol must be claimed *and* decoded,
    // so the equality above cannot be satisfied by a detector that rejects
    // everything — the regression a conditional assertion is blind to.
    assert!(DDemangler::detect("_D4main3fooFiZi"));
    assert!(DDemangler::demangle("_D4main3fooFiZi").is_some());
}

/// Control: everything that legitimately decodes still does.
///
/// Without this a "fix" that declined all D symbols would satisfy every
/// assertion above. The list deliberately includes each shape corrected in this
/// crate's D work — function pointer, `noreturn`, the runtime special symbols —
/// so a placeholder rule that over-reached would be caught here rather than by
/// a consumer.
#[test]
fn well_formed_d_symbols_still_decode() {
    for (sym, want) in [
        ("_D4main3fooFiZi", "int main.foo(int)"),
        (
            "_D3std5stdio7writelnFAyaZv",
            "void std.stdio.writeln(immutable(char)[])",
        ),
        ("_D4main1xi", "int main.x"),
        ("_D4main12__ModuleInfoZ", "main.__ModuleInfo"),
        ("_D4main3fooFPFiZvZv", "void main.foo(void function(int))"),
        ("_D4main3fooFZNn", "noreturn main.foo()"),
        ("_D4main3fooFiYv", "void main.foo(int, ...)"),
    ] {
        let got = rustre_demangle::demangle(sym)
            .unwrap_or_else(|| panic!("{sym} must still decode"))
            .demangled;
        assert_eq!(got, want, "{sym}");
        assert!(!got.contains('?'), "no placeholder in a good decode: {got}");
    }
}

/// No decode from either real corpus may carry a placeholder.
///
/// The corpora contain no D symbols at all, so this cannot regress today — it
/// is here so that adding a D corpus (the step that would unblock the `Q`
/// back-reference work) immediately reports any fabrication it introduces,
/// rather than silently raising the decode count.
#[test]
fn no_corpus_decode_carries_a_placeholder() {
    let mut checked = 0;
    for path in [
        "tests/data/real_symbols.txt",
        "tests/data/pdb_symbols.txt",
    ] {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines() {
            let sym = line.trim();
            if sym.is_empty() {
                continue;
            }
            if let Some(r) = rustre_demangle::demangle(sym) {
                assert!(
                    !r.demangled.contains("?("),
                    "corpus symbol {sym} decoded to a fabrication: {}",
                    r.demangled
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked > 2000,
        "vacuity guard: only {checked} corpus decodes examined — did the data files move?"
    );
}
