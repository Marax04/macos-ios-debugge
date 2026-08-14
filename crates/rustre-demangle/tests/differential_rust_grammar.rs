//! Rust v0 differential over GRAMMAR-DERIVED inputs, not the corpus.
//!
//! `differential_rust_pdb.rs` checks the 135 real v0 symbols from the PDBs and
//! the live path is exact on all of them. That is a strong result and a narrow
//! one: those symbols exercise whatever productions rustc happened to emit for
//! two programs. The MSVC side already has `differential_msvc_grammar.rs` for
//! the same reason; Rust had no equivalent.
//!
//! So these inputs are written from RFC 2603 — one per production: the type
//! tags, references and pointers, arrays and slices, tuples, function types,
//! const generics, lifetimes, `dyn` bounds, backreferences, closures,
//! disambiguators, and both impl forms.
//!
//! **The oracle arbitrates construction too.** Hand-writing a mangled symbol
//! means hand-counting length prefixes, which has been the single largest
//! source of false findings in this crate's history. So an input that
//! `rustc-demangle` *rejects* is treated as a bug in the test, not a finding —
//! it simply cannot contribute. `oracle_accepts_every_case` pins how many
//! survive that filter, so the suite cannot quietly decay into asserting
//! nothing.
//!
//! Measured 2026-07-30: 34 of 36 constructions are well-formed and the live
//! path agrees with `rustc-demangle` on every one. No defect. The value here is
//! the guard, not a fix.
//!
//! Extended at iter 146 with the COMPLETE const-generic type table (iter 112
//! sampled three of the fifteen) and with backreference edge cases —
//! self-referential, chained, into a path, beside a nested generic. MSVC's
//! argument back-references were wrong for every parameter containing a class
//! (iter 126), so the same machinery deserved the same scrutiny here. 28 of 29
//! agree, 0 differ, the one exception being a binder I could not construct
//! validly.

/// One entry per RFC 2603 production.
const CASES: &[(&str, &str)] = &[
    ("_RNvC1a1f", "value in crate"),
    ("_RNvNtC1a1b1c", "nested type path"),
    ("_RNvNtNtC1a1b1c1d", "twice-nested"),
    ("_RNvXC1aNtC1a1TNtC1a1t1m", "trait impl (X)"),
    ("_RNvMC1aNtC1a1T1m", "inherent impl (M)"),
    ("_RINvC1a1flE", "generic <i32>"),
    ("_RINvC1a1fmE", "generic <u32>"),
    ("_RINvC1a1fbE", "generic <bool>"),
    ("_RINvC1a1fcE", "generic <char>"),
    ("_RINvC1a1feE", "generic <str>"),
    ("_RINvC1a1fuE", "generic <()>"),
    ("_RINvC1a1fllE", "two generics"),
    ("_RINvC1a1fRlE", "generic <&i32>"),
    ("_RINvC1a1fQlE", "generic <&mut i32>"),
    ("_RINvC1a1fPlE", "generic <*const i32>"),
    ("_RINvC1a1fOlE", "generic <*mut i32>"),
    ("_RINvC1a1fAlj4_E", "generic <[i32; 4]>"),
    ("_RINvC1a1fSlE", "generic <[i32]>"),
    ("_RINvC1a1fTllEE", "generic <(i32, i32)>"),
    ("_RINvC1a1fTlmeEE", "generic <(i32, u32, str)>"),
    ("_RINvC1a1fB4_E", "backreference"),
    ("_RINvC1a1fKj1_E", "const generic usize"),
    ("_RINvC1a1fKb0_E", "const generic bool"),
    ("_RINvC1a1fKc61_E", "const generic char"),
    ("_RINvC1a1fFEuE", "fn() -> ()"),
    ("_RINvC1a1fFlEuE", "fn(i32)"),
    ("_RNCNvC1a1fs_0", "closure with disambiguator"),
    ("_RNCNvC1a1f0", "closure"),
    ("_RNvC1as_1f", "path disambiguator"),
    ("_RINvC1a1fDG0_NtC1a1tEL_E", "dyn trait with lifetime"),
    ("_RINvC1a1fL0_E", "lifetime"),
    ("_RNvNtCs1234_1a1b1c", "crate disambiguator"),
    ("_RNvCsCRATE_1a1f", "crate disambiguator, letters"),
    ("_RINvC1a1fINtC1a1bllEE", "nested generic type"),
    // The COMPLETE const-generic type table (iter 146). Iter 112 sampled three
    // of these; a table with N entries needs N vectors — the rule that found
    // the JNI escape defect, and three wrong entries in the MSVC tables.
    ("_RINvC1a1fKh1_E", "const generic u8"),
    ("_RINvC1a1fKt1_E", "const generic u16"),
    ("_RINvC1a1fKm1_E", "const generic u32"),
    ("_RINvC1a1fKy1_E", "const generic u64"),
    ("_RINvC1a1fKo1_E", "const generic u128"),
    ("_RINvC1a1fKa1_E", "const generic i8"),
    ("_RINvC1a1fKs1_E", "const generic i16"),
    ("_RINvC1a1fKl1_E", "const generic i32"),
    ("_RINvC1a1fKx1_E", "const generic i64"),
    ("_RINvC1a1fKn1_E", "const generic i128"),
    ("_RINvC1a1fKi1_E", "const generic isize"),
    ("_RINvC1a1fKb1_E", "const generic bool true"),
    ("_RINvC1a1fKe61_E", "const generic str"),
    ("_RINvC1a1fKln1_E", "const generic negative"),
    ("_RINvC1a1fKpE", "const generic placeholder"),
    // Backreference edge cases. MSVC's argument back-references were wrong for
    // every parameter containing a class (iter 126), so the same machinery is
    // worth exercising here: self-referential, chained, into a path, and into a
    // nested generic.
    ("_RINvC1a1flB4_E", "backref after a type"),
    ("_RINvNtC1a1b1fB2_E", "backref to a path"),
    ("_RINvC1a1flB4_B4_E", "two backrefs to one target"),
    ("_RINvC1a1fB0_E", "self-referential backref"),
    ("_RINvC1a1fINtC1a1blEB4_E", "backref beside a nested generic"),
    ("_RNvYNtC1a1tNtC1a1u1f", "trait definition (Y)"),
    ("_RNvNtNtC1a1b1c1d", "twice-nested value path"),
    // Degenerate but WELL-FORMED, and only the oracle could settle that: an
    // empty generic list, an empty crate name, an empty const, and a
    // backreference as the whole final component. All four were in the
    // malformed list until `oracle(sym).is_none()` refused them — the probe
    // that preceded this suite skipped them silently with a `continue`, which
    // is why the assertion is written as an assertion.
    ("_RINvC1a1fE", "empty generic list"),
    ("_RNvC0_1f", "empty crate name"),
    ("_RINvC1a1fKj_E", "empty const value"),
    ("_RNvC1a1fB_", "trailing backreference"),
    // Known-malformed, kept so the arbitration below is not vacuous.
    ("_RINvC1a1fFlEuEE", "MALFORMED: fn nested in generic"),
    ("_RNvC1auss_1f", "MALFORMED: punycode ident"),
];

/// Malformed shapes: truncation, over-long length prefixes, an out-of-range
/// backreference, an empty generic list, a stray byte. The oracle rejects each.
const MALFORMED: &[&str] = &[
    "_RNvC1auss_1f",
    "_RINvC1a1fFlEuEE",
    "_RNvC1a",
    "_RNvC9a1f",
    "_RNvC1a1",
    "_RINvC1a1f",
    "_RNvC1a1fZZZ",
    "_RNvXC1a",
    "_RINvC1a1fA lE",
    "_RNvC1a1f_",
    "_RNvNtC1a1b",
    "_RINvC1a1fB9999_E",
    "_RINvC1a1fTE",
    "_RNCNvC1a1f",
    "_RINvC1a1fDE",
];

fn oracle(sym: &str) -> Option<String> {
    rustc_demangle::try_demangle(sym)
        .ok()
        .map(|d| format!("{d:#}"))
}

/// Every well-formed construction must decode exactly as the compiler's own
/// demangler does.
#[test]
fn live_path_matches_the_oracle_on_every_production() {
    let mut disagreements: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for (sym, what) in CASES {
        let Some(want) = oracle(sym) else {
            continue; // malformed construction: cannot contribute
        };
        checked += 1;
        match rustre_demangle::demangle(sym) {
            Some(got) if got.demangled == want => {}
            Some(got) => disagreements.push(format!(
                "{sym} ({what})\n     oracle: {want}\n     ours:   {}",
                got.demangled
            )),
            None => disagreements.push(format!(
                "{sym} ({what})\n     oracle: {want}\n     ours:   <declined>"
            )),
        }
    }

    assert!(checked >= 60, "vacuous: only {checked} well-formed cases");
    assert!(
        disagreements.is_empty(),
        "{} productions disagree with rustc-demangle:\n{}",
        disagreements.len(),
        disagreements.join("\n")
    );
}

/// A malformed v0 symbol must DECLINE, never decode into something invented.
///
/// This is the direction where fabrication lives — the crate has been caught
/// inventing on input no oracle contradicts (Go closures, MSVC RTTI, the JNI
/// escape table). Here an oracle does contradict it, so the property is exact.
#[test]
fn malformed_input_declines_rather_than_fabricating() {
    let mut fabrications: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for sym in MALFORMED {
        assert!(
            oracle(sym).is_none(),
            "{sym} is in the malformed list but the oracle accepts it — \
             move it to CASES"
        );
        checked += 1;
        if let Some(got) = rustre_demangle::demangle(sym) {
            fabrications.push(format!("{sym} => {}", got.demangled));
        }
    }

    assert!(checked >= 15, "vacuous: only {checked} malformed inputs");
    assert!(
        fabrications.is_empty(),
        "{} malformed v0 symbols decoded instead of declining:\n{}",
        fabrications.len(),
        fabrications.join("\n")
    );
}

/// Guards the arbitration itself: exactly the two entries marked MALFORMED may
/// fail to parse.
///
/// Without this, a future edit that breaks a length prefix would silently
/// remove that case from the suite above — the "no offenders because it is
/// empty" failure, which looks identical to success from a green test.
#[test]
fn oracle_accepts_every_case_not_marked_malformed() {
    let mut wrong: Vec<String> = Vec::new();
    for (sym, what) in CASES {
        let marked = what.starts_with("MALFORMED");
        match (oracle(sym).is_some(), marked) {
            (false, false) => wrong.push(format!(
                "{sym} ({what}): the oracle rejects it, so the length prefixes \
                 are miscounted — fix the input, do not report a finding"
            )),
            (true, true) => wrong.push(format!(
                "{sym} ({what}): marked MALFORMED but the oracle accepts it"
            )),
            _ => {}
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
