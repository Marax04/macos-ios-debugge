//! Differential testing against `cpp_demangle` over the REAL symbol corpus.
//!
//! `differential.rs` compares against a hand-curated symbol list. That list is
//! chosen by us, so it cannot surface a construct we never thought to include.
//! This suite instead runs every Itanium symbol that real compilers actually
//! emitted into the 12 corpus binaries — g++ template instantiations, libstdc++
//! internals, thunks — against the reference implementation.
//!
//! Symbols the reference itself rejects are skipped: for those there is no
//! ground truth to compare against.

/// Reference output for `sym`, or `None` if `cpp_demangle` declines it.
fn reference(sym: &str) -> Option<String> {
    let parsed = cpp_demangle::BorrowedSymbol::new(sym.as_bytes()).ok()?;
    parsed
        .demangle(&cpp_demangle::DemangleOptions::default())
        .ok()
}

/// `cpp_demangle` renders RTTI/vtable entities as `{vtable(T)}` while the
/// crate uses the `c++filt` wording; normalise so the comparison is about
/// demangling rather than presentation. Mirrors `differential.rs`.
fn normalise(raw: &str) -> String {
    let s = raw.trim();
    if let Some(body) = s.strip_prefix('{').and_then(|t| t.strip_suffix('}'))
        && let Some(open) = body.find('(')
        && body.ends_with(')')
    {
        let label = match body[..open].trim() {
            "vtable" => Some("vtable for"),
            "vtt" | "VTT" => Some("VTT for"),
            "typeinfo" => Some("typeinfo for"),
            "typeinfo name" => Some("typeinfo name for"),
            "construction vtable" => Some("construction vtable for"),
            _ => None,
        };
        if let Some(lbl) = label {
            return format!("{lbl} {}", &body[open + 1..body.len() - 1]);
        }
    }
    raw.to_owned()
}

/// Itanium symbols from the corpus, excluding legacy-Rust `_ZN…17h…` names —
/// those are Rust's, and `rustc-demangle` is their oracle, not `cpp_demangle`.
fn itanium_symbols() -> Vec<String> {
    include_str!("data/real_symbols.txt")
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("_Z") || l.starts_with("__Z"))
        .filter(|l| !is_legacy_rust(l))
        .map(str::to_owned)
        .collect()
}

/// Legacy Rust mangling reuses the Itanium `_ZN` prefix and ends with a
/// `17h<16 hex digits>E` hash component.
fn is_legacy_rust(s: &str) -> bool {
    s.strip_suffix('E')
        .and_then(|t| t.rfind("17h").map(|i| &t[i + 3..]))
        .is_some_and(|hash| hash.len() == 16 && hash.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Symbols where the crate deliberately diverges because the *reference* is
/// wrong. Verified against `c++filt`, which agrees with this crate on all
/// three.
///
/// Keeping them as an explicit allowlist rather than relaxing the assertion
/// means a new divergence still fails the suite, and each entry has to carry
/// its justification.
const REFERENCE_IS_WRONG: &[(&str, &str)] = &[
    (
        "_ZNK10__cxxabiv120__si_class_type_info11__do_upcastEPKNS_17__class_type_infoEPKvRNS1_15__upcast_resultE",
        "cpp_demangle misplaces the reference qualifier inside the nested name, \
         emitting `__class_type_info&::__upcast_result`; the `&` belongs to the \
         parameter type, as `__class_type_info::__upcast_result&`.",
    ),
    (
        "_ZNSsC1IPKcEET_S2_RKSaIcE",
        "cpp_demangle drops the `S2_` parameter, yielding a 2-argument ctor. The \
         symbol has three: `(char const*, char const*, allocator const&)`. See \
         `repair_ss_ctor_dropped_param` and tests/repair_ss_ctor.rs.",
    ),
    (
        "_ZNSsC2IPKcEET_S2_RKSaIcE",
        "Same dropped-`S2_` reference bug as the C1 variant above.",
    ),
];

#[test]
fn real_itanium_symbols_match_the_reference() {
    let syms = itanium_symbols();
    assert!(
        syms.len() > 500,
        "corpus should hold hundreds of Itanium symbols, found {}",
        syms.len()
    );

    let mut compared = 0usize;
    let mut skipped = 0usize;
    let mut mismatches: Vec<(String, String, String)> = Vec::new();

    for s in &syms {
        let Some(expected) = reference(s) else {
            skipped += 1;
            continue;
        };
        let Some(got) = rustre_demangle::demangle(s) else {
            mismatches.push((s.clone(), normalise(&expected), "<declined>".to_owned()));
            continue;
        };
        compared += 1;
        let (expected, got) = (normalise(&expected), got.demangled);
        if expected != got {
            mismatches.push((s.clone(), expected, got));
        }
    }

    println!("real-corpus Itanium: {compared} compared, {skipped} skipped (reference declined)");

    // Coverage guard: the oracle currently accepts every real Itanium symbol in
    // the corpus (measured `skipped == 0`, 2026-07-23), so this differential
    // checks the whole set rather than a subset. Without this bound the suite
    // could pass while silently skipping most symbols — if `cpp_demangle`
    // regressed or a corpus regeneration introduced a class it rejects, the
    // gap would be invisible, exactly the unchecked-skip hole the MSVC synthetic
    // corpus turned out to have. Allow a small margin for future oddities.
    assert!(
        skipped * 20 <= compared,
        "the oracle skipped {skipped} of {} Itanium symbols — over 5%; the \
         differential is no longer checking the bulk of the corpus",
        compared + skipped
    );

    let (known, unexpected): (Vec<_>, Vec<_>) = mismatches
        .into_iter()
        .partition(|(sym, ..)| REFERENCE_IS_WRONG.iter().any(|(k, _)| k == sym));

    assert!(
        unexpected.is_empty(),
        "{} of {compared} real Itanium symbols diverge from the reference \
         without a documented reason; first 10: {:#?}",
        unexpected.len(),
        &unexpected[..unexpected.len().min(10)]
    );

    // Each allowlisted entry must still actually diverge. If the reference is
    // fixed upstream, or the crate regresses to reproducing its bug, the entry
    // becomes a lie and has to be revisited rather than quietly ignored.
    assert_eq!(
        known.len(),
        REFERENCE_IS_WRONG.len(),
        "allowlisted reference bugs that no longer diverge: {:#?}",
        REFERENCE_IS_WRONG
            .iter()
            .map(|(s, _)| *s)
            .filter(|s| !known.iter().any(|(k, ..)| k == s))
            .collect::<Vec<_>>()
    );
}
