//! Agreement between the two directions of the ABI-name canonicaliser.
//!
//! `AbiCanonicalizer` exposes two views of the same fact: `canonicalize` maps a
//! spelling to a canonical name, and `canonical_names` enumerates them. Nothing
//! makes the compiler check that the two agree, and a disagreement is silent —
//! a caller validating against the enumeration rejects a name the canonicaliser
//! itself emits, or accepts one it never produces. The header comment on
//! `canonical_names` records that exactly this had already happened once
//! (`riscv_ilp32d` was missing), which is the reason to pin it.

use rustre_analysis_callconv::abi_analyzer::AbiCanonicalizer;

/// Spellings a caller can realistically hand in: MSVC's own decorated forms,
/// plus the plain names.
const MSVC_SPELLINGS: &[&str] = &[
    "__cdecl",
    "__stdcall",
    "__fastcall",
    "__thiscall",
    "__vectorcall",
];

/// Every canonical name must be a fixed point — canonicalising it again cannot
/// change it, or the operation is not idempotent and callers cannot re-apply it
/// safely.
#[test]
fn every_canonical_name_is_a_fixed_point() {
    for name in AbiCanonicalizer::canonical_names() {
        assert_eq!(
            AbiCanonicalizer::canonicalize(name),
            name,
            "{name} is enumerated as canonical but canonicalises to something else"
        );
    }
}

/// Canonicalising is idempotent for every spelling, not just canonical ones.
#[test]
fn canonicalizing_twice_changes_nothing() {
    let mut probes: Vec<&str> = AbiCanonicalizer::canonical_names();
    probes.extend_from_slice(MSVC_SPELLINGS);
    probes.extend_from_slice(&["winapi", "sysv", "win64", "aarch64", "riscv", "nonsense"]);

    for p in probes {
        let once = AbiCanonicalizer::canonicalize(p);
        let twice = AbiCanonicalizer::canonicalize(once);
        assert_eq!(
            once, twice,
            "{p} canonicalises to {once}, which then changes again to {twice}"
        );
    }
}

/// Canonicalisation must not depend on case: the doc comment states that
/// "STDCALL" yields "stdcall", so the same must hold for every spelling.
#[test]
fn canonicalizing_ignores_case() {
    let mut probes: Vec<&str> = AbiCanonicalizer::canonical_names();
    probes.extend_from_slice(MSVC_SPELLINGS);

    for p in probes {
        let upper = p.to_uppercase();
        assert_eq!(
            AbiCanonicalizer::canonicalize(&upper),
            AbiCanonicalizer::canonicalize(p),
            "{upper} and {p} canonicalise differently"
        );
    }
}

/// The enumeration must have no duplicates: callers use it as a set, and a
/// repeated entry means one of them is dead.
#[test]
fn the_enumeration_has_no_duplicates() {
    let names = AbiCanonicalizer::canonical_names();
    let unique: std::collections::HashSet<_> = names.iter().collect();
    assert_eq!(
        unique.len(),
        names.len(),
        "canonical_names() repeats an entry: {names:?}"
    );
}

/// MSVC's own decorated spellings must all reduce to a canonical name.
///
/// `__vectorcall` is the only spelling MSVC accepts for that convention — the
/// undecorated `vectorcall` never appears in real source or in a demangled
/// symbol — so failing to map it means the convention is recognised in theory
/// (it is enumerated as canonical) and never in practice.
#[test]
fn msvc_decorated_spellings_all_canonicalize() {
    let canonical = AbiCanonicalizer::canonical_names();

    for spelling in MSVC_SPELLINGS {
        let got = AbiCanonicalizer::canonicalize(spelling);
        assert!(
            canonical.contains(&got),
            "{spelling} canonicalises to {got:?}, which is not in canonical_names() \
             {canonical:?} — a caller validating against that list rejects it"
        );
    }
}
