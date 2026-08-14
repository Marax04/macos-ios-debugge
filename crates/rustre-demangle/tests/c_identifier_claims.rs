//! No ABI may claim a plain C identifier and invent structure for it.
//!
//! Two detectors have already been caught doing this: Go claimed any dotted
//! name (so `__pformat_int.isra.0` became a closure) and Rust claimed any `_R`
//! prefix (so the MSVC CRT's `_RTC_Initialize` was reported as Rust). The
//! `lang_extra`/`lang_more` backends add roughly a dozen more detectors on the
//! same path, several keyed on conventions a C name can satisfy by accident —
//! GNAT Ada is `pkg__subprogram`, and mingw is full of `__mingw_vfprintf`.
//!
//! A bare C identifier has no mangling. Decoding it can only mean a detector
//! matched on a coincidence.

use std::collections::BTreeMap;

fn corpora() -> Vec<&'static str> {
    include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

/// A bare C identifier: `[A-Za-z_][A-Za-z0-9_]*`, carrying no mangling sigil.
fn is_plain_c_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    let head_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    head_ok && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Names a C identifier may legitimately take that ARE mangled schemes.
///
/// These schemes encode into what still looks like an identifier, so they are
/// excluded rather than treated as false positives.
fn has_a_real_mangling(s: &str) -> bool {
    // Itanium/legacy-Rust (`_Z`, `__Z`), Rust v0 (`_R` + path tag), D (`_D`),
    // legacy Swift, JNI (`Java_pkg_Class_method`).
    //
    // Swift is NOT excluded on a bare `_T`: that was an assumption, and it was
    // wrong. `_TIFFOpen` is a plain C name, and excluding every `_T…` here hid
    // the very false positive this suite exists to find — the classifier was
    // filing it as an unhandled Swift symbol. Legacy Swift entities carry an
    // entity code and a length prefix, so require both.
    s.starts_with("_Z")
        || s.starts_with("__Z")
        || s.starts_with("Java_")
        // D, like Swift, is not excluded on the bare sigil: `_DllMainCRTStartup`
        // is a C name. The D ABI length-prefixes its `QualifiedName`, so a
        // digit must follow `_D`.
        || s.strip_prefix("_D")
            .and_then(|r| r.chars().next())
            .is_some_and(|c| c.is_ascii_digit())
        || s.strip_prefix("__T")
            .or_else(|| s.strip_prefix("_T"))
            .is_some_and(|r| {
                r.chars()
                    .next()
                    .is_some_and(|c| c == '0' || c == 't' || c.is_ascii_uppercase())
                    && r.chars().any(|c| c.is_ascii_digit())
            })
        || s.strip_prefix("_R")
            .and_then(|r| r.chars().next())
            .is_some_and(|c| matches!(c, 'N' | 'I' | 'C' | 'M' | 'X' | 'Y' | 'K' | 'B'))
}

#[test]
fn no_abi_claims_a_bare_c_identifier() {
    let mut by_abi: BTreeMap<String, Vec<(&str, String)>> = BTreeMap::new();
    let mut candidates = 0usize;

    for s in corpora() {
        if !is_plain_c_identifier(s) || has_a_real_mangling(s) {
            continue;
        }
        candidates += 1;
        if let Some(r) = rustre_demangle::demangle(s) {
            by_abi
                .entry(format!("{:?}", r.abi))
                .or_default()
                .push((s, r.demangled));
        }
    }

    println!("{candidates} bare C identifiers in the corpora");
    for (abi, items) in &by_abi {
        println!("  {:>4}  claimed as {abi}", items.len());
        for (sym, dem) in items.iter().take(5) {
            println!("        {sym} -> {dem}");
        }
    }

    // The guard: without candidates the test proves nothing.
    assert!(
        candidates > 300,
        "only {candidates} bare C identifiers found — the corpora changed shape"
    );

    let total: usize = by_abi.values().map(Vec::len).sum();
    assert_eq!(
        total, 0,
        "{total} bare C identifiers were claimed by a demangler; a name with \
         no mangling cannot be demangled, so each is a detector matching on a \
         coincidence"
    );
}
