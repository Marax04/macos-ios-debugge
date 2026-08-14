//! A symbol reported as a given ABI must actually belong to it.
//!
//! `DemanglingResult::abi` is public and consumers route on it. It is also the
//! one field no differential suite checks: the oracles compare rendered
//! strings, so a symbol can demangle perfectly and still be filed under the
//! wrong ABI.
//!
//! The case that motivated this: `RustDemangler` is tried first and calls
//! `rustc_demangle::try_demangle` without consulting its own `detect`. Legacy
//! Rust mangling is Itanium-shaped, so rustc-demangle accepts plain C++
//! symbols too — `_ZN10__cxxabiv119__terminate_handlerE` decoded correctly but
//! was labelled `Rust`.

/// Rust owns a symbol only if it is v0 (`_R` + an RFC 2603 path tag) or legacy
/// (`_ZN…17h<16 hex>E`). Nothing else may carry `ManglingAbi::Rust`.
fn is_really_rust(s: &str) -> bool {
    let v0 = s
        .strip_prefix("_R")
        .and_then(|r| r.chars().next())
        .is_some_and(|c| matches!(c, 'N' | 'I' | 'C' | 'M' | 'X' | 'Y' | 'K' | 'B'));
    let legacy = s.strip_suffix('E').is_some_and(|t| {
        t.rfind("17h")
            .is_some_and(|i| t[i + 3..].len() == 16 && t[i + 3..].chars().all(|c| c.is_ascii_hexdigit()))
    });
    v0 || legacy
}

fn corpora() -> Vec<&'static str> {
    include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

#[test]
fn nothing_is_mislabelled_as_rust() {
    let mut offenders: Vec<(&str, String)> = Vec::new();
    for s in corpora() {
        let Some(r) = rustre_demangle::demangle(s) else {
            continue;
        };
        // Linker wrappers inherit the payload's ABI, so judge the payload
        // rather than the wrapper. Derived from the demangler's own wrapper
        // table rather than a list repeated here: the copy this replaced named
        // only `.refptr.`/`__imp_` and went stale the moment `__emutls_v.` was
        // added to the real one.
        let payload = payload_of(s);
        if r.abi == rustre_demangle::ManglingAbi::Rust && !is_really_rust(payload) {
            offenders.push((s, r.demangled));
        }
    }
    assert!(
        offenders.is_empty(),
        "{} symbols labelled Rust that are not Rust; first 10: {:#?}",
        offenders.len(),
        &offenders[..offenders.len().min(10)]
    );
}

/// Strip any linker-wrapper prefixes, so the payload is judged rather than the
/// wrapper.
///
/// Loops because wrappers nest — `.refptr.__imp_foo` is real, and the
/// demangler itself handles that by recursing.
fn payload_of(mut s: &str) -> &str {
    while let Some((_, inner)) = rustre_demangle::split_linker_wrapper(s) {
        s = inner;
    }
    s
}

/// The same class of error, for the other strict-prefix ABIs.
///
/// Each of these is defined by a sigil the symbol must carry. A backend that
/// claims something outside its own sigil is doing what `RustDemangler` did:
/// producing a plausible string under the wrong label.
#[test]
fn strict_abis_only_claim_their_own_sigil() {
    use rustre_demangle::ManglingAbi;

    let mut offenders: Vec<(&str, String, String)> = Vec::new();
    for s in corpora() {
        let Some(r) = rustre_demangle::demangle(s) else {
            continue;
        };
        let payload = payload_of(s);
        let ok = match r.abi {
            ManglingAbi::Itanium => payload.starts_with("_Z") || payload.starts_with("__Z"),
            ManglingAbi::Msvc => payload.starts_with('?'),
            ManglingAbi::Swift => {
                payload.starts_with("$s") || payload.starts_with("$S") || payload.starts_with("_T")
            }
            ManglingAbi::D => payload.starts_with("_D"),
            // Go and the `lang_extra` ABIs are detected by shape, not by a
            // sigil, so there is no equivalent invariant to assert.
            _ => true,
        };
        if !ok {
            offenders.push((s, format!("{:?}", r.abi), r.demangled));
        }
    }
    assert!(
        offenders.is_empty(),
        "{} symbols carry an ABI whose sigil they lack; first 10: {:#?}",
        offenders.len(),
        &offenders[..offenders.len().min(10)]
    );
}

/// The converse: a genuine Rust symbol must be labelled Rust, so the fix above
/// cannot be satisfied by relabelling everything away from Rust.
#[test]
fn genuine_rust_symbols_are_labelled_rust() {
    let mut wrong: Vec<(&str, String)> = Vec::new();
    for s in corpora().into_iter().filter(|s| is_really_rust(s)) {
        let Some(r) = rustre_demangle::demangle(s) else {
            continue;
        };
        if r.abi != rustre_demangle::ManglingAbi::Rust {
            wrong.push((s, format!("{:?}", r.abi)));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} genuine Rust symbols carry another ABI; first 10: {:#?}",
        wrong.len(),
        &wrong[..wrong.len().min(10)]
    );
}
