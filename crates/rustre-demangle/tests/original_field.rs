//! `DemanglingResult::original` must be the input, byte for byte.
//!
//! Callers use it as the key to map a result back to the symbol they asked
//! about — a symbol table lookup, a cache, a report keyed by mangled name. A
//! backend that stored an inner or normalised form instead would hand back a
//! key that matches nothing.
//!
//! Three dispatch paths rewrite it deliberately (`.refptr.`/`__imp_`
//! unwrapping, GCC clone suffixes, Mach-O prefix normalisation) because they
//! recurse on a *substring* and must restore the caller's spelling afterwards.
//! Those are exactly the places where it could silently be left wrong.

fn corpora() -> Vec<&'static str> {
    include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

#[test]
fn original_is_always_the_input() {
    let syms = corpora();
    let mut checked = 0usize;
    let mut offenders: Vec<(&str, String)> = Vec::new();

    for s in &syms {
        let Some(r) = rustre_demangle::demangle(s) else {
            continue;
        };
        checked += 1;
        if r.original != *s {
            offenders.push((s, r.original));
        }
    }

    println!("{checked} decoded symbols checked");
    assert!(
        checked > 2000,
        "only {checked} symbols decoded — suite gone vacuous"
    );
    assert!(
        offenders.is_empty(),
        "{} results carry an `original` that is not the input; first 10: {:#?}",
        offenders.len(),
        &offenders[..offenders.len().min(10)]
    );
}

/// The rewriting paths specifically: each recurses on a substring, so each is
/// a place the caller's spelling could be lost.
#[test]
fn rewriting_paths_restore_the_callers_spelling() {
    for s in [
        ".refptr._ZNSt10bad_typeidD1Ev",       // linker wrapper
        "__imp__ZNSt10bad_typeidD1Ev",         // PE import thunk
        "_ZN12_GLOBAL__N_14pool4freeEPv.constprop.0", // GCC clone suffix
        "__RNvCs4SDFJOLwvtW_7___rustc10rust_panic",   // Mach-O Rust v0
        "__D4main3fooFZv",                     // Mach-O D
        "_$s4main3fooyyF",                     // Mach-O Swift
    ] {
        let r = rustre_demangle::demangle(s).unwrap_or_else(|| panic!("{s} must decode"));
        assert_eq!(
            r.original, s,
            "{s} came back with a different `original`"
        );
    }
}
