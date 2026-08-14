//! MSVC renderings must not invent names.
//!
//! Go has had this guard since iter 64: every identifier-like token in the output must
//! occur in the input, except the renderer's own vocabulary. **MSVC did not** — and
//! MSVC is where iters 90-101 found 23 fabrications, so it is the ABI most in need of
//! it.
//!
//! The `tests/no_placeholder_leaks.rs` guard catches markers (`_unknown_`, `?SPECIAL`),
//! but not every fabrication is a marker: iter 90's worst case rendered
//! `x12345678::f::operator[]::f(void)`, and the invented `operator[]` would have passed
//! a marker check while failing this one.
//!
//! ### What it found
//!
//! Five codes still fabricated: `??_B`, `??_P`, `??_Q`, `??_W`, `??_Z` rendered
//! `operator_unknown_<code>`. Iter 97's table sweep had listed them as "no ground
//! truth" — `msvc-demangler` rejects every spelling tried — and I left them alone. That
//! was wrong: **an oracle with no opinion does not license emitting a marker.** They now
//! decline, which is this crate's standing answer for a construct it cannot read.
//!
//! The bare `??<code>` fallback had the same shape and is fixed with it.

use std::collections::BTreeSet;

/// Words the renderer contributes itself, by category. Derived from measurement rather
/// than guessed, and grouped so each addition has to justify itself against a category
/// — a long allowlist is what makes an anti-invention guard toothless.
const VOCABULARY: &[&str] = &[
    // Type names the renderer spells out.
    "void", "int", "long", "unsigned", "short", "char", "bool", "float", "double",
    "nullptr_t", "std", "__int128", "wchar_t", "char16_t", "char32_t",
    // Calling conventions.
    "__cdecl", "__thiscall", "__stdcall", "__fastcall", "__vectorcall", "__clrcall",
    "__pascal",
    // Access, storage and qualifiers.
    "public", "protected", "private", "static", "virtual", "const", "volatile",
    "__restrict", "__unaligned", "thunk",
    // Special-name words (iters 90-100), each from a table entry.
    "operator", "new", "delete", "vftable", "vbtable", "vcall", "typeof", "string",
    "vbase", "destructor", "constructor", "closure", "default", "copy", "scalar",
    "deleting", "vector", "iterator", "displacement", "eh", "local", "placement",
    "dynamic", "initializer", "atexit", "map",
    // RTTI descriptor words.
    "RTTI", "Type", "Descriptor", "Base", "Class", "Array", "Complete", "Object",
    "Hierarchy", "Locator", "at",
    // Rendered structure.
    "anonymous", "namespace", "class", "struct", "union", "enum", "conversion",
];

/// Numbers are not names: RTTI descriptors render numeric fields (`(0,-1,0,64)`) that
/// do not appear in the mangling as digits.
fn is_number(tok: &str) -> bool {
    tok.bytes().all(|b| b.is_ascii_digit())
}

fn msvc_symbols() -> Vec<String> {
    let mut v: Vec<String> = include_str!("data/pdb_symbols.txt")
        .lines()
        .map(str::trim)
        .filter(|s| s.starts_with('?'))
        .map(str::to_owned)
        .collect();
    // The grammar-derived surface where the fabrications actually lived.
    for c in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars() {
        v.push(format!("??{c}A@@QEAAXXZ"));
        v.push(format!("??_{c}A@@QEAAXXZ"));
        v.push(format!("??_{c}A@@8"));
    }
    for p in [
        "PEA", "P6A", "P8A@@EAA", "PEAP8A@@EAA", "$$CB", "$$T", "QEA", "AEA",
    ] {
        v.push(format!("?f@@YAX{p}H@Z"));
    }
    for a in b'A'..=b'X' {
        v.push(format!("?f@A@@{}EAAXXZ", a as char));
        v.push(format!("?f@A@@{}A@AEXXZ", a as char));
    }
    v.push("?f@?A0x12345678@@YAXXZ".to_owned());
    v.push("??_C@_02DPKJ@ab?$AA@".to_owned());
    v
}

#[test]
fn no_msvc_rendering_invents_a_name() {
    let allowed: BTreeSet<&str> = VOCABULARY.iter().copied().collect();
    let syms = msvc_symbols();

    let mut examined = 0;
    let mut invented: Vec<String> = Vec::new();
    for sym in &syms {
        let Some(r) = rustre_demangle::demangle(sym) else {
            continue;
        };
        if r.abi != rustre_demangle::ManglingAbi::Msvc {
            continue;
        }
        examined += 1;
        for tok in r
            .demangled
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .filter(|t| t.len() >= 2)
        {
            if allowed.contains(tok) || is_number(tok) || sym.contains(tok) {
                continue;
            }
            invented.push(format!("{tok:?} in {} <- {sym}", r.demangled));
        }
    }

    assert!(examined >= 90, "vacuous: only {examined} MSVC renderings examined");
    assert!(
        invented.is_empty(),
        "{} MSVC renderings contain a name absent from their input and not in the \
         renderer's vocabulary; first 8:\n{:#?}",
        invented.len(),
        &invented[..invented.len().min(8)]
    );
}

/// The five codes with no ground truth must decline, not fabricate.
///
/// Pinned separately so the reason is explicit: these are not *known* to be wrong
/// renderings — nothing knows what they mean. Declining is the honest answer, and if a
/// future oracle gains an opinion this test is where to start.
#[test]
fn codes_without_ground_truth_decline() {
    use msvc_demangler::{demangle as oracle, DemangleFlags};

    let mut checked = 0;
    for c in ['B', 'P', 'Q', 'W', 'Z'] {
        let sym = format!("??_{c}A@@QEAAXXZ");
        // Premise: the oracle has no opinion, so there is nothing to match.
        assert!(
            oracle(&sym, DemangleFlags::COMPLETE).is_err(),
            "??_{c} now has ground truth — add a table entry instead of declining"
        );
        let got = rustre_demangle::demangle(&sym).map(|r| r.demangled);
        assert!(
            got.is_none(),
            "??_{c} must decline rather than render a marker, got {got:?}"
        );
        checked += 1;
    }
    assert!(checked == 5, "expected 5 codes, checked {checked}");

    // Control: a code that DOES have an entry must still decode, so the fix is not a
    // blanket decline of `??_`.
    assert!(
        rustre_demangle::demangle("??_HA@@QEAAXXZ").is_some(),
        "??_H has a table entry and must keep decoding"
    );
}
