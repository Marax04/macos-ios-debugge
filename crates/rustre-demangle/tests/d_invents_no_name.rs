//! D renderings must not invent names.
//!
//! Third cross-application of the anti-invention guard (Go iter 64, MSVC iter 106), and
//! the one where it matters most in principle: **D is written entirely by hand and has
//! no oracle**, so there is nothing to contradict a wrong answer. Anti-invention is one
//! of the few checks available for it at all.
//!
//! Measured 2026-07-30 over 186 grammar-derived renderings: **45 distinct tokens absent
//! from their input, and every one is D vocabulary.** No invention.
//!
//! ### Why this vocabulary list is stronger than MSVC's
//!
//! The MSVC list (iter 106) was derived from a *sample* of shapes, so a construct nobody
//! generated could still add a word to it. D's is derived from an **exhaustive** sweep:
//! iters 63 and 72 established that every basic type code, every function attribute and
//! every type constructor in the D grammar has a test, and this sweep drives all of
//! them. So for those constructs the list is complete by construction — a new word
//! appearing means either a new grammar feature or a fabrication, and either deserves
//! attention.

use std::collections::BTreeSet;

/// Words the D renderer contributes itself, grouped by what they are.
///
/// Derived from measurement, not guessed. Each group corresponds to a table the D
/// grammar sweeps exhaustively.
const VOCABULARY: &[&str] = &[
    // Basic types (`d_demangler`'s single-letter codes).
    "void", "bool", "byte", "ubyte", "short", "ushort", "int", "uint", "long", "ulong",
    "float", "double", "real", "char", "wchar", "dchar",
    // Imaginary and complex triples.
    "ifloat", "idouble", "ireal", "cfloat", "cdouble", "creal",
    // Type constructors and qualifiers.
    "const", "immutable", "shared", "inout", "scope", "ref", "return", "typeof", "null",
    "noreturn", "__vector", "Tuple", "delegate", "function",
    // Function attributes (the ten-letter table, iter 63).
    "pure", "nothrow", "property", "trusted", "safe", "nogc", "live",
    // Extern linkages.
    "extern", "Windows", "Pascal",
];

/// `_D<len><part>…<tail>`, length prefixes computed rather than hand-counted — the error
/// that produced six false findings earlier in this session.
fn sym(parts: &[&str], tail: &str) -> String {
    let mut out = String::from("_D");
    for p in parts {
        out.push_str(&p.len().to_string());
        out.push_str(p);
    }
    out.push_str(tail);
    out
}

/// Every basic type, every attribute, every constructor, every linkage.
const TAILS: &[&str] = &[
    "FiZv", "FZv", "FAyaZv", "FPiZv", "FAiZv", "FxiZv", "FyiZv", "FOiZv",
    // The attribute table.
    "FNaiZv", "FNbiZv", "FNciZv", "FNdiZv", "FNeiZv", "FNfiZv", "FNgiZv", "FNhiZv",
    "FNiiZv", "FNjiZv", "FNkiZv", "FNmiZv", "FNnZv",
    // Aggregates and compounds.
    "FG3iZv", "FB2iiZv", "FHiAyaZv", "FDFiZvZv", "FC4main3FooZv", "FS4main3BarZv",
    "FE4main3ColZv", "FT4main3TypZv", "FRiZv", "FiiZv", "FiXv", "FiYv",
    // Linkages.
    "UiZv", "WiZv", "ViZv", "RiZv",
    // Every remaining basic-type letter.
    "FcZv", "FqZv", "FpZv", "FjZv", "FrZv", "FkZv", "FmZv", "FnZv", "FoZv", "FsZv",
    "FtZv", "FuZv", "FwZv", "FbZv", "FaZv", "FdZv", "FeZv", "FfZv", "FgZv", "FhZv",
    "FlZv", "FvZv", "FzZv",
    // A variable, and nested constructors.
    "i", "FPFiZvZv", "FAAiZv", "FPG4iZv",
];

#[test]
fn no_d_rendering_invents_a_name() {
    let allowed: BTreeSet<&str> = VOCABULARY.iter().copied().collect();
    let paths: &[&[&str]] = &[
        &["main", "foo"],
        &["mymod", "myclass", "method"],
        &["a", "b"],
    ];

    let mut examined = 0;
    let mut invented: Vec<String> = Vec::new();
    for parts in paths {
        for tail in TAILS {
            let s = sym(parts, tail);
            let Some(r) = rustre_demangle::demangle(&s) else {
                continue;
            };
            if r.abi != rustre_demangle::ManglingAbi::D {
                continue;
            }
            examined += 1;
            for tok in r
                .demangled
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .filter(|t| t.len() >= 2)
            {
                if allowed.contains(tok) || tok.bytes().all(|b| b.is_ascii_digit()) || s.contains(tok)
                {
                    continue;
                }
                invented.push(format!("{tok:?} in {} <- {s}", r.demangled));
            }
        }
    }

    assert!(examined > 150, "vacuous: only {examined} D renderings examined");
    assert!(
        invented.is_empty(),
        "{} D renderings contain a name absent from their input and not in the \
         renderer's vocabulary; first 8:\n{:#?}",
        invented.len(),
        &invented[..invented.len().min(8)]
    );
}

/// The sweep must actually reach every table, or the vocabulary claim is hollow.
///
/// Asserts that each *category* of vocabulary is exercised by at least one rendering —
/// so a future change that stopped decoding attributes, say, would fail here rather
/// than passing an anti-invention check that no longer sees them.
#[test]
fn the_sweep_exercises_every_vocabulary_category() {
    let mut renderings = Vec::new();
    for tail in TAILS {
        if let Some(r) = rustre_demangle::demangle(&sym(&["main", "foo"], tail)) {
            renderings.push(r.demangled);
        }
    }
    let all = renderings.join(" | ");

    let categories = [
        ("basic type", "ubyte"),
        ("imaginary/complex", "creal"),
        ("qualifier", "immutable"),
        ("constructor", "delegate"),
        ("attribute", "nothrow"),
        ("linkage", "Windows"),
        ("tuple", "Tuple"),
        ("vector", "__vector"),
        ("bottom type", "noreturn"),
    ];
    let mut proved = 0;
    for (what, word) in categories {
        assert!(
            all.contains(word),
            "no rendering exercises the {what} category (looked for {word:?}) — the \
             vocabulary list covers words the sweep no longer produces"
        );
        proved += 1;
    }
    assert_eq!(proved, 9, "expected 9 categories, proved {proved}");
}
