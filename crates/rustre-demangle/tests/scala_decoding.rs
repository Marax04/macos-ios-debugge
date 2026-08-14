//! Scala: the `NameTransformer` operator table, every entry.
//!
//! Scala appeared exactly once across `convention_decoding.rs` and
//! `detector_conventions.rs`, so its *rendering* was effectively unchecked —
//! the half of a detector's contract that let OCaml split only the first `__`
//! for years.
//!
//! The instrument is the rule that found the JNI escape defect: **a table with
//! N entries needs N test vectors.** Scala's has 18.
//!
//! **Measured 2026-07-30: no defect.** All 18 entries decode, adjacent
//! operators compose (`$eq$eq` -> `==`, `$greater$greater$greater` -> `>>>`),
//! and the specialization, `$anonfun$`, module and `$adapted` forms are all
//! correct. This file is the guard, not a fix.

use rustre_demangle::lang_more::jvm::demangle_scala as demangle;

/// The complete `NameTransformer` table, from the Scala compiler.
const OPS: &[(&str, &str)] = &[
    ("$plus", "+"),
    ("$minus", "-"),
    ("$times", "*"),
    ("$div", "/"),
    ("$colon", ":"),
    ("$less", "<"),
    ("$greater", ">"),
    ("$eq", "="),
    ("$bang", "!"),
    ("$percent", "%"),
    ("$amp", "&"),
    ("$bar", "|"),
    ("$up", "^"),
    ("$tilde", "~"),
    ("$qmark", "?"),
    ("$at", "@"),
    ("$hash", "#"),
    ("$bslash", "\\"),
];

/// Every entry decodes to its operator — not a sample of them.
#[test]
fn every_operator_encoding_decodes() {
    let mut checked = 0;
    let mut wrong = Vec::new();
    for (tok, sym) in OPS {
        let sym_name = format!("p.C.{tok}");
        checked += 1;
        match demangle(&sym_name) {
            Some(out) if out == format!("p.C.{sym}") => {}
            other => wrong.push(format!("{sym_name} => {other:?}, expected p.C.{sym}")),
        }
    }
    assert_eq!(checked, 18, "the table changed size — add vectors to match");
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// No two encodings decode to the same operator.
///
/// A table is also a mapping, and a duplicated right-hand side would make two
/// distinct Scala methods indistinguishable. Cheap to state, and it is the
/// class of error that put three wrong entries into the MSVC tables.
#[test]
fn the_operator_table_is_injective() {
    let mut seen: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
    for (tok, sym) in OPS {
        assert!(
            seen.insert(sym, tok).is_none(),
            "{sym} is produced by more than one encoding"
        );
    }
    assert_eq!(seen.len(), 18);
}

/// Adjacent encodings compose, which is how real Scala operators are spelled.
#[test]
fn adjacent_encodings_compose() {
    for (sym, want) in [
        ("p.C.$eq$eq", "p.C.=="),
        ("p.C.$plus$plus", "p.C.++"),
        ("p.C.$colon$colon", "p.C.::"),
        ("p.C.$less$eq", "p.C.<="),
        ("p.C.$bang$eq", "p.C.!="),
        ("p.C.$greater$greater$greater", "p.C.>>>"),
        ("p.C.$plus$colon", "p.C.+:"),
    ] {
        assert_eq!(demangle(sym).as_deref(), Some(want), "{sym}");
    }
}

/// The non-operator forms: specialization, lambda classes, modules, adapted.
#[test]
fn structural_suffixes_render() {
    for (sym, want) in [
        ("p.C$$anonfun$map$1", "p.C.map.<anonfun-1>"),
        ("p.C$", "object p.C"),
        ("p.C.m$mcII$sp", "p.C.m [specialized Int,Int]"),
        ("p.C.m$adapted", "p.C.m [adapted]"),
    ] {
        assert_eq!(demangle(sym).as_deref(), Some(want), "{sym}");
    }
}

/// DOCUMENTED AMBIGUITY, pinned rather than fixed.
///
/// An inner class whose name begins with an operator encoding's letters is
/// decoded as that operator: `p.Foo$upper` renders `p.Foo^per`, because `$up`
/// matches at the `$`.
///
/// This looks like a defect and may not be one. Scala's own
/// `NameTransformer.decode` matches by *prefix* at each `$` rather than by
/// whole token, so the same loss would occur in the compiler's decoder — the
/// encoding is genuinely lossy for such names. But that is recalled, not
/// verified: there is no Scala toolchain here to check it against, and
/// "fixing" it would silently diverge from the reference implementation.
///
/// So the current behaviour is pinned with the reasoning attached. If a future
/// session has scalac available, decide it then — and if the compiler does
/// require a token boundary, this test is the one to change.
#[test]
fn identifiers_beginning_with_an_encoding_are_decoded_as_operators() {
    for (sym, current) in [
        ("p.Foo$upper", "p.Foo^per"),
        ("p.Foo$diverge", "p.Foo/erge"),
        ("p.Foo$attribute", "p.Foo@tribute"),
        ("p.Foo$equals", "p.Foo=uals"),
    ] {
        assert_eq!(
            demangle(sym).as_deref(),
            Some(current),
            "{sym}: behaviour changed — read this test's note before updating it"
        );
    }
}
