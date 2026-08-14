//! Watcom C++: parameter ARITY, and a fallback that claimed varargs.
//!
//! Two defects, both invisible to every check the crate had:
//!
//! 1. **Phantom parameters.** `u` is a qualifier in Watcom's argument codes,
//!    not a standalone type: `ui` is `unsigned int`, ONE parameter. Mapping
//!    each character independently rendered `f(unsigned, int)` — two — and
//!    `uui` rendered three. This repo's decompiler notes single this class out
//!    as the worst kind precisely because it is invisible to everything but
//!    arity: a phantom parameter is well-formed, plausible, and silently wrong.
//!
//! 2. **`(...)` is a signature, not a placeholder.** The best-effort fallback
//!    emitted `name(...)` whenever the argument group could not be read. In C++
//!    `(...)` means varargs, so "I could not read the arguments" was rendered
//!    as a positive claim about the function's type — and seven distinct
//!    inputs, including the well-formed `W?f$n` which carries no argument group
//!    at all, collapsed onto that single output. It now emits the NAME ALONE,
//!    which claims nothing and loses nothing; `f` stays distinguishable from
//!    `f()`.
//!
//! Watcom was one of the eight conventions with no presence in either
//! `convention_decoding.rs` or `detector_conventions.rs`.

use rustre_demangle::lang_more::legacy_native::demangle_watcom as demangle;

/// Count parameters in a rendering, or `None` when no signature is claimed.
fn arity(sym: &str) -> Option<usize> {
    let out = demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
    let open = out.find('(')?;
    let close = out.rfind(')')?;
    let inner = &out[open + 1..close];
    Some(if inner.is_empty() {
        0
    } else {
        inner.split(',').count()
    })
}

/// One argument code group, one parameter per TYPE — not per character.
///
/// Discriminating: `(i)` and `(ia)` pass whether or not `u` is understood as a
/// qualifier; they are the cases anyone writes first, and they were already
/// right. `(ui)` is what separates a decoder from a character map.
#[test]
fn a_qualified_type_is_one_parameter_not_two() {
    for (sym, want_arity) in [
        ("W?f$n(i)v", 1),
        ("W?h$n(ia)v", 2),
        ("W?f$n()v", 0),
        ("W?f$n(ui)v", 1),
        ("W?f$n(ul)v", 1),
        ("W?f$n(uiui)v", 2),
        ("W?f$n(iui)v", 2),
        ("W?f$n(uia)v", 2),
    ] {
        assert_eq!(arity(sym), Some(want_arity), "{sym} has the wrong arity");
    }
}

/// And the qualified types render as one name, not two.
#[test]
fn qualified_types_render_as_a_single_type() {
    for (sym, want) in [
        ("W?f$n(ui)v", "f(unsigned int)"),
        ("W?f$n(ul)v", "f(unsigned long)"),
        ("W?f$n(us)v", "f(unsigned short)"),
        ("W?f$n(ua)v", "f(unsigned char)"),
        ("W?f$n(uiui)v", "f(unsigned int, unsigned int)"),
        ("W?h$n(ia)v", "h(int, char)"),
    ] {
        assert_eq!(demangle(sym).as_deref(), Some(want), "{sym}");
    }
}

/// A qualifier with nothing to qualify, or stacked, is not a type.
#[test]
fn a_dangling_or_stacked_qualifier_claims_no_signature() {
    for sym in ["W?f$n(u)v", "W?f$n(uui)v", "W?f$n(iu)v", "W?f$n(uuu)v"] {
        assert_eq!(
            arity(sym),
            None,
            "{sym} must not claim a parameter list it could not read"
        );
    }
}

/// An unreadable argument group yields a bare name, never a varargs signature.
///
/// Defined over the OUTPUT — no rendering may end in `(...)` — so a future
/// fallback that reintroduces the claim fails here regardless of which input
/// triggers it.
#[test]
fn unreadable_arguments_never_render_as_varargs() {
    let inputs = [
        "W?f$n",
        "W?f$nZZZ",
        "W?f$n(",
        "W?f$n)",
        "W?f$n(zzz)v",
        "W?f$n(i",
        "W?f$n(e)v",
        "W?f$n(u)v",
    ];
    let mut decoded = 0;
    let mut offenders = Vec::new();
    for sym in inputs {
        let Some(out) = demangle(sym) else { continue };
        decoded += 1;
        if out.contains("...") {
            offenders.push(format!("{sym} => {out}"));
        }
        assert_eq!(out, "f", "{sym} should recover the name alone, got {out}");
    }
    assert!(decoded >= 7, "vacuous: only {decoded} decoded");
    assert!(
        offenders.is_empty(),
        "an unreadable argument list was rendered as a varargs signature:\n{}",
        offenders.join("\n")
    );
}

/// `f` (unknown arguments) and `f()` (no arguments) are different claims and
/// must stay different strings.
#[test]
fn unknown_arguments_and_no_arguments_stay_distinct() {
    assert_eq!(demangle("W?f$n()v").as_deref(), Some("f()"));
    assert_eq!(demangle("W?f$n").as_deref(), Some("f"));
    assert_ne!(demangle("W?f$n()v"), demangle("W?f$n"));
}
