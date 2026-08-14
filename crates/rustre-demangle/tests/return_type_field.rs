//! `return_type` must be filled when the rendering names one.
//!
//! The last structured field never examined. Two ABIs spelled a return type in
//! their rendering and reported `None`:
//!
//! ```text
//! $s4main3fooySiF                      main.foo() -> Swift.Int         None
//! kfun:a.B#c(kotlin.Int){}kotlin.Any?  a.B.c(kotlin.Int): kotlin.Any?  None
//! ```
//!
//! Pure extraction — the information is already in the string, so neither a
//! grammar nor an oracle is involved, which is what makes this decidable where
//! the remaining Swift questions are not.
//!
//! **`None` is CORRECT for Itanium and cfront**, and the test pins that: neither
//! ABI mangles a return type for an ordinary function (only for templates,
//! where Itanium does report it). Reporting one there would mean inventing it.
//! Distinguishing "the field is unfilled" from "the ABI has nothing to fill it
//! with" is the whole difficulty of this field.
//!
//! The Swift extraction takes the LAST `->` at depth zero: a function-typed
//! parameter carries an arrow of its own, and taking the first would report the
//! parameter's result as the function's. The convention extraction requires the
//! `:` to FOLLOW the closing paren, so a descriptive rendering (`lua module
//! open: socket.core`) — whose colon precedes a path, not a type — is untouched.

fn ret(sym: &str) -> Option<String> {
    rustre_demangle::demangle(sym)
        .unwrap_or_else(|| panic!("{sym} must decode"))
        .return_type
}

/// When the rendering names a return type, the field carries it.
#[test]
fn a_rendered_return_type_reaches_the_field() {
    for (sym, want) in [
        ("$s4main3fooySiF", "Swift.Int"),
        ("$s4main1aySiSSF", "Swift.String"),
        ("$s4main3fooyyF", "()"),
        ("$s4main3barSiyF", "()"),
        ("kfun:a.B#c(kotlin.Int){}kotlin.Any?", "kotlin.Any?"),
        // Already correct — pinned so the change cannot have disturbed them.
        ("?f@@YAHH@Z", "int"),
        ("?f@@YAXH@Z", "void"),
        ("_D4main3fooFiZi", "int"),
        ("_D4main3fooFiZv", "void"),
        ("_D4main3fooFZC4main3Qux", "main.Qux"),
        ("_Z3fooIiEiT_", "int"),
    ] {
        assert_eq!(ret(sym).as_deref(), Some(want), "{sym}");
    }
}

/// The field is a SUBSTRING of the rendering — extraction, never invention.
#[test]
fn the_return_type_comes_from_the_rendering() {
    for sym in [
        "$s4main3fooySiF",
        "$s4main1aySiSSF",
        "kfun:a.B#c(kotlin.Int){}kotlin.Any?",
        "?f@@YAHH@Z",
        "_D4main3fooFZC4main3Qux",
    ] {
        let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym}"));
        let t = r.return_type.clone().unwrap_or_else(|| panic!("{sym} has no return type"));
        assert!(
            r.demangled.contains(&t),
            "{sym}: return_type {t:?} is not part of {:?}",
            r.demangled
        );
    }
}

/// `None` where the ABI encodes no return type.
///
/// Itanium and cfront mangle one only for templates. Filling the field here
/// would be invention, and the Itanium template case above proves the `None` is
/// a decision rather than an omission.
#[test]
fn abis_without_a_mangled_return_type_report_none() {
    for sym in ["_Z3fooic", "_Z3foov", "f__Fic", "f__Fv", "@U@P$qqric", "W?h$n(ia)v"] {
        assert_eq!(ret(sym), None, "{sym}");
    }
}

/// A descriptive rendering's colon introduces a PATH, not a type.
///
/// This is what a naive "text after the last colon" rule would have broken —
/// the "whole sentence in a field" defect that `split_convention_rendering`'s
/// own doc records.
#[test]
fn prose_renderings_gain_no_return_type() {
    for sym in [
        "luaopen_socket_core",
        "zim_ArrayObject_count",
        "Init_mymodule",
        "kclass:a.B",
        "kfun:a.B#c(){}",
        "mexFunction",
    ] {
        let Some(r) = rustre_demangle::demangle(sym) else {
            continue;
        };
        assert_eq!(
            r.return_type, None,
            "{sym}: rendering {:?} gained a return type",
            r.demangled
        );
    }
}

/// A nested function type must not have its own arrow mistaken for the result.
#[test]
fn a_function_typed_parameter_does_not_win_the_arrow() {
    // Constructed directly: the rendering is what the rule reads.
    let out = "main.f((Swift.Int) -> Swift.Bool) -> Swift.String";
    let last = out.rfind("->").expect("an arrow");
    assert_eq!(out[last + 2..].trim(), "Swift.String");
    // And the real symbol, whose parameter is a closure, keeps its own result.
    if let Some(r) = rustre_demangle::demangle("$s4main3fooySiF") {
        assert_eq!(r.return_type.as_deref(), Some("Swift.Int"));
    }
}
