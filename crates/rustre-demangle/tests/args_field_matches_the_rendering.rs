//! `args.len()` must equal the number of parameters in the rendering.
//!
//! The C++-family decoders in `lang_more` — cfront, Watcom, Borland — render a
//! full signature and reported `args: []`:
//!
//! ```text
//! f__Fic       =>  f(int, char)      args.len() == 0
//! @U@P$qqric   =>  U.P(int, char)    args.len() == 0
//! W?h$n(ia)v   =>  h(int, char)      args.len() == 0
//! ```
//!
//! Reading the field gave a different arity from reading the string. That is
//! the arity defect class inverted: iter 116 caught Watcom INVENTING phantom
//! parameters in its rendering, while the structured field was silently
//! dropping real ones — and this repo's decompiler notes single arity out
//! precisely because nothing but an arity check can see it.
//!
//! The property is stated as an EQUALITY between the two views of one symbol,
//! not as an expected number, so it holds for any ABI and any signature: if a
//! decoder ever disagrees with itself again, this fails.

/// Count parameters in a rendering, depth-aware.
///
/// Deliberately a second, independent implementation of the split — comparing
/// the field against itself would prove nothing.
fn rendered_arity(out: &str) -> Option<usize> {
    let open = out.find('(')?;
    let mut depth = 0i32;
    let mut close = None;
    for (i, c) in out.char_indices().skip(open) {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let inner = out[open + 1..close?].trim();
    if inner.is_empty() || inner == "void" {
        return Some(0);
    }
    let mut depth = 0i32;
    let mut n = 1;
    for c in inner.chars() {
        match c {
            '(' | '<' | '[' => depth += 1,
            ')' | '>' | ']' => depth -= 1,
            ',' if depth == 0 => n += 1,
            _ => {}
        }
    }
    Some(n)
}

/// Across every ABI that renders a signature, the two views agree.
#[test]
fn the_args_field_agrees_with_the_rendering() {
    const SYMBOLS: &[&str] = &[
        // Itanium / MSVC / D: were already right.
        "_Z3fooic",
        "_Z3foov",
        "?f@@YAXHH@Z",
        "?foo@@YAXXZ",
        "?f@@YAXABH0@Z",
        "??$max@H@@YAHABH0@Z",
        "_D4main3fooFiiZv",
        "_D4main3fooFZv",
        "_D4main3Foo3barMFiZi",
        "_D4main3fooFiZ3barFcZv",
        // The three that reported zero.
        "f__Fic",
        "f__Fv",
        "@U@P$qqric",
        "@Unit@Proc$qqrv",
        "W?h$n(ia)v",
        "W?f$n()v",
    ];
    let mut checked = 0;
    let mut mismatches = Vec::new();
    for sym in SYMBOLS {
        let Some(r) = rustre_demangle::demangle(sym) else {
            mismatches.push(format!("{sym} must decode"));
            continue;
        };
        let Some(rendered) = rendered_arity(&r.demangled) else {
            continue; // no signature in the rendering
        };
        checked += 1;
        if rendered != r.args.len() {
            mismatches.push(format!(
                "{sym}: rendering {:?} has {rendered} parameters, args has {}",
                r.demangled,
                r.args.len()
            ));
        }
    }
    assert!(checked >= 16, "vacuous: only {checked} signatures checked");
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

/// The entries are the parameter types, in order.
///
/// Arity alone would be satisfied by any list of the right length.
#[test]
fn the_args_entries_are_the_parameter_types() {
    for (sym, want) in [
        ("f__Fic", vec!["int", "char"]),
        ("@U@P$qqric", vec!["int", "char"]),
        ("W?h$n(ia)v", vec!["int", "char"]),
        ("f__FPCc", vec!["const char*"]),
        ("@U@P$qqrxpi", vec!["int* const"]),
        ("W?f$n(ui)v", vec!["unsigned int"]),
    ] {
        let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert_eq!(r.args, want, "{sym} (rendered {:?})", r.demangled);
    }
}

/// An empty parameter list is empty, not a one-entry list containing `void`.
///
/// The phantom-parameter shape: `["void"]` hands a caller a one-parameter
/// signature for a function that has none. The Itanium path has always reported
/// zero here, and the new extraction matches it.
#[test]
fn an_empty_parameter_list_is_empty() {
    for sym in ["f__Fv", "@Unit@Proc$qqrv", "W?f$n()v", "_Z3foov", "?foo@@YAXXZ"] {
        let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert!(
            r.args.is_empty(),
            "{sym}: args = {:?} for a function with no parameters",
            r.args
        );
    }
}

/// A symbol with no signature reports no arguments — the extraction must not
/// invent a list from a name that merely contains a parenthesis.
#[test]
fn symbols_without_a_signature_report_no_arguments() {
    for sym in [
        "_OBJC_CLASS_$_Foo",
        "Java_com_foo_Bar_baz",
        "pkg__proc",
        "camlFoo__bar",
        "main.main",
        "sync.(*Mutex).Lock",
    ] {
        let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert!(
            r.args.is_empty(),
            "{sym}: args = {:?} but the rendering {:?} names no signature",
            r.args,
            r.demangled
        );
    }
}
