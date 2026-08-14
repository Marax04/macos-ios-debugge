//! Borland / C++Builder: modifier order, and the varargs claim again.
//!
//! `borland_type` had the same order-destroying shape as cfront (fixed at iter
//! 115) plus one worse defect of its own. Borland modifiers qualify what
//! FOLLOWS them, so:
//!
//! ```text
//! pxi = p(x(i)) = pointer to const int = const int*
//! xpi = x(p(i)) = const pointer to int = int* const
//! ```
//!
//! 1. **Injectivity collapse.** `pxi`, `xpi` and `xpxi` all rendered
//!    `const int*`.
//! 2. **Indirections REVERSED.** The suffix was `push`ed rather than
//!    prepended, so `rpi` (reference to pointer, `int*&`) rendered `int&*`
//!    while the illegal `pri` rendered `int*&` — exactly swapped. This is
//!    worse than a collapse: both outputs are well-formed C++ types, and each
//!    is the correct rendering of the *other* input.
//! 3. **`(...)` on failure**, the same varargs claim fixed in Watcom at iter
//!    116: `uui` rendered `U.P(...)`. It now yields the name alone.
//!
//! Borland was the last of the eight conventions with no presence in either
//! `convention_decoding.rs` or `detector_conventions.rs`.

use rustre_demangle::lang_more::pascal_family::demangle_borland as demangle;

fn args_of(sym: &str) -> String {
    let out = demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
    let open = out.find('(').unwrap_or_else(|| panic!("{sym} claimed no signature: {out}"));
    let close = out.rfind(')').expect("a signature");
    out[open + 1..close].to_owned()
}

/// Distinct modifier orders are distinct types.
#[test]
fn distinct_modifier_orders_render_distinctly() {
    let orders = ["pxi", "xpi", "xpxi", "pxpxi", "pi", "xi", "ppi", "rxi", "xri"];
    let mut seen: std::collections::BTreeMap<String, &str> = std::collections::BTreeMap::new();
    let mut collisions = Vec::new();
    for o in orders {
        let Some(out) = demangle(&format!("@U@P$qqr{o}")) else {
            continue;
        };
        if let Some(prev) = seen.insert(out.clone(), o) {
            collisions.push(format!("{prev} and {o} both render {out}"));
        }
    }
    assert!(seen.len() >= 8, "vacuous: only {} decoded", seen.len());
    assert!(
        collisions.is_empty(),
        "distinct Borland types collapsed onto one rendering:\n{}",
        collisions.join("\n")
    );
}

/// Indirections apply outward, so `rp` is a reference TO a pointer.
///
/// This is the assertion the reversal would fail: `rpi` and `pri` are not
/// interchangeable, and one of them is not a C++ type at all.
#[test]
fn indirections_are_not_reversed() {
    assert_eq!(args_of("@U@P$qqrrpi"), "int*&");
    assert_eq!(args_of("@U@P$qqrppi"), "int**");
    assert_eq!(args_of("@U@P$qqrpppi"), "int***");
    // Pointer to reference and reference to reference do not exist in C++.
    for sig in ["pri", "rri", "prpi"] {
        let out = demangle(&format!("@U@P$qqr{sig}")).expect("the name still decodes");
        assert!(
            !out.contains('('),
            "{sig} asks for an indirection C++ forbids, but rendered {out}"
        );
    }
}

/// `const` sits west of a plain type and east of an indirection.
#[test]
fn const_placement_follows_the_modifier_order() {
    for (sig, want) in [
        ("i", "int"),
        ("xi", "const int"),
        ("pi", "int*"),
        ("pxi", "const int*"),
        ("xpi", "int* const"),
        ("xpxi", "const int* const"),
        ("rxi", "const int&"),
        ("xri", "int& const"),
    ] {
        assert_eq!(args_of(&format!("@U@P$qqr{sig}")), want, "signature {sig}");
    }
}

/// A doubled `const` at one level is not a type C++ can express.
///
/// Caught only because the same probe was re-run after the rewrite: collapsing
/// `xx` merely lost information, but building outward would have FABRICATED
/// `const const int`. The identical hole existed in the cfront builder and is
/// closed there too.
#[test]
fn a_doubled_const_claims_no_signature() {
    for sig in ["xxi", "xxpi", "pxxi"] {
        let out = demangle(&format!("@U@P$qqr{sig}")).expect("the name still decodes");
        assert!(!out.contains('('), "{sig} rendered {out}");
    }
}

/// An unreadable argument list yields a bare name, never a varargs signature.
#[test]
fn unreadable_arguments_never_render_as_varargs() {
    let mut decoded = 0;
    for sig in ["uui", "zz", "q", "xxi", "pri", "9"] {
        let Some(out) = demangle(&format!("@U@P$qqr{sig}")) else {
            continue;
        };
        decoded += 1;
        assert!(
            !out.contains("..."),
            "{sig} rendered an unreadable argument list as varargs: {out}"
        );
        assert_eq!(out, "U.P", "{sig} should recover the name alone, got {out}");
    }
    assert!(decoded >= 5, "vacuous: only {decoded} decoded");
}

/// The documented shapes, unchanged.
#[test]
fn documented_shapes_still_decode() {
    for (sym, want) in [
        ("@Forms@TApplication@Run$qqrv", "Forms.TApplication.Run()"),
        ("@Unit@Proc$qqri", "Unit.Proc(int)"),
        ("@Unit@Proc$qqric", "Unit.Proc(int, char)"),
        ("@U@P$qqrui", "U.P(unsigned int)"),
    ] {
        assert_eq!(demangle(sym).as_deref(), Some(want), "{sym}");
    }
}
