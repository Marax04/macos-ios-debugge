//! GNAT's compiler-generated entry points were filed as plain C.
//!
//! Every Ada program has a library-level entry `_ada_<unit>`, and every Ada
//! unit has elaboration procedures `<unit>___elabb` (body) and `___elabs`
//! (spec). All three declined, and `decline_reason` called them
//! `UndecoratedC` — real Ada symbols reported as C names, so a consumer
//! grouping by language lost them entirely.
//!
//! They are excluded by the ordinary rules for good reasons: the dispatcher's
//! gate drops a leading `_`, and `detect_gnat_ada` rejects a component starting
//! with `_` (the iter-110 rule that fixed `a___b` -> `a._b`). Both are correct
//! and stay; the special forms get their own dispatch line instead.
//!
//! **`detect_gnat_ada` is deliberately NOT widened.** It is used as an
//! *exclusion* in `lang_extra` — `!(detect_ocaml(s) || detect_gnat_ada(s))` —
//! where a looser rule rejects more rather than claiming more. Widening it
//! there would change the sign of the test, which is the trap the crate's
//! CLAUDE.md records as the deliberate exception to consolidating sigil checks.
//!
//! Decidable without an oracle: these are documented GNAT conventions, the same
//! standard used for D, JNI and Obj-C.

fn ours(sym: &str) -> Option<String> {
    rustre_demangle::demangle(sym).map(|r| r.demangled)
}

fn abi_of(sym: &str) -> Option<String> {
    rustre_demangle::demangle(sym).map(|r| format!("{:?}", r.abi))
}

/// The three forms decode, and are labelled Ada.
#[test]
fn gnat_entry_and_elaboration_decode() {
    for (sym, want) in [
        ("_ada_hello", "hello [ada entry]"),
        ("_ada_pkg__proc", "pkg.proc [ada entry]"),
        ("pkg___elabb", "pkg [elaborate body]"),
        ("pkg___elabs", "pkg [elaborate spec]"),
        ("a__b___elabb", "a.b [elaborate body]"),
    ] {
        assert_eq!(ours(sym).as_deref(), Some(want), "{sym}");
        assert_eq!(abi_of(sym).as_deref(), Some("Ada"), "{sym}");
    }
}

/// The kind must be reported, not folded into the name.
///
/// `_ada_pkg__proc` and `pkg__proc` are DIFFERENT symbols — the Ada-callable
/// wrapper and the procedure itself. Rendering both as `pkg.proc` would merge
/// them, which is the collision this crate has spent the session removing.
#[test]
fn the_wrapper_is_distinct_from_the_procedure() {
    assert_eq!(ours("pkg__proc").as_deref(), Some("pkg.proc"));
    assert_ne!(ours("_ada_pkg__proc"), ours("pkg__proc"));
    assert_ne!(ours("pkg___elabb"), ours("pkg___elabs"));
    // And each unit's elaboration is distinct from the next unit's.
    assert_ne!(ours("a___elabb"), ours("b___elabb"));
}

/// The ordinary Ada rules are untouched.
///
/// In particular the iter-110 component rule that rejects `a___b` — the fix
/// this change had to work around rather than undo.
#[test]
fn the_ordinary_ada_rules_still_hold() {
    for (sym, want) in [
        ("pkg__proc", "pkg.proc"),
        ("ada__text_io__put_line", "ada.text_io.put_line"),
        ("a__b__c__d", "a.b.c.d"),
    ] {
        assert_eq!(ours(sym).as_deref(), Some(want), "{sym}");
    }
    // A component starting with `_` is still not an Ada identifier.
    for sym in ["a___b", "a____b", "_a__b", "a__b_"] {
        assert_ne!(abi_of(sym).as_deref(), Some("Ada"), "{sym}");
    }
}

/// Nothing that is not GNAT may be claimed.
///
/// `_ada_` is a short prefix, so the unit that follows must itself be a valid
/// Ada name; and an `___elab` suffix on something that is not a unit name is
/// not an elaboration procedure.
#[test]
fn c_names_are_not_claimed() {
    for sym in [
        "_ada_",
        "_ada_Foo",
        "_ada_9x",
        "___elabb",
        "_elabb",
        "Pkg___elabb",
        "_ada_pkg___elabb",
    ] {
        assert_ne!(
            abi_of(sym).as_deref(),
            Some("Ada"),
            "{sym} must not be claimed as Ada"
        );
    }
}

/// No mangling residue reaches the output.
///
/// The tags are derived from the input's own markers, so the rendering must
/// carry neither `_ada_` nor `___elab`.
#[test]
fn no_marker_survives_into_the_output() {
    for sym in ["_ada_hello", "_ada_pkg__proc", "pkg___elabb", "pkg___elabs"] {
        let out = ours(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert!(!out.contains("_ada_"), "{sym} => {out}");
        assert!(!out.contains("elabb") && !out.contains("elabs"), "{sym} => {out}");
    }
}
