//! Objective-C: correctness of what it renders, not just what it claims.
//!
//! Obj-C was absent from the correctness table in this crate's CLAUDE.md — the
//! only ABI with neither an oracle entry nor a "no oracle exists" entry. It
//! does not need one: `-[Class selector]` and clang's `_OBJC_…` metadata
//! symbols are fully documented, so correctness is establishable from the
//! grammar the way D's and JNI's are.
//!
//! Probing them found that only THREE linker forms had ever been written down
//! (`CLASS_$_`, `METACLASS_$_`, `IVAR_$_`), and every other one fell through to
//! a fallback that replaced `_` with a space:
//!
//! ```text
//! _OBJC_PROTOCOL_$_Foo        =>  "PROTOCOL $ Foo"
//! _OBJC_$_INSTANCE_METHODS_Foo =>  "$ INSTANCE METHODS Foo"
//! ```
//!
//! That is not a demangling. The `$` is a mangling sigil reaching the output —
//! the defect shape this crate already names — and the result is neither the
//! input nor a decoded name, so a consumer cannot even fall back to echoing it.

use rustre_demangle::ObjCDemangler as ObjC;

/// No mangling sigil may survive into the output.
///
/// Defined over the OUTPUT against a fixed alphabet rather than over a list of
/// known-bad symbols, so a form nobody thought of still fails the check. This
/// is the property the underscore-to-space fallback violated on every symbol it
/// touched, while looking like a decode.
#[test]
fn no_mangling_sigil_reaches_the_output() {
    let inputs = [
        "_OBJC_CLASS_$_Foo",
        "_OBJC_METACLASS_$_Foo",
        "_OBJC_IVAR_$_Foo._field",
        "_OBJC_PROTOCOL_$_Foo",
        "_OBJC_LABEL_PROTOCOL_$_Foo",
        "_OBJC_CLASS_RO_$_Foo",
        "_OBJC_METACLASS_RO_$_Foo",
        "_OBJC_$_INSTANCE_METHODS_Foo",
        "_OBJC_$_CLASS_METHODS_NSString",
        "_OBJC_$_INSTANCE_VARIABLES_Foo",
        "_OBJC_$_PROP_LIST_Foo",
        "_OBJC_$_PROTOCOL_REFS_Foo",
        "_OBJC_METH_VAR_NAME_",
        "_OBJC_SELECTOR_REFERENCES_",
        "_OBJC_",
    ];
    let mut decoded = 0;
    let mut offenders = Vec::new();
    for s in inputs {
        let Some(out) = ObjC::demangle(s) else {
            continue;
        };
        decoded += 1;
        if out.contains('$') || out.contains("_OBJC") {
            offenders.push(format!("{s} => {out}"));
        }
    }
    assert!(decoded >= 12, "vacuous: only {decoded} decoded");
    assert!(
        offenders.is_empty(),
        "mangling sigils survived into the output:\n{}",
        offenders.join("\n")
    );
}

/// Each documented metadata form renders its meaning and keeps its name.
///
/// Discriminating: the three that already worked (`class`, `metaclass`,
/// `ivar`) pass either way — they are the cases anyone writes first. The
/// protocol and method-list forms are what separate a decoder from a fallback
/// that merely rearranges punctuation.
#[test]
fn documented_metadata_forms_decode() {
    for (sym, want) in [
        ("_OBJC_CLASS_$_NSObject", "class NSObject"),
        ("_OBJC_METACLASS_$_Foo", "metaclass Foo"),
        ("_OBJC_IVAR_$_MyClass._count", "ivar MyClass::_count"),
        ("_OBJC_PROTOCOL_$_Foo", "protocol Foo"),
        ("_OBJC_LABEL_PROTOCOL_$_Foo", "protocol label Foo"),
        ("_OBJC_CLASS_RO_$_Foo", "class metadata Foo"),
        ("_OBJC_$_INSTANCE_METHODS_Foo", "instance methods of Foo"),
        ("_OBJC_$_CLASS_METHODS_NSString", "class methods of NSString"),
        ("_OBJC_$_PROP_LIST_Foo", "properties of Foo"),
    ] {
        assert_eq!(ObjC::demangle(sym).as_deref(), Some(want), "{sym}");
        assert!(ObjC::detect(sym), "detector must claim {sym}");
    }
}

/// The class name must survive verbatim — the completeness property, defined
/// over the INPUT, that `go_completeness.rs` exists for.
#[test]
fn the_name_survives_into_the_output() {
    for (sym, name) in [
        ("_OBJC_CLASS_$_NSMutableArray", "NSMutableArray"),
        ("_OBJC_PROTOCOL_$_NSCopying", "NSCopying"),
        ("_OBJC_$_INSTANCE_METHODS_UIViewController", "UIViewController"),
        ("_OBJC_CLASS_RO_$_WKWebView", "WKWebView"),
    ] {
        let out = ObjC::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert!(out.contains(name), "{sym} lost its name: {out}");
    }
}

/// Anchors with no name payload carry nothing to demangle, so they decline.
///
/// `_OBJC_METH_VAR_NAME_` and `_OBJC_SELECTOR_REFERENCES_` are literal-pool
/// anchors — the same class the corpus triage counts as "linker section, not a
/// symbol". Rendering them as `METH VAR NAME` claimed a decode where there was
/// no name at all.
#[test]
fn nameless_anchors_decline() {
    for sym in [
        "_OBJC_METH_VAR_NAME_",
        "_OBJC_SELECTOR_REFERENCES_",
        "_OBJC_",
        "_OBJC_CLASS_$_",
        "_OBJC_PROTOCOL_$_",
    ] {
        assert_eq!(ObjC::demangle(sym), None, "{sym} has no name to decode");
        assert!(!ObjC::detect(sym), "the detector must not claim {sym} either");
    }
}

/// The method syntax, including the shapes the detector must refuse.
#[test]
fn method_syntax_round_trips_and_rejects_degenerates() {
    for (sym, want) in [
        ("-[Foo bar]", "-[Foo bar]"),
        ("+[NSObject alloc]", "+[NSObject alloc]"),
        ("-[Foo bar:baz:]", "-[Foo bar:baz:]"),
        ("-[NSString(Cat) length]", "-[NSString(Cat) length]"),
        ("-[Foo]", "-[Foo]"),
        // Whitespace between class and selector is normalised, not preserved.
        ("-[Foo  bar]", "-[Foo bar]"),
    ] {
        assert_eq!(ObjC::demangle(sym).as_deref(), Some(want), "{sym}");
        assert!(ObjC::detect(sym), "detector must claim {sym}");
    }
    for sym in ["-[]", "-[ ]", "- [Foo bar]", "[Foo bar]", "-Foo bar]"] {
        assert_eq!(ObjC::demangle(sym), None, "{sym} is not a method symbol");
        assert!(!ObjC::detect(sym), "the detector must not claim {sym}");
    }
}
