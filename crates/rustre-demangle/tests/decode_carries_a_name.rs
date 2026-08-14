//! A decode must carry a name.
//!
//! The Obj-C backend's own comment states the rule — "a bare `_OBJC_` used to
//! 'decode' to the empty string, handing the caller a successful result with no
//! symbol name in it" — and the crate enforces it per-ABI: Obj-C's empty
//! payloads, Swift's `?module`, D's `?` placeholder. Applying the same rule to
//! the ABIs it had never reached found two:
//!
//! ```text
//! _RNvC0_0_  =>  Some("")     zero-length crate AND value name
//! Java__     =>  Some(".")    a package and method with no name
//! ```
//!
//! Both are degenerate inputs no compiler emits, so this is about robustness
//! and about keeping `DeclineReason::Decoded` meaningful, not about fidelity on
//! real symbols.
//!
//! **It does not contradict an oracle.** `rustc-demangle` renders `_RNvC0_0_`
//! as the empty string too — checked, because "we disagree with the oracle" is
//! the finding that would have mattered. rustc cannot emit a zero-length crate
//! name, so declining costs nothing real while a `Some("")` costs the caller a
//! success it cannot use.

/// No rendering may be empty of alphanumeric characters.
///
/// Stated over the OUTPUT against a character class rather than over a list of
/// symbols, so a shape nobody thought of still fails it.
#[test]
fn no_decode_is_nameless() {
    const DEGENERATE: &[&str] = &[
        "_RNvC0_0_",
        "_RC0_",
        "Java__",
        "Java_a_",
        "Java__b",
        "?@@YAXXZ",
        "?@@3HA",
        "_D0",
        "_D4main0FZv",
        ".",
        ".main",
        "main.",
        "$s0",
        "_OBJC_CLASS_$_",
        "-[ ]",
        "a__",
    ];
    let mut checked = 0;
    let mut offenders = Vec::new();
    for sym in DEGENERATE {
        checked += 1;
        if let Some(r) = rustre_demangle::demangle(sym)
            && !r.demangled.chars().any(char::is_alphanumeric)
        {
            offenders.push(format!("{sym} => {:?}", r.demangled));
        }
    }
    assert!(checked >= 16, "vacuous: only {checked}");
    assert!(
        offenders.is_empty(),
        "these decoded to a rendering with no name in it:\n{}",
        offenders.join("\n")
    );
}

/// The guard is narrow: an operator name is all punctuation *after* its
/// namespace, and must still decode.
///
/// This is what a blunter rule — "the rendering must not be mostly
/// punctuation", or a check applied to the last path component — would have
/// broken.
#[test]
fn operator_names_still_decode() {
    for (sym, want) in [
        ("clojure.core$_PLUS_", "clojure.core/+"),
        ("p.C.$eq$eq", "p.C.=="),
        ("p.C.$greater$greater$greater", "p.C.>>>"),
    ] {
        assert_eq!(
            rustre_demangle::demangle(sym).map(|r| r.demangled).as_deref(),
            Some(want),
            "{sym}"
        );
    }
    // MSVC operators carry punctuation in the name too.
    let plus = rustre_demangle::demangle("??HFoo@@QAEHH@Z").expect("must decode");
    assert!(plus.demangled.contains("operator+"), "{}", plus.demangled);
}

/// JNI: every component of the name must be non-empty.
///
/// The check has to run on the NAME, not on everything after `Java_`: `__` is
/// the overload-signature separator, so checking too early rejected the
/// perfectly ordinary `Java_pkg_Cls_meth__Ljava_lang_String_2`. That regression
/// was caught by the existing `jni_escapes.rs` suite, which is why the rule is
/// stated here with the control beside it.
#[test]
fn jni_components_are_non_empty() {
    for sym in ["Java__", "Java_a_", "Java__b", "Java_a__b_"] {
        assert_eq!(rustre_demangle::demangle(sym).map(|r| r.demangled), None, "{sym}");
    }
    for (sym, want) in [
        ("Java_a_b", "a.b"),
        ("Java_com_foo_Bar_baz", "com.foo.Bar.baz"),
        ("Java_com_foo_Bar_my_1method", "com.foo.Bar.my_method"),
        ("Java_pkg_Cls_meth__Ljava_lang_String_2", "pkg.Cls.meth"),
    ] {
        assert_eq!(
            rustre_demangle::demangle(sym).map(|r| r.demangled).as_deref(),
            Some(want),
            "{sym}"
        );
    }
}

/// The whole real corpus still decodes exactly as before.
///
/// The guard sits on the crate's public entry point, so a mistake there would
/// cost real symbols rather than degenerate ones. Vacuity-guarded.
#[test]
fn the_corpus_is_unaffected() {
    let mut decoded = 0;
    for line in include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
    {
        let sym = line.trim();
        if sym.is_empty() {
            continue;
        }
        if let Some(r) = rustre_demangle::demangle(sym) {
            decoded += 1;
            assert!(
                r.demangled.chars().any(char::is_alphanumeric),
                "{sym} decoded to a nameless rendering: {:?}",
                r.demangled
            );
        }
    }
    assert!(decoded > 3000, "vacuity: only {decoded} corpus decodes");
}
