//! The structured fields must name PARTS of the symbol, not the whole of it.
//!
//! `tests/structured_consistency.rs` requires a field to appear inside the
//! rendering, and `split_convention_rendering`'s own doc comment records why
//! that is too weak: "an empty field is vacuously contained, and the full
//! string is contained literally", so two opposite wrong implementations both
//! passed it. Checking the fields against a stronger property found two ABIs
//! still failing in exactly those two ways:
//!
//! ```text
//! ?bar@Foo@@QAEXXZ     class     = "public: void __thiscall Foo"
//! ?bar@Foo@Ns@@QAEXXZ  namespace = "public: void __thiscall Ns"
//! -[Foo bar]           function  = "-[Foo bar]"          (the whole rendering)
//! ```
//!
//! Consumers route on these fields — the decompiler names variables from them —
//! so `class: "public: void __thiscall Foo"` is not cosmetic.
//!
//! **MSVC:** the "entity is the last whitespace-separated token" rule already
//! existed for `function`; it simply was not applied to the leading scope,
//! where the access specifier, return type and calling convention live.
//!
//! **Obj-C:** it was going through the *convention prose* splitter, which finds
//! no separator in `-[Foo bar]` and hands back the whole string. It has its own
//! extraction now.
//!
//! **One rule, three copies.** The first attempt at the MSVC fix edited the
//! wrong one: that `match parts.len()` block is duplicated three times in
//! `backends.rs` (Itanium, MSVC, and a third path), and a string replace hit
//! the Itanium one. Reverted and re-applied by locating the block *after*
//! `fn split_msvc_components`. This is the crate's own headline defect shape,
//! encountered while fixing a different instance of it.

fn fields(sym: &str) -> (Option<String>, Option<String>, String, String) {
    let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
    (r.namespace, r.class, r.function, r.demangled)
}

/// No field may be empty, and none may be the whole rendering.
///
/// Stated over a cross-ABI sample rather than per-ABI, because the defect was
/// the same shape in two unrelated backends.
#[test]
fn no_field_is_empty_or_the_whole_rendering() {
    const SYMBOLS: &[&str] = &[
        "_Z3fooi",
        "?bar@Foo@@QAEXXZ",
        "?foo@@YAXXZ",
        "?bar@Foo@Ns@@QAEXXZ",
        "_RNvNtC4core3fmt5write",
        "_ZN4core3fmt5write17h0123456789abcdefE",
        "_D4main3Foo3barMFZv",
        "$s4main3fooyyF",
        "sync.(*Mutex).Lock",
        "fmt.Println",
        "-[Foo bar]",
        "+[NSObject alloc]",
        "_OBJC_CLASS_$_Foo",
        "Java_com_foo_Bar_baz",
        "pkg__proc",
    ];
    let mut checked = 0;
    let mut offenders = Vec::new();
    for sym in SYMBOLS {
        let (ns, class, function, rendering) = fields(sym);
        checked += 1;
        if function.is_empty() {
            offenders.push(format!("{sym}: empty function"));
        }
        if function == rendering {
            offenders.push(format!("{sym}: function is the whole rendering ({function})"));
        }
        for (label, v) in [("namespace", &ns), ("class", &class)] {
            if let Some(v) = v {
                if v.is_empty() {
                    offenders.push(format!("{sym}: empty {label}"));
                }
                if *v == rendering {
                    offenders.push(format!("{sym}: {label} is the whole rendering"));
                }
            }
        }
    }
    assert!(checked >= 15, "vacuous: only {checked}");
    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}

/// No field may carry a type, an access specifier or a calling convention.
///
/// This is what "contained in the rendering" could never catch: every offending
/// value was a genuine substring of the output.
#[test]
fn no_field_carries_signature_text() {
    const NOISE: &[&str] = &[
        "public:", "private:", "protected:", "static ", "virtual ",
        "__thiscall", "__cdecl", "__stdcall", "void ", "int ",
    ];
    let mut checked = 0;
    for sym in [
        "?bar@Foo@@QAEXXZ",
        "?bar@Foo@Ns@@QAEXXZ",
        "?foo@@YAXXZ",
        "??0Foo@@QAE@XZ",
        "?x@?$V@H@@2HA",
        "_D4main3Foo3barMFZv",
        "$s4main3fooyyF",
    ] {
        let (ns, class, function, _) = fields(sym);
        checked += 1;
        for (label, v) in [
            ("namespace", ns),
            ("class", class),
            ("function", Some(function)),
        ] {
            let Some(v) = v else { continue };
            for n in NOISE {
                assert!(
                    !v.contains(n),
                    "{sym}: {label} = {v:?} carries signature text {n:?}"
                );
            }
        }
    }
    assert!(checked >= 7, "vacuous: only {checked}");
}

/// The MSVC fields name what they say they name.
#[test]
fn msvc_fields_are_the_scope_and_the_entity() {
    for (sym, ns, class, function) in [
        ("?bar@Foo@@QAEXXZ", None, Some("Foo"), "bar"),
        ("?bar@Foo@Ns@@QAEXXZ", Some("Ns"), Some("Foo"), "bar"),
        ("?foo@@YAXXZ", None, None, "foo"),
    ] {
        let (got_ns, got_class, got_fn, _) = fields(sym);
        assert_eq!(got_ns.as_deref(), ns, "{sym} namespace");
        assert_eq!(got_class.as_deref(), class, "{sym} class");
        assert_eq!(got_fn, function, "{sym} function");
    }
}

/// The Obj-C fields split the method syntax into its two parts.
#[test]
fn objc_fields_split_class_from_selector() {
    for (sym, class, function) in [
        ("-[Foo bar]", Some("Foo"), "bar"),
        ("+[NSObject alloc]", Some("NSObject"), "alloc"),
        ("-[NSString(Cat) length]", Some("NSString(Cat)"), "length"),
        ("-[Foo]", None, "Foo"),
        ("_OBJC_CLASS_$_Foo", None, "Foo"),
        ("_OBJC_IVAR_$_MyClass._count", Some("MyClass"), "_count"),
        ("_OBJC_PROTOCOL_$_NSCopying", None, "NSCopying"),
    ] {
        let (_, got_class, got_fn, _) = fields(sym);
        assert_eq!(got_class.as_deref(), class, "{sym} class");
        assert_eq!(got_fn, function, "{sym} function");
    }
}

/// Every field must still be a substring of the rendering — the old, weaker
/// property, kept so the fix cannot have invented content.
#[test]
fn every_field_still_comes_from_the_rendering() {
    let mut checked = 0;
    for line in include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
    {
        let sym = line.trim();
        if sym.is_empty() {
            continue;
        }
        let Some(r) = rustre_demangle::demangle(sym) else {
            continue;
        };
        checked += 1;
        for (label, v) in [
            ("namespace", r.namespace.clone()),
            ("class", r.class.clone()),
            ("function", Some(r.function.clone())),
        ] {
            let Some(v) = v else { continue };
            assert!(
                r.demangled.contains(&v),
                "{sym}: {label} {v:?} is not part of {:?}",
                r.demangled
            );
        }
    }
    assert!(checked > 3000, "vacuity: only {checked} corpus decodes");
}
