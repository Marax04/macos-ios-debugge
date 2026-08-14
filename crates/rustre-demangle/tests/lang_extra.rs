//! Integration tests for the additional-language demanglers
//! (`rustre_demangle::lang_extra`) and their routing through `demangle()`.

use rustre_demangle::{demangle, lang_extra, ManglingAbi};

#[test]
fn jni_symbols() {
    let cases = [
        ("Java_com_example_Foo_doThing", "com.example.Foo.doThing"),
        // `_1` unescapes to an underscore inside a name segment.
        ("Java_com_example_My_1Class_run", "com.example.My_Class.run"),
        // Overload signature after `__` is dropped from the readable form.
        (
            "Java_com_example_Foo_get__Ljava_lang_String_2",
            "com.example.Foo.get",
        ),
    ];
    for (sym, want) in cases {
        assert_eq!(lang_extra::demangle_jni(sym).as_deref(), Some(want), "{sym}");
        let r = demangle(sym).unwrap_or_else(|| panic!("dispatcher missed {sym}"));
        assert_eq!(r.demangled, want);
        assert_eq!(r.abi, ManglingAbi::Java);
    }
}

/// The JNI escape table has FOUR defined entries — `_1` `_2` `_3` and the
/// unicode escape `_0XXXX`. Applying the iters-95..98 rule (a table with N
/// inputs needs N test vectors) to all ten digits found two defects:
///
/// 1. `_4`..`_9` do not exist in the spec, and were rendered by treating the
///    `_` as the package separator and keeping the digit — `…Bar_a_4b` gave
///    `com.foo.Bar.a.4b`. `4b` cannot be a Java identifier (it starts with a
///    digit), so the output asserted a package component that cannot exist.
/// 2. `_0` is defined as exactly four hex digits, but `take(4)` yields fewer
///    when the input runs short and `from_str_radix` accepts a 1-3 digit
///    string, so a truncated escape silently swallowed the rest of the name:
///    `…Bar_a_0b` gave `com.foo.Bar.a`, losing the `b` with no complaint.
///
/// Discriminating, not merely obvious: `_1` and `_00024` pass whether or not
/// the digit table and the length rule are right. `_4b` and `_0b` separate a
/// correct implementation from a plausible one.
#[test]
fn jni_undefined_escapes_and_short_unicode_decline() {
    // The three defined single-digit escapes still decode.
    for (sym, want) in [
        ("Java_com_foo_Bar_a_1b", "com.foo.Bar.a_b"),
        ("Java_com_foo_Bar_a_2b", "com.foo.Bar.a;b"),
        ("Java_com_foo_Bar_a_3b", "com.foo.Bar.a[b"),
    ] {
        assert_eq!(lang_extra::demangle_jni(sym).as_deref(), Some(want), "{sym}");
    }

    // `_4`..`_9` are undefined: decline rather than invent a component.
    for d in '4'..='9' {
        let sym = format!("Java_com_foo_Bar_a_{d}b");
        assert_eq!(
            lang_extra::demangle_jni(&sym),
            None,
            "`_{d}` is not a JNI escape, so {sym} must not decode"
        );
        assert!(
            demangle(&sym).is_none_or(|r| r.abi != ManglingAbi::Java),
            "the dispatcher must not claim {sym} as Java either"
        );
    }

    // `_0` needs EXACTLY four hex digits; 1-3 is a truncated escape.
    for sym in [
        "Java_com_foo_Bar_a_0b",
        "Java_com_foo_Bar_a_00b",
        "Java_com_foo_Bar_a_002b",
    ] {
        assert_eq!(
            lang_extra::demangle_jni(sym),
            None,
            "{sym} carries fewer than four hex digits"
        );
    }

    // Four digits is well-formed and consumes exactly four — the `b` in
    // `_0024b` is the fourth digit, not a trailing literal.
    assert_eq!(
        lang_extra::demangle_jni("Java_com_foo_Bar_a_0024b").as_deref(),
        Some("com.foo.Bar.a\u{024b}")
    );
    // A surrogate continuation is length-checked the same way.
    assert_eq!(lang_extra::demangle_jni("Java_com_foo_Bar_a_0d83d_0de0"), None);

    // Controls: the documented shapes are untouched.
    for (sym, want) in [
        ("Java_com_foo_Bar_my_1method", "com.foo.Bar.my_method"),
        ("Java_com_foo_Bar_a_00024b", "com.foo.Bar.a$b"),
        ("Java_com_foo_Bar_baz", "com.foo.Bar.baz"),
    ] {
        assert_eq!(lang_extra::demangle_jni(sym).as_deref(), Some(want), "{sym}");
    }
}

/// Ada and Fortran identifiers must both begin with a LETTER, so a component
/// starting with an underscore names something the language cannot express.
///
/// Both decoders checked their components — Ada rejected empty and
/// digit-initial ones, gfortran rejected empty ones — and both stopped one
/// rule short, so a third underscore slipped through:
///
/// * `a___b` → `a._b` (an Ada identifier may only carry underscores *between*
///   alphanumerics, never leading)
/// * `___a_MOD_x` → `_a::x` (a Fortran module named `_a` cannot exist)
///
/// Discriminating: `ada__text_io__put_line` and `__mymod_MOD_solve` pass
/// whether or not the leading-underscore rule is present — they are the cases
/// anyone writes first. The three-underscore inputs are what separate a
/// correct implementation from a plausible one.
///
/// Deliberately NOT asserted: `__A_MOD_X` still decodes. gfortran lowercases
/// identifiers, so an uppercase module is not its output — but that is a
/// compiler convention, not a rule of the language, and no oracle exists to
/// settle it. Declining on case would be a guess; declining on a leading
/// underscore is the standard.
#[test]
fn ada_and_fortran_components_must_start_with_a_letter() {
    for sym in ["a___b", "a____b", "a__b__2", "a__2b", "_ada_main"] {
        assert_eq!(
            lang_extra::demangle_gnat_ada(sym),
            None,
            "{sym} carries a component that is not an Ada identifier"
        );
        assert!(
            !lang_extra::detect_gnat_ada(sym),
            "the detector must not claim {sym} either"
        );
    }
    for sym in ["___a_MOD_x", "___MOD_x", "__a_MOD_"] {
        assert_eq!(
            lang_extra::demangle_gfortran(sym),
            None,
            "{sym} carries a component that is not a Fortran identifier"
        );
        // A detector looser than its backend claims symbols nothing decodes.
        assert!(
            !lang_extra::detect_gfortran(sym),
            "detect_gfortran must stay in step with demangle_gfortran on {sym}"
        );
    }

    // Controls: the documented shapes are untouched, detector included.
    for (sym, want) in [
        ("ada__text_io__put_line", "ada.text_io.put_line"),
        ("a__b__c__d", "a.b.c.d"),
    ] {
        assert_eq!(lang_extra::demangle_gnat_ada(sym).as_deref(), Some(want));
        assert!(lang_extra::detect_gnat_ada(sym));
    }
    assert_eq!(
        lang_extra::demangle_gfortran("__mymod_MOD_solve").as_deref(),
        Some("mymod::solve")
    );
    assert!(lang_extra::detect_gfortran("__mymod_MOD_solve"));
    // A trailing underscore IS legal in both languages — do not over-reject.
    assert_eq!(
        lang_extra::demangle_gfortran("__a_MOD_x_").as_deref(),
        Some("a::x_")
    );
}

#[test]
fn gfortran_symbols() {
    assert_eq!(
        lang_extra::demangle_gfortran("__linalg_MOD_solve").as_deref(),
        Some("linalg::solve")
    );
    let r = demangle("__linalg_MOD_solve").expect("dispatcher");
    assert_eq!(r.abi, ManglingAbi::Fortran);
}

#[test]
fn gnat_ada_symbols() {
    assert_eq!(
        lang_extra::demangle_gnat_ada("ada__text_io__put_line").as_deref(),
        Some("ada.text_io.put_line")
    );
    // C runtime names with leading underscores must not match.
    assert!(lang_extra::demangle_gnat_ada("__libc_start_main").is_none());
    assert!(lang_extra::demangle_gnat_ada("pthread_mutex_lock").is_none());
}

#[test]
fn ocaml_symbols() {
    assert_eq!(
        lang_extra::demangle_ocaml("camlList__map_271").as_deref(),
        Some("List.map")
    );
    assert_eq!(
        lang_extra::demangle_ocaml("camlStdlib__printf_1423").as_deref(),
        Some("Stdlib.printf")
    );
    // `calloc` and other C names starting with `cal` must not match.
    assert!(!lang_extra::detect_ocaml("calloc"));
}

#[test]
fn ghc_symbols() {
    assert_eq!(
        lang_extra::demangle_ghc("base_GHCziBase_map_info").as_deref(),
        Some("base:GHC.Base.map (info)")
    );
    // z-encoding: `zu` = underscore, `zd` = dollar.
    assert_eq!(lang_extra::zdecode("fooziBarzubaz"), "foo.Bar_baz");
}

#[test]
fn c_decorated_symbols() {
    assert_eq!(
        lang_extra::demangle_c_decorated("_MessageBoxA@16").as_deref(),
        Some("MessageBoxA")
    );
    assert_eq!(
        lang_extra::demangle_c_decorated("@fastfn@8").as_deref(),
        Some("fastfn")
    );
    // MSVC C++ symbols must not match.
    assert!(!lang_extra::detect_c_decorated("?foo@@YAHH@Z"));
}

/// The new demanglers must not steal symbols that belong to the core ABIs.
#[test]
fn does_not_shadow_core_abis() {
    for (sym, abi) in [
        ("_Z3fooi", ManglingAbi::Itanium),
        ("?foo@@YAHH@Z", ManglingAbi::Msvc),
        ("_RNvCs1234_7mycrate3foo", ManglingAbi::Rust),
        ("_D4main3fooFZv", ManglingAbi::D),
        ("main.main", ManglingAbi::Go),
    ] {
        let r = demangle(sym).unwrap_or_else(|| panic!("dispatcher missed {sym}"));
        assert_eq!(r.abi, abi, "{sym} routed to the wrong ABI");
    }
}
