//! A convention's separator or escape must behave the same at every occurrence.
//!
//! This is the shape that has actually failed here. OCaml split only the *first*
//! `__` for as long as anyone tested `camlList__map`, so
//! `camlStdlib__Printf__printf_42` read as `Stdlib.Printf__printf` — for years,
//! because the single-separator case is the one anybody writes first. D had the
//! same shape at a different scale: `Ng` was read as a type in every parameter
//! position except the first (`tests/d_attribute_positions.rs`).
//!
//! Both were found by asking one question — *is this construct handled the same
//! way in every position?* — and neither is guarded by a test defined over
//! repetition. This file is that guard, for the convention decoders.
//!
//! The tests are written over *generated* inputs with a growing number of
//! separators, and they assert structure rather than a hand-written expected
//! string: N separators must yield N+1 components. An implementation that
//! handles only the first separator produces fewer, whatever the names are.

fn rendered(sym: &str) -> String {
    rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode")).demangled
}

/// OCaml: `caml<A>__<B>__…__<fn>` — every `__` is a module boundary.
#[test]
fn ocaml_splits_every_double_underscore() {
    for depth in 1..=5 {
        let parts: Vec<String> = (0..depth).map(|i| format!("M{i}")).collect();
        let sym = format!("caml{}__fn", parts.join("__"));
        let out = rendered(&sym);

        let want = format!("{}.fn", parts.join("."));
        assert_eq!(out, want, "{sym}: {depth} module levels");
        assert!(!out.contains("__"), "{sym} leaked a separator: {out}");
    }
}

/// GNAT Ada: same separator, same rule, including behind the `_ada_` prefix —
/// the combination is what a single-level test never reaches.
#[test]
fn ada_splits_every_double_underscore() {
    for depth in 1..=5 {
        let parts: Vec<String> = (0..depth).map(|i| format!("p{i}")).collect();
        let base = format!("{}__proc", parts.join("__"));

        let out = rendered(&base);
        assert_eq!(out, format!("{}.proc", parts.join(".")), "{base}");
        assert!(!out.contains("__"), "{base} leaked a separator: {out}");

        // Prefixed form: the separator rule must not change because the symbol
        // gained a prefix handled by a different branch.
        let prefixed = format!("_ada_{base}");
        let out = rendered(&prefixed);
        assert!(
            out.starts_with(&format!("{}.proc", parts.join("."))),
            "{prefixed} rendered {out}"
        );
        assert!(!out.contains("__"), "{prefixed} leaked a separator: {out}");
    }
}

/// JNI escapes must decode in every component, not just the one that happened
/// to be tested. `_1` `_2` `_3` are `_` `;` `[`; `_0XXXX` is a code point.
#[test]
fn jni_escapes_decode_in_every_component() {
    for (escape, decoded) in [("_1", '_'), ("_2", ';'), ("_3", '['), ("_0002f", '/')] {
        let in_package = rendered(&format!("Java_a{escape}b_Cls_meth"));
        let in_class = rendered(&format!("Java_pkg_C{escape}D_meth"));
        let in_method = rendered(&format!("Java_pkg_Cls_m{escape}n"));

        assert_eq!(in_package, format!("a{decoded}b.Cls.meth"), "{escape} in package");
        assert_eq!(in_class, format!("pkg.C{decoded}D.meth"), "{escape} in class");
        assert_eq!(in_method, format!("pkg.Cls.m{decoded}n"), "{escape} in method");
    }
}

/// Repetition within one component, which is where an escape loop that handles
/// a single occurrence gives itself away.
#[test]
fn jni_escapes_repeat_within_a_component() {
    for count in 1..=4 {
        let escaped = "_1".repeat(count);
        let want = "_".repeat(count);
        let sym = format!("Java_pkg_Cls_m{escaped}n");
        assert_eq!(rendered(&sym), format!("pkg.Cls.m{want}n"), "{count} escapes");
    }
}

/// The counterpart to uniformity: more separators must not make a decoder
/// claim a name that is not its. A rule relaxed to handle repetition is the
/// obvious way to break this.
#[test]
fn repetition_does_not_widen_a_detector() {
    for sym in [
        // Leading underscores are C runtime symbols, at any depth.
        "__libc_start_main",
        "___a__b__c",
        // OCaml without its prefix is not OCaml.
        "List__map__inner",
        // A JNI-looking name that is not one: no class/method split.
        "Java_",
        "Java__1",
    ] {
        let claimed = rustre_demangle::demangle(sym)
            .is_some_and(|r| matches!(r.abi, rustre_demangle::ManglingAbi::Fortran));
        assert!(!claimed, "{sym} was claimed as Fortran");
    }
    // The specific historical false claim: a third leading underscore names a
    // module that cannot exist in Fortran.
    assert!(rustre_demangle::lang_extra::demangle_gfortran("___a_MOD_x").is_none());
}
