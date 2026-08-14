//! Each language detector claims its own convention — and only that.
//!
//! `lang_extra`/`lang_more` carry roughly a dozen detectors keyed on naming
//! conventions rather than on a mangling sigil. One of them was found wrong on
//! 2026-07-23: Python 2's `init<module>` claimed the real corpus symbol
//! `initialized` and rendered it `python2 module init: ialized`, chopping a
//! word in half. It was removed from the generic dispatcher.
//!
//! **The corpora cannot cover the rest.** They contain zero symbols matching
//! `boot_`, `Init_`, `luaopen_`, `zif_`, `R_`, `napi`, `Java_` or `_MOD_`, so
//! a corpus invariant says nothing about these detectors. This suite probes
//! them directly — capability in one direction, restraint in the other.

use rustre_demangle::demangle;

fn rendered(s: &str) -> Option<String> {
    demangle(s).map(|r| r.demangled).filter(|d| d != s)
}

/// Each detector must still recognise its own convention. Guards against a
/// future sweep removing a rule that is doing real work — the mistake avoided
/// with `__Zoom`, where output that looked fabricated was correct.
#[test]
fn detectors_recognise_their_own_convention() {
    for (sym, needle) in [
        ("Init_mymodule", "mymodule"),         // Ruby extension init
        ("luaopen_socket", "socket"),          // Lua module open
        ("zif_count", "count"),                // PHP internal function
        ("mexFunction", "MEX"),                // MATLAB gateway
        ("_stdcall_helper@8", "stdcall_helper"), // Windows stdcall decoration
        ("__mod_MOD_thing", "thing"),          // gfortran module procedure
    ] {
        let got = rendered(sym).unwrap_or_else(|| panic!("{sym} should be recognised"));
        assert!(got.contains(needle), "{sym} -> {got}, expected to mention {needle}");
    }
}

/// Names outside every convention must stay declined. These are ordinary C
/// identifiers that superficially resemble a prefix without matching one.
#[test]
fn detectors_decline_names_outside_their_convention() {
    for s in [
        "Java_helper",        // no package/class/method structure
        "__cxa_throw",        // leading `__`, not `pkg__subprogram`
        "caml_stat_alloc",    // OCaml runtime, not `camlModule__fn`
        "stg_gc_info",        // GHC runtime, not Z-encoded
        "R_alloc",            // R's C API, not an R entry point
        "napi_get_value",     // Node's C API, not a napi module init
        "Tcl_AppInit",        // Tcl's C API, not `<pkg>_Init`
        "crypto_Init",
    ] {
        assert!(
            rendered(s).is_none(),
            "{s} is a plain C name and must be declined, got {:?}",
            rendered(s)
        );
    }
}

/// ACCEPTED AMBIGUITY, recorded rather than fixed.
///
/// Perl XS names its bootstrap `boot_<module>`, so `boot_strap` decodes as the
/// module `strap`. "bootstrap" is a common word and `boot_sector`-style C
/// names exist, which makes this the same shape as the Python 2 `init` bug.
///
/// It is NOT removed, and the difference from Python 2 is the evidence:
/// `initialized` was a *real corpus symbol* whose output was visibly garbled,
/// whereas `boot_strap` is a name constructed to expose the collision and its
/// output is structurally coherent. Deleting a working convention on a
/// hypothetical costs real capability. Revisit if a real binary ever shows a
/// `boot_`-prefixed C function being misread.
#[test]
fn perl_bootstrap_prefix_is_a_known_ambiguity() {
    let got = rendered("boot_strap").expect("the Perl XS convention still applies");
    assert!(got.contains("strap"), "got {got}");
}

/// Crystal's detector is loose on character content, and that is **recorded,
/// not fixed**.
///
/// Sweeping random printable ASCII, `detect_crystal` claims 76 of 20000
/// strings — anything starting with `*` that holds a `:` or `#` and has no
/// space before a `<`. Garbage like `*o~3)*@<Q\4F28d^e.iXBx9JBdA:` passes.
///
/// The obvious fix — restrict the path to identifier characters, as was done
/// for Go (iter 47) and Swift (iter 48) — **cannot be applied here**, and the
/// reason is measurable rather than a matter of caution. Crystal has operator
/// methods and Ruby-style suffixes, so all of these are plausible symbols:
///
/// ```text
/// *Foo::+<Int32>:Int32      *Foo::[]<Int32>:Int32     *Foo::<=><Int32>:Int32
/// *Foo::empty?<Int32>:Bool  *Foo::save!<Int32>:Nil
/// ```
///
/// An alphanumeric rule rejects every one. Nor can the rule be narrowed to
/// "obviously junk" characters: `%`, `|`, `^` and `~` appear in the random
/// garbage *and* are all Crystal operators.
///
/// Go and Swift were fixable because their permitted character sets could be
/// **measured** — 2163 real Go symbols, 38 sampled Swift identifiers. This
/// crate has no Crystal corpus and no Crystal oracle, so there is nothing to
/// measure against. Fixing it on inference would trade a loose detector for a
/// detector that silently drops operator methods.
///
/// This test pins what *is* certain: the structural rules already enforced, and
/// that the operator forms keep decoding, so a later charset rule added without
/// a corpus fails here.
#[test]
fn crystal_operator_methods_are_not_rejected() {
    use rustre_demangle::lang_more::modern_native::detect_crystal;

    for sym in [
        "*Foo::bar<Int32>:Nil",
        "*Foo::Bar::baz<Int32>:Nil",
        "*Foo::+<Int32>:Int32",
        "*Foo::[]<Int32>:Int32",
        "*Foo::<=><Int32>:Int32",
        "*Foo::empty?<Int32>:Bool",
        "*Foo::save!<Int32>:Nil",
    ] {
        assert!(
            detect_crystal(sym),
            "{sym} is a plausible Crystal symbol and must stay claimed"
        );
    }

    // The structural rules that *are* enforced, and must remain so.
    for sym in ["*", "*:", "*#", "*noColonOrHash", "*has space<T>:X"] {
        assert!(
            !detect_crystal(sym),
            "{sym:?} breaks a structural rule and must not be claimed"
        );
    }
}
