//! LLVM's `ThinLTO` suffix `.llvm.<number>` was missing from the clone table.
//!
//! `split_clone_suffix` knew `isra`, `part`, `constprop`, `lto_priv`, `cold`
//! and `localalias` — and every one of them worked, which is exactly what made
//! the gap invisible. `.llvm.<hash>` is emitted by `ThinLTO` on ordinary
//! optimised builds and was not recognised, so a suffixed symbol was not
//! identified as a C-family name and fell through to the **permissive Go
//! detector**, which claims anything containing a dot:
//!
//! ```text
//! _D4main3fooFZv.llvm.1234567890   =>  abi Go, "_D4main3fooFZv.llvm.1234567890"
//! _TtC4main3Foo.llvm.1234567890    =>  abi Go, "_TtC4main3Foo.llvm.1234567890"
//! ```
//!
//! The ABI was wrong and the "demangling" was the raw mangled symbol echoed
//! back — the failure mode `split_clone_suffix`'s own doc warns about for
//! `.isra.0`, reached through a tag the table did not list.
//!
//! **The tag is guarded by a numeric-index test**, unlike the others: `llvm` is
//! a plausible Go package or type name, while `.llvm.` followed by a decimal
//! number is not. `llvm.Parse`, `main.llvm.Foo` and
//! `tinygo.org/x/go-llvm.Value` all stay Go.
//!
//! Found by the per-variant sweep, applied to the suffixed forms of D and
//! Swift — the gap iter 127 explicitly left open.

fn abi_of(sym: &str) -> Option<String> {
    rustre_demangle::demangle(sym).map(|r| format!("{:?}", r.abi))
}

fn ours(sym: &str) -> Option<String> {
    rustre_demangle::demangle(sym).map(|r| r.demangled)
}

/// A `ThinLTO` suffix changes neither the ABI nor the decoded name.
///
/// Discriminating: `.cold` and `.part.0` pass either way — they were already in
/// the table. `.llvm.1234567890` is what separates a complete table from one
/// that merely looks complete.
#[test]
fn a_thinlto_suffix_changes_neither_abi_nor_name() {
    let bases = [
        ("_D4main3fooFZv", "D", "void main.foo()"),
        ("__D4main3fooFZv", "D", "void main.foo()"),
        ("_TtC4main3Foo", "Swift", "class main.Foo"),
    ];
    for (base, abi, name) in bases {
        assert_eq!(abi_of(base).as_deref(), Some(abi), "{base}");
        for sfx in [".cold", ".part.0", ".llvm.1234567890", ".constprop.0"] {
            let sym = format!("{base}{sfx}");
            assert_eq!(abi_of(&sym).as_deref(), Some(abi), "{sym}");
            let out = ours(&sym).unwrap_or_else(|| panic!("{sym} must decode"));
            assert!(out.starts_with(name), "{sym} lost its name: {out}");
            assert!(
                !out.contains(base),
                "the raw mangling was echoed instead of decoded: {out}"
            );
        }
    }
}

/// The suffix is reported, not silently dropped — distinct clones stay
/// distinct.
#[test]
fn distinct_clones_render_distinctly() {
    let base = "_D4main3fooFZv";
    let mut seen = std::collections::BTreeSet::new();
    for sfx in ["", ".cold", ".part.0", ".llvm.1234567890", ".llvm.9999999999"] {
        let out = ours(&format!("{base}{sfx}")).unwrap_or_else(|| panic!("{base}{sfx}"));
        assert!(seen.insert(out.clone()), "{sfx} collided: {out}");
    }
    assert_eq!(seen.len(), 5);
}

/// A Go name containing `llvm` is not a clone.
///
/// The numeric-index test is what makes this true, and it is the reason `llvm`
/// sits in its own table rather than beside `isra` and `part`.
#[test]
fn go_names_containing_llvm_stay_go() {
    for sym in [
        "llvm.Parse",
        "main.llvm.Foo",
        "tinygo.org/x/go-llvm.Value",
        "github.com/llvm/x.F",
        "main.llvm",
    ] {
        assert_eq!(abi_of(sym).as_deref(), Some("Go"), "{sym}");
        assert_eq!(ours(sym).as_deref(), Some(sym), "{sym} must round-trip");
    }
}

/// The tags that already worked must keep working — the table was extended,
/// not rewritten.
#[test]
fn the_pre_existing_clone_tags_are_unchanged() {
    // A mangled base still decodes.
    for sym in [
        "_D4main3fooFZv.constprop.0",
        "_D4main3fooFZv.lto_priv.1",
        "_D4main3fooFZv.localalias",
    ] {
        assert_eq!(abi_of(sym).as_deref(), Some("D"), "{sym}");
    }
    // A plain C base has nothing to demangle, so it declines — but it must not
    // be claimed by Go, which is the failure `split_clone_suffix` exists to
    // prevent (`__pformat_int.isra {closure-1 #?}`). Asserting a decode here
    // was my error: the guarantee is about the routing, not the decoding.
    for sym in ["__pformat_int.isra.0", "some_c_function.part.0"] {
        assert_eq!(rustre_demangle::demangle(sym), None, "{sym}");
        assert_ne!(
            format!("{:?}", rustre_demangle::decline::decline_reason(sym)),
            "UnsupportedAbi",
            "{sym} is a C name, not an unhandled ABI"
        );
    }
}
