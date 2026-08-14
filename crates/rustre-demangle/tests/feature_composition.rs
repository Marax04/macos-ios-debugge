//! Features must compose: every one of them was tested ALONE.
//!
//! Iterations that probed features in isolation stopped finding anything;
//! iterations that probed pairings found a defect immediately — twice running:
//!
//! * **148**: Go generics × closures. A nested generic argument lost its outer
//!   type name and left an unbalanced bracket.
//! * **149**: clone suffixes × the convention ABIs. A JNI method was renamed to
//!   the clone tag (`function == "cold"`), and Swift lost both its operator
//!   suffix and the clone tag.
//!
//! Neither was reachable by testing either feature on its own. This file is the
//! standing guard for the combination surface, so the next feature added has to
//! survive contact with the others rather than only with the corpus.
//!
//! **Measured 2026-07-30: all pairs and triples below compose correctly.** The
//! two defects above are fixed; this pins that they stay fixed together.

fn ours(sym: &str) -> Option<String> {
    rustre_demangle::demangle(sym).map(|r| r.demangled)
}

/// Mach-O prefix × clone suffix, across every ABI that has both.
///
/// On an optimised macOS build these always appear together, and until now they
/// had only ever been tested apart (iters 125 and 127).
#[test]
fn the_mach_o_prefix_composes_with_clone_suffixes() {
    const PAIRS: &[(&str, &str)] = &[
        ("_D4main3fooFZv", "__D4main3fooFZv"),
        ("_ZN2ns4funcEv", "__ZN2ns4funcEv"),
        ("_RNvC1a1f", "__RNvC1a1f"),
        (
            "_ZN4core3fmt5write17h0123456789abcdefE",
            "__ZN4core3fmt5write17h0123456789abcdefE",
        ),
        ("$s4main3fooyyF", "_$s4main3fooyyF"),
        ("_TtC4main3Foo", "__TtC4main3Foo"),
        ("$s4main3fooyyFTA", "_$s4main3fooyyFTA"),
    ];
    let mut checked = 0;
    let mut differ = Vec::new();
    for (plain, macho) in PAIRS {
        for sfx in ["", ".cold", ".llvm.123", ".part.0"] {
            let a = rustre_demangle::demangle(&format!("{plain}{sfx}"));
            let b = rustre_demangle::demangle(&format!("{macho}{sfx}"));
            checked += 1;
            let same = match (&a, &b) {
                (Some(x), Some(y)) => {
                    x.demangled == y.demangled
                        && format!("{:?}", x.abi) == format!("{:?}", y.abi)
                }
                (None, None) => true,
                _ => false,
            };
            if !same {
                differ.push(format!(
                    "{plain}{sfx} => {:?} but {macho}{sfx} => {:?}",
                    a.map(|x| x.demangled),
                    b.map(|x| x.demangled)
                ));
            }
        }
    }
    assert!(checked >= 28, "vacuous: only {checked} pairs");
    assert!(differ.is_empty(), "{}", differ.join("\n"));
}

/// Every marker a symbol earns survives the presence of the others.
///
/// The iter-149 symptom was a marker vanishing under composition, which no
/// single-feature test could see.
#[test]
fn stacked_markers_all_survive() {
    for (sym, markers) in [
        ("$s4main3fooyyFTA.cold", vec!["[TA]", "[clone .cold]"]),
        ("$s4main3fooySaySiGF.cold", vec!["[unparsed ySaySiGF]", "[clone .cold]"]),
        (
            "$s4main3fooySaySiGFTA.cold",
            vec!["[unparsed ySaySiGFTA]", "[clone .cold]"],
        ),
        ("_ada_pkg__proc.part.0", vec!["[ada entry]", "[clone .part.0]"]),
        ("_D4main3Foo1mMFZ5innerFZv.cold", vec!["main.Foo.m().inner()", "[clone .cold]"]),
    ] {
        let out = ours(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        for m in markers {
            assert!(out.contains(m), "{sym} lost {m:?}: {out}");
        }
    }
}

/// Composition never costs the entity name.
///
/// `function` is the field iter 149 found holding `"cold"` and `"0"`.
#[test]
fn composition_never_renames_the_entity() {
    for (sym, function) in [
        ("$s4main3fooySaySiGF.cold", "foo"),
        ("_D4main3Foo1mMFZ5innerFZv.cold", "inner"),
        ("__D4main3fooFZ3barFZv.cold", "bar"),
        ("??$max@H@@YAHABH0@Z.cold", "max<int>"),
        ("_ada_pkg__proc.part.0", "proc"),
        ("_OBJC_$_INSTANCE_METHODS_Foo.cold", "Foo"),
        ("Java_com_foo_Bar_my_1method.cold", "my_method"),
        ("main.A[main.B[go.shape.int]].m.func2.3", "m"),
    ] {
        let r = rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert_eq!(r.function, function, "{sym} => {:?}", r.demangled);
    }
}

/// Composed symbols stay distinct from each other and from their parts.
///
/// Mach-O variants are excluded on purpose: `$s…` and `_$s…` are the SAME
/// symbol under Apple's convention, so rendering them alike is the property
/// asserted above, not a collision. A probe that forgot this reported a false
/// one.
#[test]
fn composed_symbols_do_not_collide() {
    let mut seen: std::collections::BTreeMap<String, &str> = std::collections::BTreeMap::new();
    let mut collisions = Vec::new();
    for sym in [
        "$s4main3fooyyF",
        "$s4main3fooyyFTA",
        "$s4main3fooyyFTA.cold",
        "$s4main3fooySaySiGF",
        "$s4main3fooySaySiGF.cold",
        "$s4main3fooySaySiGFTA",
        "$s4main3fooySaySiGFTA.cold",
        "_D4main3fooFZ3barFZv",
        "_D4main3fooFZ3barFZv.cold",
        "_D4main3Foo1mMFZ5innerFZv",
        "_D4main3Foo1mMFZ5innerFZv.cold",
        "main.A[main.B[go.shape.int]].m",
        "main.A[main.B[go.shape.int]].m.func1",
        "main.A[main.B[go.shape.int]].m.func2.3",
    ] {
        let out = ours(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        if let Some(prev) = seen.insert(out.clone(), sym) {
            collisions.push(format!("{prev} and {sym} both render {out}"));
        }
    }
    assert_eq!(seen.len(), 14, "{collisions:?}");
    assert!(collisions.is_empty(), "{}", collisions.join("\n"));
}

/// A combination that is not a real symbol shape still declines.
///
/// `_ada_<unit>` is the library entry and `<unit>___elabb` the elaboration; a
/// unit is one or the other, never both. Composition must not make the decoder
/// credulous.
#[test]
fn impossible_combinations_decline() {
    for sym in ["_ada_pkg___elabb", "_ada_pkg___elabs"] {
        assert_eq!(ours(sym), None, "{sym} is not a GNAT symbol shape");
    }
}
