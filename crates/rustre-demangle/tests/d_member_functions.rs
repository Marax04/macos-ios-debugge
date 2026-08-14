//! Every non-static D method declined.
//!
//! `M` marks a **member function** and precedes the calling-convention sigil:
//! `_D4main3Foo3barMFZv` is `void main.Foo.bar()`. The demangler handled `M`
//! only as a *parameter* storage class (`scope`), never in the symbol's own
//! type position, so the top-level dispatch — which matches
//! `F`/`U`/`W`/`V`/`R`/`Y` — never saw a convention sigil and the whole symbol
//! fell out as `DeclineReason::UnsupportedAbi`.
//!
//! That is the variant this crate treats as its only real defect signal, and it
//! covers an enormous share of any real D binary: every instance method.
//!
//! Found by the per-variant sweep applied to D's compiler-generated families
//! (`__ModuleInfo`, `TypeInfo_*`, `__init`, `__vtbl`, `__Class`, `__Interface`,
//! the four `extern` conventions). All of those were already correct; the
//! plainest form of all — a class method — was not.
//!
//! **Prefixes are computed, never hand-counted.** The first run of this probe
//! hand-wrote `_D11TypeInfo_i…` for a 10-character name and reported a phantom
//! defect. Fourth time in this session; the generator below removes the
//! possibility.

/// Build a D symbol from components, computing every length prefix.
fn d(parts: &[&str], tail: &str) -> String {
    let mut s = String::from("_D");
    for p in parts {
        use std::fmt::Write as _;
        let _ = write!(s, "{}{p}", p.len());
    }
    s.push_str(tail);
    s
}

fn ours(sym: &str) -> Option<String> {
    rustre_demangle::demangle(sym).map(|r| r.demangled)
}

/// A member function decodes, under every calling convention.
///
/// Discriminating: the same symbol without `M` decoded before this fix — it is
/// the case the existing tests covered. `M` is what separates a decoder for D's
/// function grammar from one for its non-member subset.
#[test]
fn member_functions_decode() {
    let base = ["main", "Foo", "bar"];
    for (tail, want) in [
        ("MFZv", "void main.Foo.bar()"),
        ("MFiZi", "int main.Foo.bar(int)"),
        ("MUiZi", "extern(C) int main.Foo.bar(int)"),
        ("MWiZi", "extern(Windows) int main.Foo.bar(int)"),
        ("MRiZi", "extern(C++) int main.Foo.bar(int)"),
        ("MFNaNbZv", "void main.Foo.bar() pure nothrow"),
    ] {
        let sym = d(&base, tail);
        assert_eq!(ours(&sym).as_deref(), Some(want), "{sym}");
    }
}

/// The member qualifiers are rendered, not merely consumed.
///
/// Consuming them would make `barMxFZv` (a const method) and `barMFZv` render
/// identically — two different D functions, one output. This is the collision
/// the first version of the fix introduced, and it is why the qualifiers are
/// spelled in D's own trailing-keyword syntax rather than dropped.
#[test]
fn member_qualifiers_are_rendered_and_stay_distinct() {
    let base = ["main", "Foo", "bar"];
    let mut seen: std::collections::BTreeMap<String, &str> = std::collections::BTreeMap::new();
    for tail in ["MFZv", "MxFZv", "MyFZv", "MOFZv", "MNgFZv", "MxFNaZv"] {
        let sym = d(&base, tail);
        let out = ours(&sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert!(
            seen.insert(out.clone(), tail).is_none(),
            "{tail} collides with an earlier qualifier: {out}"
        );
    }
    assert_eq!(seen.len(), 6);

    for (tail, want) in [
        ("MxFZv", "void main.Foo.bar() const"),
        ("MyFZv", "void main.Foo.bar() immutable"),
        ("MOFZv", "void main.Foo.bar() shared"),
        ("MNgFZv", "void main.Foo.bar() inout"),
        ("MxFNaZv", "void main.Foo.bar() const pure"),
    ] {
        assert_eq!(ours(&d(&base, tail)).as_deref(), Some(want), "{tail}");
    }
}

/// Nothing a `M` symbol produces may report `UnsupportedAbi`.
///
/// Stated over `decline_reason` rather than a symbol list: the defect was not
/// a wrong rendering but a claimed-and-declined shape, so this is the property
/// that was actually violated.
#[test]
fn member_functions_report_no_unsupported_abi() {
    let mut checked = 0;
    for tail in ["MFZv", "MFiZi", "MxFZv", "MyFZv", "MOFZv", "MNgFZv", "MUiZi", "MFNaNbZv"] {
        let sym = d(&["main", "Foo", "bar"], tail);
        checked += 1;
        assert_eq!(
            format!("{:?}", rustre_demangle::decline::decline_reason(&sym)),
            "Decoded",
            "{sym}"
        );
    }
    assert!(checked >= 8, "vacuous: only {checked}");
}

/// D's compiler-generated families, which the sweep confirmed were already
/// right — pinned so the `M` change cannot have disturbed them.
#[test]
fn compiler_generated_families_still_decode() {
    for (parts, tail, want) in [
        (&["main", "__ModuleInfo"][..], "Z", "main.__ModuleInfo"),
        (&["TypeInfo_i", "__init"][..], "Z", "TypeInfo_i.__init"),
        (&["main", "Foo", "__vtbl"][..], "Z", "main.Foo.__vtbl"),
        (&["main", "S", "__Class"][..], "Z", "main.S.__Class"),
        (&["main", "Foo", "__Interface"][..], "Z", "main.Foo.__Interface"),
        (&["main", "__unittest"][..], "FZv", "void main.__unittest()"),
    ] {
        let sym = d(parts, tail);
        assert_eq!(ours(&sym).as_deref(), Some(want), "{sym}");
    }
}

/// Attributes belong AFTER the convention sigil; before it is malformed.
///
/// `MNaNbFZv` looks plausible and is not D — the ABI writes
/// `CallConvention FuncAttrs`. An earlier version of the fix consumed the
/// bytes and accepted it, which is accepting a symbol no compiler emits.
#[test]
fn attributes_before_the_convention_are_malformed() {
    assert_eq!(ours(&d(&["main", "Foo", "bar"], "MNaNbFZv")), None);
    assert_eq!(ours(&d(&["main", "Foo", "bar"], "MNaFZv")), None);
    // The well-formed ordering decodes.
    assert_eq!(
        ours(&d(&["main", "Foo", "bar"], "MFNaNbZv")).as_deref(),
        Some("void main.Foo.bar() pure nothrow")
    );
}
