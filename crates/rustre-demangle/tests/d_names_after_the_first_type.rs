//! D names that appear AFTER the first type code.
//!
//! `d_completeness.rs` states its own blind spot: its extractor is `_D` followed
//! by consecutive `<len><chars>` pairs and **stops at the first non-digit**,
//! because a digit in *type* position is a grammar number rather than a length
//! (`FG3iZv` is an array dimension, `FB2iiZv` a tuple count). That scoping is
//! right — a general extractor is impossible without parsing D — but it leaves
//! every name past the first type unchecked, and that is where two of this
//! session's features live: nested functions (iter 130) and the member marker
//! (iter 129).
//!
//! This suite reaches that region the only way that is sound: **constructed**
//! symbols, where the expected names are known because the test built them.
//! Prefixes are computed, never hand-counted — eight of this session's false
//! findings came from miscounting one.
//!
//! **Measured 2026-07-30: 15 shapes, zero lost names, no collisions. No
//! defect.** This file is the guard.

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

/// The body of `d(...)`, for embedding one symbol's name inside another.
fn body(parts: &[&str], tail: &str) -> String {
    d(parts, tail)[2..].to_owned()
}

/// `(description, symbol, every name that must reappear)`.
fn cases() -> Vec<(&'static str, String, Vec<&'static str>)> {
    vec![
        // Names after an enclosing function's type — the iter-130 production.
        ("nested fn", d(&["main", "foo"], &format!("FZ{}", body(&["bar"], "FZv"))), vec!["main", "foo", "bar"]),
        (
            "nested twice",
            d(&["main", "foo"], &format!("FZ{}", body(&["bar"], &format!("FZ{}", body(&["baz"], "FZv"))))),
            vec!["main", "foo", "bar", "baz"],
        ),
        (
            "nested in method",
            d(&["main", "Foo", "m"], &format!("MFZ{}", body(&["inner"], "FZv"))),
            vec!["main", "Foo", "m", "inner"],
        ),
        // Names inside TYPES — the other half of the blind region.
        ("class param", d(&["main", "foo"], "FC4main3BarZv"), vec!["main", "foo", "Bar"]),
        ("struct param", d(&["main", "foo"], "FS4main3BazZv"), vec!["main", "foo", "Baz"]),
        ("enum param", d(&["main", "foo"], "FE4main4KindZv"), vec!["main", "foo", "Kind"]),
        ("class return", d(&["main", "foo"], "FZC4main3Qux"), vec!["main", "foo", "Qux"]),
        ("two class args", d(&["main", "foo"], "FC4main1AC4main1BZv"), vec!["main", "foo", "A", "B"]),
        ("pointer to class", d(&["main", "foo"], "FPC4main3BarZv"), vec!["main", "foo", "Bar"]),
        ("array of class", d(&["main", "foo"], "FAC4main3BarZv"), vec!["main", "foo", "Bar"]),
        ("assoc array", d(&["main", "foo"], "FHC4main1KC4main1VZv"), vec!["main", "foo", "K", "V"]),
        ("delegate param", d(&["main", "foo"], "FDFC4main3BarZvZv"), vec!["main", "foo", "Bar"]),
        ("const class", d(&["main", "foo"], "FxC4main3BarZv"), vec!["main", "foo", "Bar"]),
        ("static array", d(&["main", "foo"], "FG4C4main3BarZv"), vec!["main", "foo", "Bar"]),
        // Both at once: a class-typed parameter on an ENCLOSING function, which
        // exercises iter 130's speculative parse together with a named type.
        (
            "nested with class arg",
            d(&["main", "foo"], &format!("FC4main3ArgZ{}", body(&["bar"], "FZv"))),
            vec!["main", "foo", "Arg", "bar"],
        ),
    ]
}

/// Every expected name reaches the rendering.
#[test]
fn no_name_after_the_first_type_is_lost() {
    let cases = cases();
    let mut checked = 0;
    let mut losses = Vec::new();
    for (what, sym, names) in &cases {
        let Some(out) = rustre_demangle::demangle(sym).map(|r| r.demangled) else {
            losses.push(format!("{what}: {sym} does not decode"));
            continue;
        };
        checked += 1;
        for n in names {
            if !out.contains(n) {
                losses.push(format!("{what}: {sym} lost {n:?} — rendered {out}"));
            }
        }
    }
    assert!(checked >= 15, "vacuous: only {checked} shapes decoded");
    assert!(losses.is_empty(), "{}", losses.join("\n"));
}

/// The shapes stay distinct from one another.
///
/// Completeness alone cannot catch a merge: two symbols can each contain all
/// their names and still render alike.
#[test]
fn the_shapes_do_not_collide() {
    let mut seen: std::collections::BTreeMap<String, &str> = std::collections::BTreeMap::new();
    let mut collisions = Vec::new();
    for (what, sym, _) in &cases() {
        let Some(out) = rustre_demangle::demangle(sym).map(|r| r.demangled) else {
            continue;
        };
        if let Some(prev) = seen.insert(out.clone(), what) {
            collisions.push(format!("{prev} and {what} both render {out}"));
        }
    }
    assert!(seen.len() >= 15, "vacuous: only {} decoded", seen.len());
    assert!(collisions.is_empty(), "{}", collisions.join("\n"));
}

/// The renderings are the D spellings, not merely name-complete.
///
/// Discriminating: a decoder that dumped every name into a flat list would pass
/// the completeness test above. These pin the structure.
#[test]
fn the_renderings_are_d_syntax() {
    for (sym, want) in [
        (d(&["main", "foo"], "FC4main3BarZv"), "void main.foo(main.Bar)"),
        (d(&["main", "foo"], "FPC4main3BarZv"), "void main.foo(main.Bar*)"),
        (d(&["main", "foo"], "FAC4main3BarZv"), "void main.foo(main.Bar[])"),
        (d(&["main", "foo"], "FG4C4main3BarZv"), "void main.foo(main.Bar[4])"),
        (d(&["main", "foo"], "FxC4main3BarZv"), "void main.foo(const(main.Bar))"),
        (d(&["main", "foo"], "FHC4main1KC4main1VZv"), "void main.foo(main.V[main.K])"),
        (d(&["main", "foo"], "FZC4main3Qux"), "main.Qux main.foo()"),
        (
            d(&["main", "foo"], &format!("FC4main3ArgZ{}", body(&["bar"], "FZv"))),
            "void main.foo(main.Arg).bar()",
        ),
    ] {
        assert_eq!(
            rustre_demangle::demangle(&sym).map(|r| r.demangled).as_deref(),
            Some(want),
            "{sym}"
        );
    }
}
