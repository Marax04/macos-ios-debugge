//! A nested generic argument lost its outer type name and left a stray bracket.
//!
//! `strip_shape_prefix` removed the compiler's synthetic shape package by
//! truncating from the front — "everything after the last `.shape.`". That is
//! correct only when the qualifier OPENS the argument. A nested instantiation
//! puts a type name before it:
//!
//! ```text
//! main.A[main.B[go.shape.int]].m  =>  main.A[int]].m
//! ```
//!
//! `main.B[` thrown away, `]` orphaned — a lost component AND an unbalanced
//! rendering, from one line. Bracket-aware handling has been this crate's most
//! repeated defect source (four sibling `split_*` functions at iters 55-58),
//! and this is the same family reached through a different door: generics
//! combined with closures, a pairing never probed.
//!
//! The fix removes each `<pkg>.shape.` where it occurs, walking back only over
//! the package identifier that owns it, so everything else — brackets included
//! — survives.
//!
//! **Not to be confused with iter 141**, which REVERTED an attempt to strip the
//! same qualifier from `type:` DESCRIPTOR renderings: there the corpus holds
//! both the shape-instantiated and concrete forms as separate symbols, so
//! stripping merges two real functions. Type arguments are the opposite case
//! and the crate has always stripped them; `shape_qualifier_is_load_bearing.rs`
//! pins both halves.

fn ours(sym: &str) -> Option<String> {
    rustre_demangle::demangle(sym).map(|r| r.demangled)
}

/// A nested generic keeps its inner type name.
///
/// Discriminating: the single-level `main.Foo[go.shape.int].m` passes either
/// way — the qualifier opens the argument, so truncation happens to be right.
/// Only nesting separates a rule that removes the qualifier from one that
/// truncates.
#[test]
fn a_nested_generic_keeps_its_inner_name() {
    for (sym, want) in [
        ("main.Foo[go.shape.int].m", "main.Foo[int].m"),
        ("main.A[main.B[go.shape.int]].m", "main.A[main.B[int]].m"),
        (
            "main.A[main.B[go.shape.int]].m.func1",
            "main.A[main.B[int]].m {closure-1 #1}",
        ),
        (
            "main.A[main.B[main.C[go.shape.int]]].m",
            "main.A[main.B[main.C[int]]].m",
        ),
        (
            "main.Foo[go.shape.int,go.shape.string].m",
            "main.Foo[int, string].m",
        ),
    ] {
        assert_eq!(ours(sym).as_deref(), Some(want), "{sym}");
    }
}

/// Every rendering has balanced brackets.
///
/// Stated over the OUTPUT rather than against expected strings, so a truncation
/// nobody wrote a vector for still fails. The orphaned `]` is what made this
/// defect visible at a glance.
#[test]
fn renderings_have_balanced_brackets() {
    let mut inputs: Vec<String> = include_str!("data/real_symbols.txt")
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    for s in [
        "main.A[main.B[go.shape.int]].m",
        "main.A[main.B[go.shape.int]].m.func1",
        "main.A[main.B[main.C[go.shape.int]]].m",
        "main.(*Foo[go.shape.int]).m.func1",
        "main.Foo[a.b.C].m.func1",
    ] {
        inputs.push(s.to_owned());
    }

    let mut checked = 0;
    let mut unbalanced = Vec::new();
    for sym in &inputs {
        let Some(out) = ours(sym) else { continue };
        checked += 1;
        let mut depth = 0i32;
        for c in out.chars() {
            match c {
                '[' => depth += 1,
                ']' => depth -= 1,
                _ => {}
            }
            if depth < 0 {
                break;
            }
        }
        if depth != 0 {
            unbalanced.push(format!("{sym} => {out}"));
        }
    }
    assert!(checked > 3000, "vacuous: only {checked} decodes");
    assert!(unbalanced.is_empty(), "{}", unbalanced.join("\n"));
}

/// Generics combined with closures and pointer receivers.
///
/// The pairing this probe was built for: each feature was tested alone, never
/// together.
#[test]
fn generics_compose_with_closures_and_receivers() {
    for (sym, want) in [
        ("main.Foo[go.shape.int].m.func1", "main.Foo[int].m {closure-1 #1}"),
        ("main.Foo[go.shape.int].m.func2.3", "main.Foo[int].m {closure-2 #2.3}"),
        ("main.(*Foo[go.shape.int]).m", "main.(*Foo[int]).m"),
        ("main.(*Foo[go.shape.int]).m.func1", "main.(*Foo[int]).m {closure-1 #1}"),
        ("slices.Sort[go.shape.int].func1", "slices.Sort[int] {closure-1 #1}"),
    ] {
        assert_eq!(ours(sym).as_deref(), Some(want), "{sym}");
    }
}

/// A dotted type argument that is NOT a shape package is untouched.
///
/// The walk-back stops at the package identifier, so an ordinary qualified type
/// keeps its path.
#[test]
fn ordinary_qualified_type_arguments_are_untouched() {
    for (sym, want) in [
        ("main.Foo[a.b.C].m", "main.Foo[a.b.C].m"),
        ("main.Foo[a.b.C].m.func1", "main.Foo[a.b.C].m {closure-1 #1}"),
        ("main.Foo[int].m", "main.Foo[int].m"),
    ] {
        assert_eq!(ours(sym).as_deref(), Some(want), "{sym}");
    }
}
