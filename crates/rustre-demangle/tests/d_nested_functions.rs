//! D functions nested in another function's scope.
//!
//! D's ABI writes a nested symbol's path as
//! `SymbolName M? TypeModifiers? TypeFunctionNoReturn QualifiedName`: the
//! enclosing function's type is embedded between the two names, **with its
//! return type omitted**. `parse_qualified` read only length-prefixed
//! identifiers, so it stopped at the enclosing function's convention sigil and
//! the whole symbol declined as `UnsupportedAbi`.
//!
//! The omitted return type is what makes the two cases separable, and it is the
//! detail I got wrong first: after the parameter terminator `Z`, a **digit**
//! means a length prefix and therefore another name; anything else is the
//! symbol's own return type, because no D type code is a digit. I initially
//! "corrected" a probe input by adding the parent's return type, which made it
//! malformed — reading the grammar settled it, not the probe.
//!
//! Needs no oracle: this is a documented production, decided by the spec.

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

/// `_D` + the body of `d(...)`, for embedding one symbol's tail in another.
fn body(parts: &[&str], tail: &str) -> String {
    d(parts, tail)[2..].to_owned()
}

fn ours(sym: &str) -> Option<String> {
    rustre_demangle::demangle(sym).map(|r| r.demangled)
}

/// A nested function decodes, at any depth and inside a method.
#[test]
fn nested_functions_decode() {
    for (sym, want) in [
        (
            d(&["main", "foo"], &format!("FZ{}", body(&["bar"], "FZv"))),
            "void main.foo().bar()",
        ),
        (
            d(
                &["main", "foo"],
                &format!("FZ{}", body(&["bar"], &format!("FZ{}", body(&["baz"], "FZv")))),
            ),
            "void main.foo().bar().baz()",
        ),
        (
            d(&["main", "Foo", "m"], &format!("MFZ{}", body(&["inner"], "FZv"))),
            "void main.Foo.m().inner()",
        ),
    ] {
        assert_eq!(ours(&sym).as_deref(), Some(want), "{sym}");
        assert_eq!(
            format!("{:?}", rustre_demangle::decline::decline_reason(&sym)),
            "Decoded",
            "{sym}"
        );
    }
}

/// Nesting is not the same as class membership, and must not render as it.
///
/// Discriminating: this is the pair the `()` marker exists for. Without it
/// `bar` nested inside `foo` and `bar` inside class `foo` — two different
/// symbols — render identically.
#[test]
fn nesting_is_distinguished_from_membership() {
    let nested = d(&["main", "foo"], &format!("FZ{}", body(&["bar"], "FZv")));
    let member = d(&["main", "foo", "bar"], "FZv");
    assert_eq!(ours(&nested).as_deref(), Some("void main.foo().bar()"));
    assert_eq!(ours(&member).as_deref(), Some("void main.foo.bar()"));
    assert_ne!(ours(&nested), ours(&member));
}

/// The enclosing function's parameters are rendered.
///
/// Emitting a bare `()` dropped them, so a nested `bar` inside each of two
/// `foo` overloads collapsed onto one output — a collision introduced by the
/// first version of this fix, not present before it.
#[test]
fn the_enclosing_signature_is_not_dropped() {
    let mut seen = std::collections::BTreeSet::new();
    // `X` REPLACES `Z` as the terminator for a variadic function; `FiXZ`
    // is malformed and was my error, not the decoder's.
    for tail in ["FZ", "FiZ", "FiiZ", "FaZ", "FiX"] {
        let sym = d(&["main", "foo"], &format!("{tail}{}", body(&["bar"], "FZv")));
        let out = ours(&sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert!(seen.insert(out.clone()), "{tail} collided: {out}");
    }
    assert_eq!(seen.len(), 5);
    assert_eq!(
        ours(&d(&["main", "foo"], &format!("FiZ{}", body(&["bar"], "FZv")))).as_deref(),
        Some("void main.foo(int).bar()")
    );
}

/// The speculative parse must rewind cleanly: an ordinary symbol is unchanged.
///
/// `try_consume_enclosing_function_type` runs on every path component, so a
/// failure to rewind would corrupt every D symbol in the crate.
#[test]
fn ordinary_symbols_are_untouched_by_the_speculative_parse() {
    for (sym, want) in [
        (d(&["main", "foo"], "FZv"), "void main.foo()"),
        (d(&["main", "Foo", "bar"], "MFZv"), "void main.Foo.bar()"),
        (d(&["main", "foo"], "FiZi"), "int main.foo(int)"),
        (d(&["main", "__ModuleInfo"], "Z"), "main.__ModuleInfo"),
        (d(&["main", "foo"], "UiZi"), "extern(C) int main.foo(int)"),
        (d(&["main", "Foo", "bar"], "MxFZv"), "void main.Foo.bar() const"),
    ] {
        assert_eq!(ours(&sym).as_deref(), Some(want), "{sym}");
    }
}
