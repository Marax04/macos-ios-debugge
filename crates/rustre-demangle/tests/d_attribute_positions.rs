//! A D construct must mean the same thing wherever it appears.
//!
//! D writes function attributes as `N<letter>` immediately after the calling
//! convention, and several *type* constructors share that shape — `Ng` inout,
//! `Nh` __vector, `Nn` noreturn. So the attribute loop and the type parser
//! compete for the same two bytes, and only at the first parameter position.
//!
//! That is decidable with no D oracle. A type that renders `inout(int)` in
//! every other position cannot legitimately become `@nogc` merely by moving to
//! the front — whichever reading is right, the two cannot both be. This file
//! tests that *invariance*, not the meaning, which is why it works for an ABI
//! whose ground truth this crate does not have.
//!
//! `Nh` and `Nn` were fixed this way earlier. `Ng` was left behind, and the
//! note explaining why argued that the attribute letters are
//! "`a b c d e f g i j k` — **measured from the parser's own table**". The
//! table was the thing in question. Circular evidence is how a defect survives
//! a test written specifically to catch its siblings:
//!
//! ```text
//!   _D4main3fooFiNgiZv  =>  void main.foo(int, inout(int))
//!   _D4main3fooFNgiZv   =>  void main.foo(int) @nogc
//! ```
//!
//! Removing `g` alone would have made `@nogc` unreachable from parsing, so the
//! remaining letters took their published meanings. The set is now exactly the
//! documented `FuncAttr` table; it was that table minus `m` plus `g`.

fn demangled(sym: &str) -> String {
    rustre_demangle::demangle(sym).unwrap_or_else(|| panic!("{sym} must decode")).demangled
}

/// `_D4main3fooF<tail>Zv`.
fn f(tail: &str) -> String {
    format!("_D4main3fooF{tail}Zv")
}

/// **The invariant.** An `N`-prefixed type reads the same first as it does
/// anywhere else.
///
/// Discriminating by construction: the expected rendering is not written down,
/// it is *taken from a later position* — where the attribute loop cannot reach
/// — and required of the first. A reading that is wrong in both places would
/// still have to be wrong consistently, and any table that steals one of these
/// letters fails immediately.
#[test]
fn an_n_prefixed_type_means_the_same_in_every_position() {
    let mut checked = 0;
    for ty in ["Ng", "Nh"] {
        // Second position: past the attribute loop, so this is the type
        // parser's own reading.
        let later = demangled(&f(&format!("i{ty}i")));
        let inner = later
            .strip_prefix("void main.foo(int, ")
            .and_then(|s| s.strip_suffix(')'))
            .unwrap_or_else(|| panic!("unexpected control rendering: {later}"));

        assert_eq!(
            demangled(&f(&format!("{ty}i"))),
            format!("void main.foo({inner})"),
            "{ty} reads differently when it comes first"
        );
        checked += 1;
    }
    assert_eq!(checked, 2);
}

/// The attribute table, pinned by letter. Each letter must produce a distinct
/// attribute, so a shifted table cannot satisfy this by relabelling.
#[test]
fn the_attribute_letters_are_the_published_set() {
    let table = [
        ('a', "pure"),
        ('b', "nothrow"),
        ('c', "ref"),
        ('d', "@property"),
        ('e', "@trusted"),
        ('f', "@safe"),
        ('i', "@nogc"),
        ('j', "return"),
        ('k', "scope"),
        ('m', "@live"),
    ];
    let mut seen = std::collections::BTreeSet::new();
    for (letter, want) in table {
        assert_eq!(
            demangled(&f(&format!("N{letter}i"))),
            format!("void main.foo(int) {want}"),
            "N{letter}"
        );
        assert!(seen.insert(want), "{want} reachable from two letters");
    }
    assert_eq!(seen.len(), 10);
}

/// Every attribute must be reachable from parsing. Dropping `g` without
/// reassigning would have orphaned `@nogc` — a variant no input can produce,
/// the defect shape that once left `MangleLanguage::Java` unreachable from
/// `classify`.
#[test]
fn no_attribute_is_orphaned() {
    for want in [
        "pure", "nothrow", "ref", "@property", "@trusted", "@safe", "@nogc", "return", "scope",
        "@live",
    ] {
        let reachable = ('a'..='z').any(|c| {
            rustre_demangle::demangle(&f(&format!("N{c}i")))
                .is_some_and(|r| r.demangled.ends_with(&format!(" {want}")))
        });
        assert!(reachable, "{want} cannot be produced by any letter");
    }
}

/// Attributes stack, and stacking must not resurrect the stolen letter: a
/// leading `Ng` is a type, so it ends the attribute run rather than joining it.
#[test]
fn stacking_does_not_reopen_the_gap() {
    assert_eq!(demangled(&f("NaNbi")), "void main.foo(int) pure nothrow");
    assert_eq!(demangled(&f("NaNiNki")), "void main.foo(int) pure @nogc scope");

    // `Ng` after real attributes is still the type, not an eleventh attribute.
    assert_eq!(demangled(&f("NaNgi")), "void main.foo(inout(int)) pure");
}

/// The set stays closed: a letter outside the table is neither an attribute nor
/// silently swallowed.
#[test]
fn unassigned_letters_still_decline() {
    for letter in "lopqrstuvwxyz".chars() {
        let sym = f(&format!("N{letter}i"));
        assert!(rustre_demangle::demangle(&sym).is_none(), "N{letter} must decline");
    }
}
