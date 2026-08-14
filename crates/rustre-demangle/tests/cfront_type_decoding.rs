//! cfront / g++ 2.x: modifiers apply to what FOLLOWS, so order carries meaning.
//!
//! The decoder collected `P`/`R` into a suffix and `C`/`U`/`S` into a prefix.
//! That is order-destroying, and the ARM scheme's meaning lives entirely in the
//! order:
//!
//! ```text
//! PCc = P(Cc) = pointer to const char = const char*
//! CPc = C(Pc) = const pointer to char = char* const
//! ```
//!
//! Four defects followed from the one cause:
//!
//! 1. **Injectivity collapse.** `PCc`, `CPc` and `CPCc` all rendered
//!    `const char*` — three distinct C++ types, one output. A consumer cannot
//!    recover which was meant, and two of the three readings are wrong.
//! 2. **A qualifier silently dropped.** `UCi` rendered `unsigned int`: the `C`
//!    was discarded because the prefix was already occupied.
//! 3. **Types C++ cannot express.** `UUi` rendered `unsigned unsigned int` and
//!    `USi` rendered `unsigned signed int`.
//! 4. **Illegal indirection rendered as legal.** `PRi` rendered `int&*` — C++
//!    has no pointer to a reference — and `RRi` rendered `int&&`, which reads
//!    as a C++11 rvalue reference, a different type from the (illegal)
//!    reference-to-reference the input asks for.
//!
//! cfront was one of the eight conventions with no presence in either
//! `convention_decoding.rs` or `detector_conventions.rs`, so neither of a
//! detector's two properties had been checked for it.

use rustre_demangle::lang_more::legacy_native::demangle_cfront as demangle;

fn args_of(sym: &str) -> String {
    let out = demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
    let open = out.find('(').expect("a signature");
    let close = out.rfind(')').expect("a signature");
    out[open + 1..close].to_owned()
}

/// The load-bearing property: distinct modifier orders are distinct types.
///
/// Stated as injectivity over a set of inputs rather than as a list of expected
/// strings, so it fails for any collapse — including one produced by a
/// rendering nobody has written down yet.
#[test]
fn distinct_modifier_orders_render_distinctly() {
    let orders = ["PCc", "CPc", "CPCc", "PCPCc", "Pc", "Cc", "PPc", "RCc", "CRc"];
    let mut seen: std::collections::BTreeMap<String, &str> = std::collections::BTreeMap::new();
    let mut collisions = Vec::new();
    for o in orders {
        let sym = format!("f__F{o}");
        let Some(out) = demangle(&sym) else { continue };
        if let Some(prev) = seen.insert(out.clone(), o) {
            collisions.push(format!("{prev} and {o} both render {out}"));
        }
    }
    assert!(seen.len() >= 8, "vacuous: only {} decoded", seen.len());
    assert!(
        collisions.is_empty(),
        "distinct ARM types collapsed onto one rendering:\n{}",
        collisions.join("\n")
    );
}

/// `const` sits west of a plain type and east of an indirection.
///
/// Discriminating: `Pc` and `Ci` pass whether or not the ordering is honoured —
/// they are the cases anyone writes first. `CPc` is what separates a correct
/// decoder from an order-destroying one.
#[test]
fn const_placement_follows_the_modifier_order() {
    for (sig, want) in [
        ("i", "int"),
        ("Ci", "const int"),
        ("Pc", "char*"),
        ("PCc", "const char*"),
        ("CPc", "char* const"),
        ("CPCc", "const char* const"),
        ("PCPCc", "const char* const*"),
        ("Ri", "int&"),
        ("CRi", "int& const"),
        ("RCi", "const int&"),
    ] {
        assert_eq!(args_of(&format!("f__F{sig}")), want, "signature {sig}");
    }
}

/// No qualifier may be dropped, and none may be stacked into a type C++ cannot
/// express.
#[test]
fn qualifiers_are_neither_dropped_nor_stacked() {
    // Well-formed: exactly one sign qualifier, adjacent to the base.
    assert_eq!(args_of("f__FUi"), "unsigned int");
    assert_eq!(args_of("f__FSc"), "signed char");
    assert_eq!(args_of("f__FCUi"), "const unsigned int");
    assert_eq!(args_of("f__FPUi"), "unsigned int*");

    // Malformed: repeated, contradictory, or separated from the base. Each
    // previously produced output — `UCi` by *losing* the const, the others by
    // inventing a type that does not exist.
    for sig in ["UUi", "USi", "SUi", "UCi", "UUUUi", "SSi", "UPi"] {
        assert_eq!(
            demangle(&format!("f__F{sig}")),
            None,
            "{sig} is not a type cfront can emit"
        );
    }
}

/// C++ has no pointer to a reference and no reference to a reference.
#[test]
fn illegal_indirection_declines() {
    for sig in ["PRi", "RRi", "PRPi", "RRPi"] {
        assert_eq!(
            demangle(&format!("f__F{sig}")),
            None,
            "{sig} asks for an indirection C++ forbids"
        );
    }
    // The legal neighbours must still decode, or the rule is over-rejecting.
    for (sig, want) in [("RPi", "int*&"), ("PPi", "int**"), ("PPPi", "int***")] {
        assert_eq!(args_of(&format!("f__F{sig}")), want, "{sig}");
    }
}

/// A doubled `const` at one level is not a type C++ can express.
///
/// This hole was introduced BY the iter-115 rewrite: the old order-destroying
/// code collapsed `CC` (losing information), while building outward would
/// fabricate `const const int`. Found the next day by re-running the same probe
/// against Borland, which had the identical builder.
#[test]
fn a_doubled_const_declines() {
    for sig in ["CCi", "CCPc", "PCCi"] {
        assert_eq!(
            demangle(&format!("f__F{sig}")),
            None,
            "{sig} is not a type C++ can express"
        );
    }
    // The single-`const` neighbours must still decode.
    assert_eq!(args_of("f__FCi"), "const int");
    assert_eq!(args_of("f__FCPCc"), "const char* const");
}

/// The documented shapes, unchanged.
#[test]
fn documented_shapes_still_decode() {
    for (sym, want) in [
        ("f__Fi", "f(int)"),
        ("f__Fic", "f(int, char)"),
        ("f__Fv", "f()"),
        ("f__FPc", "f(char*)"),
        ("bar__3Fooi", "Foo::bar(int)"),
        ("bar__C3Fooi", "Foo::bar(int) const"),
    ] {
        assert_eq!(demangle(sym).as_deref(), Some(want), "{sym}");
    }
}
