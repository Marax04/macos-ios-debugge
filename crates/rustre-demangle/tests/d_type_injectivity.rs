//! D type modifiers: distinct orders must render distinctly.
//!
//! **Why this can exist without a D oracle.** Injectivity is a structural
//! property of the mapping, not a claim about what the right answer is: it
//! asks only whether two different inputs collapse onto one output. That
//! needs no ground truth, which is the same reason `go_completeness.rs` works
//! for an ABI nothing can contradict. D's open question — the raw `__T…`
//! template name — genuinely does need a real D binary and is untouched here.
//!
//! The property is worth pinning because the identical class was found three
//! times in a row in the neighbouring decoders, all of which accumulated
//! modifiers into a prefix and a suffix instead of nesting them:
//!
//! * cfront: `PCc`, `CPc`, `CPCc` all rendered `const char*` (iter 115)
//! * Borland: same collapse, plus indirections rendered in reverse (iter 117)
//!
//! **Measured 2026-07-30: D is clean.** It renders modifiers with D's own
//! wrapping syntax (`const(int)*` for a pointer to const, `const(int*)` for a
//! const pointer) via a recursive parser, so the order is preserved by
//! construction rather than by care. No defect was found; this file is the
//! guard, not a fix.

use std::collections::BTreeMap;

/// Build the minimal D symbol `void a.f(<type>)` carrying `code` as the
/// parameter type.
fn symbol(code: &str) -> String {
    format!("_D1a1fF{code}Zv")
}

fn demangle(code: &str) -> Option<String> {
    rustre_demangle::demangle(&symbol(code)).map(|r| r.demangled)
}

/// Every distinct modifier sequence over a fixed base is a distinct type.
///
/// The sequences are GENERATED rather than listed, so the check covers orders
/// nobody thought to write down — including the `xPy` / `xyP` / `Pxy` family
/// that separates a nesting parser from an accumulating one.
#[test]
fn distinct_modifier_orders_render_distinctly() {
    // `P` pointer, `x` const, `y` immutable, `O` shared, `A` dynamic array.
    const MODS: [&str; 5] = ["P", "x", "y", "O", "A"];

    // Build level by level from the PREVIOUS level only. Extending the list
    // being iterated regenerates every shorter prefix each round, which yields
    // duplicates — and a duplicate input reads as an injectivity collapse, a
    // false finding produced entirely by the probe.
    let mut orders: Vec<String> = Vec::new();
    let mut level: Vec<String> = vec![String::new()];
    for _ in 0..3 {
        level = level
            .iter()
            .flat_map(|o| MODS.iter().map(move |m| format!("{o}{m}")))
            .collect();
        orders.extend(level.iter().cloned());
    }
    {
        let unique: std::collections::BTreeSet<&String> = orders.iter().collect();
        assert_eq!(unique.len(), orders.len(), "the generator emitted duplicates");
    }

    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut collisions = Vec::new();
    let mut decoded = 0;
    for o in &orders {
        let Some(out) = demangle(&format!("{o}i")) else {
            continue;
        };
        decoded += 1;
        if let Some(prev) = seen.insert(out.clone(), o.clone()) {
            collisions.push(format!("{prev:?} and {o:?} both render {out}"));
        }
    }

    assert!(
        decoded >= 150,
        "vacuous: only {decoded} of {} orders decoded",
        orders.len()
    );
    assert!(
        collisions.is_empty(),
        "{} distinct D type orders collapsed onto one rendering:\n{}",
        collisions.len(),
        collisions.join("\n")
    );
}

/// The orderings that discriminate a nesting parser from an accumulating one.
///
/// `Pi` and `xi` pass either way; `Px` versus `xP` is where the neighbouring
/// decoders failed, and D renders them as different D types.
#[test]
fn qualifier_and_indirection_nest_in_the_written_order() {
    for (code, want) in [
        ("i", "int"),
        ("Pi", "int*"),
        ("xi", "const(int)"),
        ("Pxi", "const(int)*"),
        ("xPi", "const(int*)"),
        ("xyi", "const(immutable(int))"),
        ("yxi", "immutable(const(int))"),
        ("Ai", "int[]"),
        ("Axi", "const(int)[]"),
        ("xAi", "const(int[])"),
        ("APi", "int*[]"),
        ("PAi", "int[]*"),
    ] {
        let out = demangle(code).unwrap_or_else(|| panic!("{} must decode", symbol(code)));
        assert_eq!(
            out,
            format!("void a.f({want})"),
            "type code {code}"
        );
    }
}

/// The compound type constructors carry their operands, in order.
#[test]
fn compound_types_keep_their_operands() {
    for (code, want) in [
        ("Hii", "int[int]"),      // associative array: value[key]
        ("Hik", "uint[int]"),     // distinct key and value
        ("Hxii", "int[const(int)]"),
        ("G4i", "int[4]"),        // static array
        ("AAi", "int[][]"),
        ("Ja", "out char"),
    ] {
        let out = demangle(code).unwrap_or_else(|| panic!("{} must decode", symbol(code)));
        assert_eq!(out, format!("void a.f({want})"), "type code {code}");
    }
    // Swapping the operands of an associative array is a different type.
    assert_ne!(demangle("Hik"), demangle("Hki"));
}

/// A compound constructor missing an operand is malformed and declines.
///
/// Guards the suite above from vacuity in the other direction: if `H`, `G` or
/// `B` silently accepted a missing operand, the assertions would be comparing
/// invented output.
#[test]
fn truncated_compound_types_decline() {
    for code in ["H", "Hi", "G", "G4", "B", "Ba", "S", "Sa", "D", "Da"] {
        assert_eq!(
            demangle(code),
            None,
            "type code {code} is missing an operand and must not decode"
        );
    }
}
