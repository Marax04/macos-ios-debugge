//! A symbol that decodes must name its function.
//!
//! `tests/structured_consistency.rs` requires every populated field to appear
//! inside the rendered string. An **empty** field satisfies that vacuously, so
//! 75 real corpus symbols decoded correctly while reporting no function name at
//! all — a third of the Rust corpus and every Itanium anonymous-namespace
//! variable. The consumers that matter read the fields, not the string.
//!
//! Two independent causes, both the same mistake: splitting a rendering on a
//! character that also occurs *inside* its syntax.
//!
//! * Rust truncated at the first `<` to drop generic arguments. When the
//!   rendering **begins** with a qualified type — `<str>::trim_start_matches`,
//!   or any `core::…::assert_failed::<usize, usize>` — that leaves nothing.
//!   Fixed by splitting `::` at bracket depth zero and dropping trailing
//!   turbofish groups.
//! * Itanium took the last balanced `(…)` as the argument list. A data symbol
//!   named `(anonymous namespace)::__new_handler` has no argument list, so the
//!   name was consumed as one. Fixed by requiring the parens to sit at the end
//!   of the rendering, modulo cv/ref qualifiers.
//!
//! A third, smaller case in MSVC: `?g@@3PAHA` renders `int* g` and reported
//! `function: "int* g"`. The entity is the last whitespace-separated token —
//! except for the backtick-quoted special names, which contain spaces
//! (`` `vector deleting destructor' ``). The first attempt at that fix missed
//! the exception and was caught by the existing rejoin test, which is why the
//! backtick case is pinned explicitly below.

use std::collections::BTreeMap;

fn corpus() -> Vec<&'static str> {
    include_str!("data/real_symbols.txt")
        .lines()
        .chain(include_str!("data/pdb_symbols.txt").lines())
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect()
}

/// No decoded symbol may report an empty `function`.
///
/// Go is included: its renderings are already names, so it has never had this
/// problem, and leaving it in means a regression there would be caught too.
#[test]
fn every_decoded_symbol_names_its_function() {
    let mut offenders: Vec<(&str, String, String)> = Vec::new();
    let mut checked: BTreeMap<String, usize> = BTreeMap::new();

    for sym in corpus() {
        let Some(r) = rustre_demangle::demangle(sym) else {
            continue;
        };
        let abi = format!("{:?}", r.abi);
        *checked.entry(abi.clone()).or_default() += 1;
        if r.function.is_empty() {
            offenders.push((sym, abi, r.demangled));
        }
    }

    assert!(
        offenders.is_empty(),
        "{} symbols decoded but reported no function; first 5: {:?}",
        offenders.len(),
        &offenders[..offenders.len().min(5)]
    );
    // Vacuity: each ABI must actually be present, or the sweep proves nothing.
    for abi in ["Itanium", "Rust", "Go"] {
        let n = checked.get(abi).copied().unwrap_or(0);
        assert!(n > 100, "only {n} {abi} decodes examined — guard is vacuous");
    }
}

/// `function` must never be the whole rendering when the rendering is a
/// signature or a typed declaration.
///
/// The mirror of the emptiness defect: a field that carries everything is as
/// useless as one that carries nothing, and both slip past a containment check.
#[test]
fn function_is_not_the_entire_rendering() {
    let mut offenders: Vec<(&str, String)> = Vec::new();
    let mut checked = 0;
    for sym in corpus() {
        let Some(r) = rustre_demangle::demangle(sym) else {
            continue;
        };
        checked += 1;
        // A rendering carrying a signature or a type prefix has more in it than
        // the entity name, so the two must differ.
        if r.function == r.demangled && r.demangled.contains(['(', ' ']) {
            offenders.push((sym, r.demangled));
        }
    }
    assert!(
        offenders.is_empty(),
        "function field holds the entire rendering: {offenders:?}"
    );
    assert!(checked > 2000, "vacuity guard: only {checked} decodes examined");
}

/// The shapes that defeated each splitter, named individually.
///
/// The corpus sweeps above would pass again if someone fixed one cause and
/// reintroduced the other, since both produce the same symptom. These pin the
/// causes apart.
#[test]
fn the_shapes_that_broke_each_splitter() {
    let f = |s: &str| {
        rustre_demangle::demangle(s)
            .unwrap_or_else(|| panic!("{s} must decode"))
            .function
    };

    // Rust: rendering begins with a qualified type, and ends with a turbofish.
    assert_eq!(
        f("_RINvMNtCs189ThkfrTWj_4core3stre18trim_start_matchesReECsdUyFeGaMdop_14rustc_demangle"),
        "trim_start_matches"
    );
    assert_eq!(
        f("_RINvNtCs189ThkfrTWj_4core9panicking13assert_failedjjEB4_"),
        "assert_failed"
    );

    // Itanium: a `(…)` group inside the name of a symbol that takes no
    // arguments at all.
    assert_eq!(f("_ZN12_GLOBAL__N_1L13__new_handlerE"), "__new_handler");
    assert_eq!(
        f("_ZN12_GLOBAL__N_1L24system_category_instanceE"),
        "system_category_instance"
    );

    // Itanium control: a real argument list is still recognised.
    assert_eq!(f("_ZN3foo3barEi"), "bar");

    // MSVC: typed data declarations, and the backtick-quoted special names
    // whose entity legitimately contains spaces.
    assert_eq!(f("?x@@3HA"), "x");
    assert_eq!(f("?g@@3PAHA"), "g");
    assert_eq!(
        f("?__type_info_root_node@@3U__type_info_node@@A"),
        "__type_info_root_node"
    );
    assert_eq!(f("??_7Foo@@6B@"), "`vftable'");
    assert_eq!(f("?foo@@YAHH@Z"), "foo");
}

/// The renderings themselves must be untouched.
///
/// Every change here is to the decomposition. A "fix" that simplified the
/// rendered strings to make splitting easier would pass the assertions above
/// while breaking the differential suites' contract with the oracles.
#[test]
fn renderings_are_unchanged_by_the_decomposition_fixes() {
    for (sym, rendering) in [
        (
            "_ZN12_GLOBAL__N_1L13__new_handlerE",
            "(anonymous namespace)::__new_handler",
        ),
        ("_ZN3foo3barEi", "foo::bar(int)"),
        ("?g@@3PAHA", "int* g"),
        ("??_7Foo@@6B@", "const Foo::`vftable'"),
        (
            "_RINvNtCs189ThkfrTWj_4core9panicking13assert_failedjjEB4_",
            "core::panicking::assert_failed::<usize, usize>",
        ),
    ] {
        assert_eq!(
            rustre_demangle::demangle(sym).map(|r| r.demangled),
            Some(rendering.to_owned()),
            "rendering of {sym} changed"
        );
    }
}
