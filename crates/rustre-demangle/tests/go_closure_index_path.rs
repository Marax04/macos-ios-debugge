//! Every Go closure index survives, not just the outermost.
//!
//! `parse_function_suffix` recorded only the last `funcN`'s index and let the
//! bare nesting segments bump the depth without being kept. The depth said how
//! deep the closure was; nothing said *which* one:
//!
//! ```text
//! main.f.func2.3  =>  main.f {closure-2 #2}
//! main.f.func2.5  =>  main.f {closure-2 #2}   // a different function
//! main.f.func1.2.3 =>  main.f {closure-3 #1}  // two indices lost at once
//! ```
//!
//! Go has no oracle, so a wrong rendering has nothing to contradict it, and
//! `go_completeness.rs` cannot see this: its invariant is defined over *named*
//! components and `3` is a number, not a name. Collision detection sees it
//! because it compares whole symbols against each other rather than each symbol
//! against itself — the same instrument that found the `runtime.init.6.func1`
//! collision pinned in `msvc_constant_pool.rs::go_init_index_is_not_dropped`.
//! This is that defect one level deeper.

use std::collections::BTreeMap;

fn demangle(sym: &str) -> Option<String> {
    rustre_demangle::demangle(sym).map(|r| r.demangled)
}

/// Distinct closure paths render distinctly.
///
/// Inputs are GENERATED over the index space, so the check covers combinations
/// nobody thought to write down, and the generator's own uniqueness is asserted
/// first — for a "distinct inputs, distinct outputs" property a duplicate input
/// manufactures the very collapse being looked for.
#[test]
fn distinct_closure_paths_render_distinctly() {
    let mut inputs: Vec<String> = Vec::new();
    for a in 1..=3u32 {
        inputs.push(format!("main.f.func{a}"));
        for b in 1..=3u32 {
            inputs.push(format!("main.f.func{a}.{b}"));
            for c in 1..=3u32 {
                inputs.push(format!("main.f.func{a}.{b}.{c}"));
            }
        }
    }
    let unique: std::collections::BTreeSet<&String> = inputs.iter().collect();
    assert_eq!(unique.len(), inputs.len(), "the generator emitted duplicates");

    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut collisions = Vec::new();
    let mut decoded = 0;
    for i in &inputs {
        let Some(out) = demangle(i) else { continue };
        decoded += 1;
        if let Some(prev) = seen.insert(out.clone(), i.clone()) {
            collisions.push(format!("{prev} and {i} both render {out}"));
        }
    }

    assert!(decoded >= 39, "vacuous: only {decoded} of {} decoded", inputs.len());
    assert!(
        collisions.is_empty(),
        "{} distinct Go closures collapsed onto one rendering:\n{}",
        collisions.len(),
        collisions.join("\n")
    );
}

/// The whole index path is rendered, outermost first.
///
/// Discriminating: `main.f.func1` and `main.f.func1.1` pass whether or not the
/// inner indices are kept — every index in them is `1`. `func2.3` is what
/// separates a decoder that records the path from one that records only the
/// head.
#[test]
fn the_index_path_is_rendered_in_order() {
    for (sym, want) in [
        ("main.f.func1", "main.f {closure-1 #1}"),
        ("main.f.func2", "main.f {closure-1 #2}"),
        ("main.f.func2.3", "main.f {closure-2 #2.3}"),
        ("main.f.func3.2", "main.f {closure-2 #3.2}"),
        ("main.f.func1.2.3", "main.f {closure-3 #1.2.3}"),
    ] {
        assert_eq!(demangle(sym).as_deref(), Some(want), "{sym}");
    }
}

/// Every index in the input reappears in the output.
///
/// The completeness direction, defined over the INPUT — the property that
/// `go_completeness.rs` applies to names, applied to the numbers it excludes.
#[test]
fn every_input_index_reappears_in_the_output() {
    for sym in [
        "main.f.func2.3",
        "main.f.func5.2",
        "main.f.func1.2.3",
        "runtime.traceAdvance.func3.osyield.1",
        "runtime.init.6.func1",
    ] {
        let out = demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        let indices: Vec<&str> = sym
            .split('.')
            .filter_map(|p| {
                let n = p.strip_prefix("func").unwrap_or(p);
                n.chars().all(|c| c.is_ascii_digit()).then_some(n)
            })
            .filter(|n| !n.is_empty())
            .collect();
        assert!(!indices.is_empty(), "no indices extracted from {sym}");
        for n in indices {
            assert!(
                out.contains(n),
                "{sym} lost the index {n}: {out}"
            );
        }
    }
}

/// Non-closure symbols are untouched — the rule must not leak into ordinary
/// names.
#[test]
fn ordinary_symbols_gain_no_closure_path() {
    for sym in ["main.main", "fmt.Println", "sync.(*Mutex).Lock", "a/b/c.(*T).M"] {
        let out = demangle(sym).unwrap_or_else(|| panic!("{sym} must decode"));
        assert!(!out.contains("closure"), "{sym} gained a closure: {out}");
        assert_eq!(out, sym, "{sym} must round-trip unchanged");
    }
}
