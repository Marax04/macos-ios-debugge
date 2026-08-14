//! Regression tests for logic defects found by the wave-1 semantic audit.
//!
//! These all returned plausible answers that were wrong: a glob that reported
//! "no match" for a pattern that matches, a traversal that silently dropped
//! reachable nodes, a chromatic number for a graph with no vertices.

use rustre_graph::graph_algorithms_extended::{Graph, GraphColoring};
use rustre_graph::query_engine::glob_match;

// ── glob_match ─────────────────────────────────────────────────────────────

/// The old implementation recursed and capped the depth at 4096, turning
/// "too deep" into "no match". Demangled C++/Rust names routinely exceed that,
/// and matching them is exactly what `SymbolQuery::name_pattern` is for.
#[test]
fn star_matches_text_longer_than_the_old_recursion_cap() {
    let long = "a".repeat(5000);
    assert!(glob_match("*", &long));
    assert!(glob_match("a*", &long));
    assert!(glob_match("*a", &long));
    assert!(glob_match("*a*", &long));
}

#[test]
fn prefix_pattern_matches_a_very_long_symbol_name() {
    let name = format!("sub_{}", "x".repeat(6000));
    assert!(glob_match("sub_*", &name));
    assert!(!glob_match("other_*", &name));
}

/// A long pattern must work too — the cap counted pattern + text together.
#[test]
fn long_patterns_of_wildcards_still_terminate_correctly() {
    let pattern = "?".repeat(5000);
    let text = "b".repeat(5000);
    assert!(glob_match(&pattern, &text));
    assert!(!glob_match(&pattern, &"b".repeat(4999)));
}

#[test]
fn basic_glob_semantics_are_unchanged() {
    assert!(glob_match("", ""));
    assert!(!glob_match("", "a"));
    assert!(glob_match("*", ""));
    assert!(glob_match("**", ""));
    assert!(glob_match("abc", "abc"));
    assert!(!glob_match("abc", "ab"));
    assert!(!glob_match("abc", "abcd"));
    assert!(glob_match("a?c", "abc"));
    assert!(!glob_match("a?c", "ac"));
    assert!(glob_match("a*c", "ac"));
    assert!(glob_match("a*c", "abbbc"));
    assert!(!glob_match("a*c", "abbb"));
    assert!(glob_match("*.rs", "main.rs"));
    assert!(!glob_match("*.rs", "main.rss"));
    assert!(glob_match("a*b*c", "axxbyyc"));
    assert!(!glob_match("a*b*c", "axxcyyb"));
}

/// A pattern of only wildcards matches anything, and never diverges.
#[test]
fn pathological_star_runs_do_not_hang_or_misreport() {
    let stars = "*".repeat(64);
    for text in ["", "a", "abcabcabc", &"z".repeat(2000)] {
        assert!(glob_match(&stars, text), "{stars:.8}… vs {} chars", text.len());
    }
    // Interleaved stars and literals that cannot be satisfied.
    assert!(!glob_match(&format!("{}q", "*a".repeat(20)), &"a".repeat(100)));
}

// ── GraphColoring::dsatur ──────────────────────────────────────────────────

/// The chromatic number of a graph with no vertices is 0. `unwrap_or(&0) + 1`
/// invented a colour that was never used.
#[test]
fn empty_graph_uses_no_colours() {
    let r = GraphColoring::dsatur(&Graph::new(0));
    assert!(r.colors.is_empty());
    assert_eq!(r.chromatic_number, 0);
}

#[test]
fn a_single_vertex_uses_one_colour() {
    let r = GraphColoring::dsatur(&Graph::new(1));
    assert_eq!(r.chromatic_number, 1);
}

/// The count must equal the number of DISTINCT colours actually assigned —
/// that is the property the `max + 1` shortcut was standing in for.
#[test]
fn chromatic_number_equals_the_colours_actually_used() {
    for n in 0..8usize {
        let g = Graph::new(n);
        let r = GraphColoring::dsatur(&g);
        let used: std::collections::HashSet<usize> = r
            .colors
            .iter()
            .copied()
            .filter(|&c| c != usize::MAX)
            .collect();
        assert_eq!(
            r.chromatic_number,
            used.len(),
            "n = {n}: reported {} colours, actually used {:?}",
            r.chromatic_number,
            used
        );
    }
}
