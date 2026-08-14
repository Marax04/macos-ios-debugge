//! `XrefGraph::top_referenced` ranks addresses by in-degree, but `edges_to` is a
//! `HashMap` and `sort_by_key` is *stable*: ranking by count alone left ties in
//! hash order, which Rust randomises per process.
//!
//! With ties straddling the `n` cutoff — and single-reference addresses are the
//! common case in real cross-reference data — the **membership** of the top-N
//! changed between runs, not merely the order inside it. A "top 5 most
//! referenced addresses" report that lists different addresses each run is
//! wrong in the way that is hardest to notice: it looks plausible every time.
//!
//! The two neighbouring sorts in the same file (`xrefs_to_sorted`,
//! `all_xrefs_sorted`) already used `.then(...)` for a total order; this one was
//! the outlier.

use rustre_symbols::symbol_cross_ref::{XrefEntry, XrefGraph, XrefType};
use rustre_symbols::{DebugSymbolMerger, SymKind, Symbol};

/// Every target gets the same in-degree, so *every* pair is a tie and the
/// tie-break is the only thing deciding the answer.
fn all_tied_graph(order: &[u64]) -> XrefGraph {
    let mut g = XrefGraph::new();
    for (i, &to) in order.iter().enumerate() {
        g.add_xref(XrefEntry::new(0x9000 + i as u64, to, XrefType::Call));
    }
    g
}

#[test]
fn the_ranking_is_a_total_order() {
    let targets: Vec<u64> = (0..16).map(|i| 0x1000 + i * 0x10).collect();
    let g = all_tied_graph(&targets);
    let top = g.top_referenced(5);

    assert_eq!(top.len(), 5, "premise: the graph has more targets than the cutoff");

    // Descending count, then ascending address — checkable without knowing the
    // hash seed.
    for w in top.windows(2) {
        let (a, b) = (w[0], w[1]);
        assert!(
            a.1 > b.1 || (a.1 == b.1 && a.0 < b.0),
            "ranking is not a total order: ({:#x}, {}) precedes ({:#x}, {})",
            a.0, a.1, b.0, b.1
        );
    }
}

#[test]
fn insertion_order_does_not_change_which_addresses_make_the_cut() {
    // The decisive consequence: the same graph content, inserted in different
    // orders, must yield the same top-N. Before the fix the stable sort carried
    // the insertion/hash order straight into the result.
    let ascending: Vec<u64> = (0..16).map(|i| 0x1000 + i * 0x10).collect();
    let mut descending = ascending.clone();
    descending.reverse();
    let mut shuffled = ascending.clone();
    shuffled.swap(0, 15);
    shuffled.swap(3, 9);

    let a = all_tied_graph(&ascending).top_referenced(5);
    let b = all_tied_graph(&descending).top_referenced(5);
    let c = all_tied_graph(&shuffled).top_referenced(5);

    assert_eq!(a, b, "reversing the insertion order changed the top-N");
    assert_eq!(a, c, "shuffling the insertion order changed the top-N");

    // And it is the arithmetically right answer: the five lowest addresses,
    // since every count is equal.
    let expected: Vec<(u64, usize)> = ascending[..5].iter().map(|&a| (a, 1)).collect();
    assert_eq!(a, expected, "ties must resolve to the lowest addresses");
}

/// `DebugSymbolMerger` is keyed by **name**, so several distinct names can sit
/// at one address — C++ constructor variants (`C1`/`C2`), weak aliases and
/// `main`/`_main` all do it routinely. `finish()` sorted on the address alone,
/// leaving those ties to the stable sort, which preserved `HashMap` order.
#[test]
fn merged_symbols_sharing_an_address_come_out_in_a_stable_order() {
    let aliases = || {
        vec![
            Symbol::new("_ZN3FooC1Ev".to_string(), 0x1000, SymKind::Function),
            Symbol::new("_ZN3FooC2Ev".to_string(), 0x1000, SymKind::Function),
            Symbol::new("main".to_string(), 0x1000, SymKind::Function),
            Symbol::new("_main".to_string(), 0x1000, SymKind::Function),
            Symbol::new("later".to_string(), 0x2000, SymKind::Function),
        ]
    };

    let mut forward = DebugSymbolMerger::new();
    forward.merge(aliases());
    let a = forward.finish();

    let mut backward = DebugSymbolMerger::new();
    let mut reversed = aliases();
    reversed.reverse();
    backward.merge(reversed);
    let b = backward.finish();

    assert_eq!(a.len(), 5, "premise: all five names are distinct map keys");
    let names_a: Vec<&str> = a.iter().map(|s| s.name.as_str()).collect();
    let names_b: Vec<&str> = b.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names_a, names_b,
        "reversing the input order changed the merged output order"
    );

    // Addresses ascending, and within one address the names ascending — a total
    // order, since the name is the map key and therefore unique.
    for w in a.windows(2) {
        assert!(
            w[0].address < w[1].address
                || (w[0].address == w[1].address && w[0].name < w[1].name),
            "merged output is not totally ordered: {} @ {:#x} precedes {} @ {:#x}",
            w[0].name, w[0].address, w[1].name, w[1].address
        );
    }
}

#[test]
fn a_genuinely_higher_count_still_wins() {
    // Premise: the tie-break has not replaced the ranking itself.
    let mut g = XrefGraph::new();
    for i in 0..4 {
        // 0x2000 is referenced four times; 0x1000 only once.
        g.add_xref(XrefEntry::new(0x9000 + i, 0x2000, XrefType::Call));
    }
    g.add_xref(XrefEntry::new(0x9100, 0x1000, XrefType::Call));

    let top = g.top_referenced(2);
    assert_eq!(
        top[0],
        (0x2000, 4),
        "the most-referenced address must rank first regardless of being higher-addressed"
    );
    assert_eq!(top[1], (0x1000, 1));
}
