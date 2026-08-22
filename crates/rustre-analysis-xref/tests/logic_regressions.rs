//! Regression tests for logic defects found by the wave-1 semantic audit.
//!
//! Written BEFORE their fixes and confirmed to fail against the then-current
//! code, with the exact output the audit predicted.

use rustre_analysis_xref::string_xref_finder::StringXrefFinder;

fn addrs(code: &[u8]) -> Vec<u64> {
    let f = StringXrefFinder::default().with_x86_32();
    let mut out: Vec<u64> = f.scan(code, 0x1000, 0).all_strings().collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// A 4-byte ABSOLUTE operand is an unsigned address, not a signed
/// displacement. Sign-extending it turned every 32-bit address with the high
/// bit set into a bogus `0xFFFFFFFF_8xxxxxxx`, so on any x86-32 image based at
/// or above `0x8000_0000` every single string xref resolved to garbage.
/// (Only the PC-relative path needs sign extension.)
#[test]
fn absolute_operands_are_zero_extended() {
    // PUSH 0x90000000
    let got = addrs(&[0x68, 0x00, 0x00, 0x00, 0x90]);
    assert!(
        got.contains(&0x9000_0000),
        "PUSH 0x90000000 must resolve to 0x90000000, got {got:#x?}"
    );
    assert!(
        !got.contains(&0xFFFF_FFFF_9000_0000),
        "the address must not be sign-extended, got {got:#x?}"
    );
}

#[test]
fn mov_with_a_high_bit_address_is_zero_extended() {
    // MOV eax, 0x80000000
    let got = addrs(&[0xB8, 0x00, 0x00, 0x00, 0x80]);
    assert!(
        got.contains(&0x8000_0000),
        "MOV eax, 0x80000000 must resolve to 0x80000000, got {got:#x?}"
    );
}

/// No absolute 32-bit operand may ever produce an address above 2^32 — that is
/// the general property the sign extension broke.
#[test]
fn no_absolute_operand_exceeds_32_bits() {
    for high in [0x80u8, 0x90, 0xC0, 0xFF] {
        for opcode in [0x68u8, 0xB8] {
            let got = addrs(&[opcode, 0x00, 0x00, 0x00, high]);
            for a in &got {
                assert!(
                    *a <= u64::from(u32::MAX),
                    "opcode {opcode:#x} with high byte {high:#x} produced {a:#x}, \
                     which does not fit in 32 bits"
                );
            }
        }
    }
}

/// Addresses below the high-bit boundary were already right and must stay so.
#[test]
fn low_addresses_are_unchanged() {
    let got = addrs(&[0x68, 0x00, 0x20, 0x40, 0x00]); // PUSH 0x00402000
    assert!(got.contains(&0x0040_2000), "got {got:#x?}");
}

// ── CallHierarchy::remove_call ─────────────────────────────────────────────

use rustre_analysis_xref::call_hierarchy::CallHierarchy;

/// The edge `(caller, dest)` carries the NUMBER of call sites, and
/// `remove_call` deletes the whole edge — all N of them. Subtracting only 1
/// from the destination's `call_site_count` left a permanently inflated fan-in
/// for every edge with more than one call site.
#[test]
fn removing_an_edge_removes_all_of_its_call_sites() {
    let mut h = CallHierarchy::new();
    h.add_call(0x1000, 0x2000);
    h.add_call(0x1000, 0x2000);
    h.add_call(0x1000, 0x2000);
    assert_eq!(h.node(0x2000).unwrap().call_site_count, 3);

    assert!(h.remove_call(0x1000, 0x2000));
    assert_eq!(
        h.node(0x2000).unwrap().call_site_count,
        0,
        "nothing calls 0x2000 any more, so its fan-in must be zero"
    );
    assert!(h.callers_of(0x2000).is_empty());
}

/// Removing one caller must not disturb the call sites contributed by another.
#[test]
fn removing_one_edge_leaves_the_other_callers_intact() {
    let mut h = CallHierarchy::new();
    h.add_call(0x1000, 0x3000);
    h.add_call(0x1000, 0x3000);
    h.add_call(0x2000, 0x3000);
    assert_eq!(h.node(0x3000).unwrap().call_site_count, 3);

    h.remove_call(0x1000, 0x3000);
    assert_eq!(
        h.node(0x3000).unwrap().call_site_count,
        1,
        "0x2000 still calls 0x3000 once"
    );
    assert_eq!(h.callers_of(0x3000), vec![0x2000]);
}

/// The invariant: a node's `call_site_count` equals the total number of
/// `add_call`s targeting it that have not been removed.
#[test]
fn call_site_count_tracks_the_surviving_edges() {
    let mut h = CallHierarchy::new();
    for _ in 0..4 {
        h.add_call(0x1000, 0x9000);
    }
    for _ in 0..2 {
        h.add_call(0x2000, 0x9000);
    }
    h.add_call(0x3000, 0x9000);
    assert_eq!(h.node(0x9000).unwrap().call_site_count, 7);

    h.remove_call(0x2000, 0x9000);
    assert_eq!(h.node(0x9000).unwrap().call_site_count, 5);
    h.remove_call(0x1000, 0x9000);
    assert_eq!(h.node(0x9000).unwrap().call_site_count, 1);
    h.remove_call(0x3000, 0x9000);
    assert_eq!(h.node(0x9000).unwrap().call_site_count, 0);
}

/// Removing an edge that does not exist changes nothing.
#[test]
fn removing_a_missing_edge_is_a_no_op() {
    let mut h = CallHierarchy::new();
    h.add_call(0x1000, 0x2000);
    assert!(!h.remove_call(0x5000, 0x2000));
    assert_eq!(h.node(0x2000).unwrap().call_site_count, 1);
}

// ── XrefGraph::subgraph_around ─────────────────────────────────────────────

use rustre_analysis_xref::xref_graph::XrefGraph;

/// For radius >= 2 an edge whose BOTH endpoints get dequeued was copied twice:
/// once by the source's outgoing pass and again by the target's incoming pass.
/// `edge_count`, `in_degree` and `out_degree` all came out inflated.
#[test]
fn a_single_edge_is_copied_once() {
    let mut g = XrefGraph::new();
    g.add_call(0x200, 0x100);

    let sub = g.subgraph_around(0x200, 2);
    assert_eq!(sub.edge_count(), 1, "one edge in, one edge out");
    assert_eq!(sub.in_degree(0x100), 1);
    assert_eq!(sub.out_degree(0x200), 1);
}

/// A radius of 1 was already right and must stay right.
#[test]
fn radius_one_is_unchanged() {
    let mut g = XrefGraph::new();
    g.add_call(0x200, 0x100);

    let sub = g.subgraph_around(0x200, 1);
    assert_eq!(sub.edge_count(), 1);
    assert_eq!(sub.out_degree(0x200), 1);
}

/// The general property: the extracted subgraph never contains more edges
/// than the graph it came from, at any radius.
#[test]
fn a_subgraph_never_has_more_edges_than_the_whole_graph() {
    let mut g = XrefGraph::new();
    g.add_call(0x100, 0x200);
    g.add_call(0x200, 0x300);
    g.add_call(0x300, 0x400);
    g.add_call(0x100, 0x400);
    let total = g.edge_count();

    for radius in 0..5 {
        for center in [0x100u64, 0x200, 0x300, 0x400] {
            let sub = g.subgraph_around(center, radius);
            assert!(
                sub.edge_count() <= total,
                "center {center:#x} radius {radius}: subgraph has {} edges, \
                 the whole graph only has {total}",
                sub.edge_count()
            );
        }
    }
}

/// Every node's degree in the subgraph is bounded by its degree in the
/// original — a duplicated edge shows up here even when the totals happen to
/// line up.
#[test]
fn no_degree_exceeds_the_original() {
    let mut g = XrefGraph::new();
    g.add_call(0x100, 0x200);
    g.add_call(0x200, 0x300);
    g.add_call(0x100, 0x300);

    for radius in 0..4 {
        let sub = g.subgraph_around(0x100, radius);
        for n in [0x100u64, 0x200, 0x300] {
            assert!(
                sub.in_degree(n) <= g.in_degree(n),
                "radius {radius}: in_degree({n:#x}) = {} exceeds the original {}",
                sub.in_degree(n),
                g.in_degree(n)
            );
            assert!(
                sub.out_degree(n) <= g.out_degree(n),
                "radius {radius}: out_degree({n:#x}) = {} exceeds the original {}",
                sub.out_degree(n),
                g.out_degree(n)
            );
        }
    }
}
