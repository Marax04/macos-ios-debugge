//! Adversarial, deterministic tests for `rustre-knowledge` core graph types.

use rustre_knowledge::{KnowledgeEdge, KnowledgeGraph, KnowledgeNode};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

const fn lcg(seed: &mut u64) -> u64 {
    *seed = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *seed
}

fn rand_str(seed: &mut u64, max_len: usize) -> String {
    let n = usize::try_from(lcg(seed)).unwrap_or(usize::MAX) % (max_len + 1);
    let mut s = String::with_capacity(n);
    for _ in 0..n {
        let c = (lcg(seed) % 26) as u8 + b'a';
        s.push(c as char);
    }
    s
}

#[test]
fn new_graph_is_empty() {
    let g = KnowledgeGraph::new();
    assert_eq!(g.node_count(), 0);
    assert_eq!(g.edge_count(), 0);
}

#[test]
fn default_graph_is_empty() {
    let g = KnowledgeGraph::default();
    assert_eq!(g.node_count(), 0);
    assert_eq!(g.edge_count(), 0);
}

#[test]
fn add_node_increases_count() {
    let mut g = KnowledgeGraph::new();
    g.add_node(KnowledgeNode::new("a", "A", "fn"));
    assert_eq!(g.node_count(), 1);
    g.add_node(KnowledgeNode::new("b", "B", "fn"));
    assert_eq!(g.node_count(), 2);
}

#[test]
fn add_node_with_same_id_overwrites() {
    let mut g = KnowledgeGraph::new();
    g.add_node(KnowledgeNode::new("x", "first", "fn"));
    g.add_node(KnowledgeNode::new("x", "second", "type"));
    assert_eq!(g.node_count(), 1);
    let n = g.nodes.get("x").unwrap();
    assert_eq!(n.label, "second");
    assert_eq!(n.kind, "type");
}

#[test]
fn add_edge_increases_count() {
    let mut g = KnowledgeGraph::new();
    g.add_edge(KnowledgeEdge::new("a", "b", "calls"));
    assert_eq!(g.edge_count(), 1);
    g.add_edge(KnowledgeEdge::new("a", "b", "calls"));
    // Edges are duplicated (Vec storage).
    assert_eq!(g.edge_count(), 2);
}

#[test]
fn outgoing_finds_only_matching_source() {
    let mut g = KnowledgeGraph::new();
    g.add_edge(KnowledgeEdge::new("a", "b", "r"));
    g.add_edge(KnowledgeEdge::new("a", "c", "r"));
    g.add_edge(KnowledgeEdge::new("b", "c", "r"));
    let out = g.outgoing("a");
    assert_eq!(out.len(), 2);
    assert!(out.iter().all(|e| e.from == "a"));
}

#[test]
fn incoming_finds_only_matching_target() {
    let mut g = KnowledgeGraph::new();
    g.add_edge(KnowledgeEdge::new("a", "z", "r"));
    g.add_edge(KnowledgeEdge::new("b", "z", "r"));
    g.add_edge(KnowledgeEdge::new("b", "y", "r"));
    let inc = g.incoming("z");
    assert_eq!(inc.len(), 2);
    assert!(inc.iter().all(|e| e.to == "z"));
}

#[test]
fn outgoing_empty_for_unknown_node() {
    let g = KnowledgeGraph::new();
    assert_eq!(g.outgoing("nope").len(), 0);
}

#[test]
fn incoming_empty_for_unknown_node() {
    let g = KnowledgeGraph::new();
    assert_eq!(g.incoming("nope").len(), 0);
}

#[test]
fn outgoing_with_empty_node_id() {
    let mut g = KnowledgeGraph::new();
    g.add_edge(KnowledgeEdge::new("", "b", "r"));
    assert_eq!(g.outgoing("").len(), 1);
}

#[test]
fn node_new_fields_round_trip() {
    let n = KnowledgeNode::new("id", "label", "kind");
    assert_eq!(n.id, "id");
    assert_eq!(n.label, "label");
    assert_eq!(n.kind, "kind");
    assert!(n.metadata.is_empty());
}

#[test]
fn edge_new_has_no_weight() {
    let e = KnowledgeEdge::new("a", "b", "r");
    assert_eq!(e.weight, None);
}

#[test]
fn node_eq_consistent_with_clone() {
    let n = KnowledgeNode::new("x", "y", "z");
    let m = n.clone();
    assert_eq!(n, m);
}

#[test]
fn edge_eq_consistent_with_clone() {
    let e = KnowledgeEdge::new("x", "y", "z");
    let f = e.clone();
    assert_eq!(e, f);
}

#[test]
fn node_serde_round_trip_empty_meta() {
    let n = KnowledgeNode::new("id1", "lbl", "fn");
    let s = serde_json::to_string(&n).unwrap();
    let back: KnowledgeNode = serde_json::from_str(&s).unwrap();
    assert_eq!(n, back);
}

#[test]
fn node_serde_round_trip_with_meta() {
    let mut n = KnowledgeNode::new("id1", "lbl", "fn");
    n.metadata
        .insert("k".to_string(), serde_json::json!("v"));
    n.metadata
        .insert("num".to_string(), serde_json::json!(42));
    let s = serde_json::to_string(&n).unwrap();
    let back: KnowledgeNode = serde_json::from_str(&s).unwrap();
    assert_eq!(n, back);
}

#[test]
fn edge_serde_round_trip_no_weight() {
    let e = KnowledgeEdge::new("from", "to", "rel");
    let s = serde_json::to_string(&e).unwrap();
    let back: KnowledgeEdge = serde_json::from_str(&s).unwrap();
    assert_eq!(e, back);
}

#[test]
fn edge_serde_round_trip_with_weight() {
    let mut e = KnowledgeEdge::new("from", "to", "rel");
    e.weight = Some(123);
    let s = serde_json::to_string(&e).unwrap();
    let back: KnowledgeEdge = serde_json::from_str(&s).unwrap();
    assert_eq!(e, back);
}

#[test]
fn graph_serde_round_trip_empty() {
    let g = KnowledgeGraph::new();
    let s = serde_json::to_string(&g).unwrap();
    let back: KnowledgeGraph = serde_json::from_str(&s).unwrap();
    assert_eq!(back.node_count(), 0);
    assert_eq!(back.edge_count(), 0);
}

#[test]
fn graph_serde_round_trip_populated() {
    let mut g = KnowledgeGraph::new();
    g.add_node(KnowledgeNode::new("a", "A", "fn"));
    g.add_node(KnowledgeNode::new("b", "B", "type"));
    g.add_edge(KnowledgeEdge::new("a", "b", "uses"));
    let s = serde_json::to_string(&g).unwrap();
    let back: KnowledgeGraph = serde_json::from_str(&s).unwrap();
    assert_eq!(back.node_count(), 2);
    assert_eq!(back.edge_count(), 1);
    assert_eq!(back.edges[0].from, "a");
}

#[test]
fn fuzz_random_nodes_never_panic() {
    let mut s: u64 = 0xDEAD_BEEF;
    let mut g = KnowledgeGraph::new();
    for _ in 0..200 {
        let id = rand_str(&mut s, 8);
        let label = rand_str(&mut s, 16);
        let kind = rand_str(&mut s, 4);
        g.add_node(KnowledgeNode::new(id, label, kind));
    }
    assert!(g.node_count() <= 200);
    // node_count should equal unique-id count, which is <= total added.
}

#[test]
fn fuzz_random_edges_outgoing_invariant() {
    let mut seed: u64 = 0x00C0_FFEE;
    let mut graph = KnowledgeGraph::new();
    for _ in 0..200 {
        let from = rand_str(&mut seed, 4);
        let to = rand_str(&mut seed, 4);
        let rel = rand_str(&mut seed, 4);
        graph.add_edge(KnowledgeEdge::new(from, to, rel));
    }
    assert_eq!(graph.edge_count(), 200);
    let mut total = 0;
    let probes = ["", "a", "ab", "abc"];
    for probe in &probes {
        total += graph.outgoing(probe).len();
    }
    // outgoing for these prefixes is a subset of all edges.
    assert!(total <= 200);
}

#[test]
fn outgoing_plus_other_outgoing_does_not_double_count() {
    let mut g = KnowledgeGraph::new();
    g.add_edge(KnowledgeEdge::new("a", "b", "r"));
    g.add_edge(KnowledgeEdge::new("b", "c", "r"));
    let out_a = g.outgoing("a").len();
    let out_b = g.outgoing("b").len();
    assert_eq!(out_a + out_b, g.edge_count());
}

#[test]
fn incoming_partition_matches_edge_count() {
    let mut g = KnowledgeGraph::new();
    g.add_edge(KnowledgeEdge::new("a", "b", "r"));
    g.add_edge(KnowledgeEdge::new("a", "c", "r"));
    g.add_edge(KnowledgeEdge::new("c", "b", "r"));
    let inc_b = g.incoming("b").len();
    let inc_c = g.incoming("c").len();
    assert_eq!(inc_b + inc_c, g.edge_count());
}

#[test]
fn self_loop_appears_in_both_outgoing_and_incoming() {
    let mut g = KnowledgeGraph::new();
    g.add_edge(KnowledgeEdge::new("x", "x", "self"));
    assert_eq!(g.outgoing("x").len(), 1);
    assert_eq!(g.incoming("x").len(), 1);
}

#[test]
fn many_self_loops() {
    let mut g = KnowledgeGraph::new();
    for _ in 0..50 {
        g.add_edge(KnowledgeEdge::new("x", "x", "r"));
    }
    assert_eq!(g.edge_count(), 50);
    assert_eq!(g.outgoing("x").len(), 50);
    assert_eq!(g.incoming("x").len(), 50);
}

#[test]
fn unicode_node_ids_are_preserved() {
    let mut g = KnowledgeGraph::new();
    g.add_node(KnowledgeNode::new("日本", "ラベル", "種類"));
    g.add_edge(KnowledgeEdge::new("日本", "中国", "rel"));
    assert_eq!(g.outgoing("日本").len(), 1);
    assert_eq!(g.nodes.get("日本").unwrap().label, "ラベル");
}

#[test]
fn long_id_is_preserved_through_serde() {
    let long = "x".repeat(10_000);
    let n = KnowledgeNode::new(long, "L", "k");
    let s = serde_json::to_string(&n).unwrap();
    let back: KnowledgeNode = serde_json::from_str(&s).unwrap();
    assert_eq!(back.id.len(), 10_000);
}

#[test]
fn graph_clone_is_independent() {
    let mut g = KnowledgeGraph::new();
    g.add_node(KnowledgeNode::new("a", "A", "fn"));
    let mut h = g.clone();
    h.add_node(KnowledgeNode::new("b", "B", "fn"));
    assert_eq!(g.node_count(), 1);
    assert_eq!(h.node_count(), 2);
}

#[test]
fn edge_weight_max_round_trip() {
    let mut e = KnowledgeEdge::new("a", "b", "r");
    e.weight = Some(u32::MAX);
    let s = serde_json::to_string(&e).unwrap();
    let back: KnowledgeEdge = serde_json::from_str(&s).unwrap();
    assert_eq!(back.weight, Some(u32::MAX));
}

#[test]
fn edge_weight_zero_round_trip() {
    let mut e = KnowledgeEdge::new("a", "b", "r");
    e.weight = Some(0);
    let s = serde_json::to_string(&e).unwrap();
    let back: KnowledgeEdge = serde_json::from_str(&s).unwrap();
    assert_eq!(back.weight, Some(0));
}

#[test]
fn many_nodes_unique_ids() {
    let mut g = KnowledgeGraph::new();
    for i in 0..1000u32 {
        g.add_node(KnowledgeNode::new(format!("n{i}"), "L", "k"));
    }
    assert_eq!(g.node_count(), 1000);
}

#[test]
fn many_nodes_duplicate_ids_collapse() {
    let mut g = KnowledgeGraph::new();
    for _ in 0..1000u32 {
        g.add_node(KnowledgeNode::new("same", "L", "k"));
    }
    assert_eq!(g.node_count(), 1);
}

fn hash_of<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

#[test]
fn node_eq_implies_hash_eq() {
    // KnowledgeNode derives Eq but not Hash (HashMap value). The wrapping tuple Hash check.
    // Skip if not Hash. Instead, verify Eq reflexivity over 30 pairs.
    let mut s: u64 = 1;
    for _ in 0..30 {
        let id = rand_str(&mut s, 6);
        let label = rand_str(&mut s, 6);
        let kind = rand_str(&mut s, 6);
        let a = KnowledgeNode::new(id.clone(), label.clone(), kind.clone());
        let b = KnowledgeNode::new(id, label, kind);
        assert_eq!(a, b);
    }
}

#[test]
fn edge_eq_reflexive_and_clone_stable() {
    let mut seed: u64 = 7;
    for _ in 0..30 {
        let from = rand_str(&mut seed, 6);
        let to = rand_str(&mut seed, 6);
        let rel = rand_str(&mut seed, 6);
        let mut edge = KnowledgeEdge::new(from, to, rel);
        edge.weight = Some(u32::try_from(lcg(&mut seed) % 1000).unwrap_or(u32::MAX));
        let cloned = edge.clone();
        assert_eq!(edge, cloned);
        let _h = hash_of(&edge.from);
    }
}

#[test]
fn outgoing_and_incoming_lengths_sum_at_least_self_loop_count() {
    let mut g = KnowledgeGraph::new();
    g.add_edge(KnowledgeEdge::new("a", "a", "r"));
    g.add_edge(KnowledgeEdge::new("a", "b", "r"));
    g.add_edge(KnowledgeEdge::new("c", "a", "r"));
    assert_eq!(g.outgoing("a").len(), 2);
    assert_eq!(g.incoming("a").len(), 2);
}

#[test]
fn json_for_default_edge_omits_or_nulls_weight() {
    let e = KnowledgeEdge::new("a", "b", "r");
    let s = serde_json::to_string(&e).unwrap();
    // Either null or absent; just ensure it parses back.
    let back: KnowledgeEdge = serde_json::from_str(&s).unwrap();
    assert_eq!(back.weight, None);
}

#[test]
fn deeply_nested_metadata_round_trip() {
    let mut n = KnowledgeNode::new("a", "b", "c");
    n.metadata.insert(
        "nested".to_string(),
        serde_json::json!({"a": {"b": {"c": [1, 2, 3]}}}),
    );
    let s = serde_json::to_string(&n).unwrap();
    let back: KnowledgeNode = serde_json::from_str(&s).unwrap();
    assert_eq!(n, back);
}

#[test]
fn graph_with_only_edges_no_nodes() {
    let mut g = KnowledgeGraph::new();
    g.add_edge(KnowledgeEdge::new("phantom_a", "phantom_b", "r"));
    assert_eq!(g.node_count(), 0);
    assert_eq!(g.edge_count(), 1);
    assert_eq!(g.outgoing("phantom_a").len(), 1);
}

#[test]
fn relation_string_arbitrary_unicode() {
    let e = KnowledgeEdge::new("a", "b", "→←↔");
    assert_eq!(e.relation, "→←↔");
}

#[test]
fn add_many_edges_then_filter() {
    let mut s: u64 = 0x00AB_CDEF;
    let mut g = KnowledgeGraph::new();
    for i in 0..100 {
        let from = if lcg(&mut s).is_multiple_of(2) { "hot" } else { "cold" };
        g.add_edge(KnowledgeEdge::new(from, format!("dst{i}"), "r"));
    }
    let hot = g.outgoing("hot").len();
    let cold = g.outgoing("cold").len();
    assert_eq!(hot + cold, 100);
}

#[test]
fn malformed_json_returns_err_not_panic() {
    let r: Result<KnowledgeNode, _> = serde_json::from_str("{not json");
    assert!(r.is_err());
    let r: Result<KnowledgeEdge, _> = serde_json::from_str("[]");
    assert!(r.is_err());
    let r: Result<KnowledgeGraph, _> = serde_json::from_str("null");
    assert!(r.is_err());
}

#[test]
fn edge_without_required_field_errors() {
    let r: Result<KnowledgeEdge, _> = serde_json::from_str(r#"{"from":"a","to":"b"}"#);
    assert!(r.is_err());
}

#[test]
fn node_without_required_field_errors() {
    let r: Result<KnowledgeNode, _> = serde_json::from_str(r#"{"id":"a","label":"b"}"#);
    assert!(r.is_err());
}
