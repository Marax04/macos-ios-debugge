// ============================================================================
// graph_layout/dummies.rs — Sugiyama step 3
//
// For every edge (u -> v) with layer(v) - layer(u) > 1, insert k-1 dummy
// nodes of width 0 height 0 on the intermediate layers, and replace the
// original LEdge with a chain of unit-span LEdges that all share the same
// `orig` index so the renderer can reassemble the waypoint list.
// ============================================================================

use super::{LEdge, LGraph, LNode};

pub fn insert_dummies(lg: &mut LGraph) {
    let mut new_edges: Vec<LEdge> = Vec::with_capacity(lg.edges.len());
    let edges = std::mem::take(&mut lg.edges);

    for e in edges {
        let from_layer = lg.node(e.from).layer;
        let to_layer = lg.node(e.to).layer;
        if to_layer <= from_layer + 1 {
            new_edges.push(e);
            continue;
        }

        let mut prev = e.from;
        for l in (from_layer + 1)..to_layer {
            let did = lg.fresh_dummy_id();
            lg.add_node(LNode {
                id: did,
                layer: l,
                order: 0, // re-numbered after dummies, before crossing reduction
                width: 0.0,
                height: 0.0,
                x: 0.0,
                y: 0.0,
                is_dummy: true,
            });
            new_edges.push(LEdge {
                from: prev,
                to: did,
                reversed: e.reversed,
                orig: e.orig,
            });
            prev = did;
        }
        new_edges.push(LEdge {
            from: prev,
            to: e.to,
            reversed: e.reversed,
            orig: e.orig,
        });
    }

    lg.edges = new_edges;

    // Renumber `order` per layer (real nodes keep their relative order,
    // newly-inserted dummies are appended).
    let mut counters: std::collections::HashMap<usize, usize> =
        std::collections::HashMap::new();
    // First real nodes (preserve their previous order), then dummies.
    let mut idx: Vec<usize> = (0..lg.nodes.len()).collect();
    idx.sort_by_key(|&i| (lg.nodes[i].is_dummy, lg.nodes[i].order));
    for i in idx {
        let n = &mut lg.nodes[i];
        let c = counters.entry(n.layer).or_insert(0);
        n.order = *c;
        *c += 1;
    }
}
