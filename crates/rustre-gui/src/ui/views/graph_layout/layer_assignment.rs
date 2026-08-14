// ============================================================================
// graph_layout/layer_assignment.rs — Sugiyama step 2
//
// Longest-path layering on the DAG produced after cycle removal:
//   layer(v) = 1 + max(layer(u) for u in predecessors(v))
//   layer(v) = 0 if v has no predecessors.
//
// We then build the initial `LGraph` (one LNode per real node, one LEdge
// per real edge, in the DAG direction — back-edges treated as if flipped).
// ============================================================================

use super::{LEdge, LGraph, LNode};
use crate::ui::panels::graph_view::GraphData;
use std::collections::{HashMap, HashSet};

pub fn assign_layers(graph: &GraphData, reversed: &[usize]) -> LGraph {
    let reversed_set: HashSet<usize> = reversed.iter().copied().collect();

    // Build DAG adjacency: predecessor lists.
    let mut preds: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut succs: HashMap<u64, Vec<u64>> = HashMap::new();
    for n in &graph.nodes {
        preds.entry(n.id).or_default();
        succs.entry(n.id).or_default();
    }
    for (i, e) in graph.edges.iter().enumerate() {
        let (from, to) = if reversed_set.contains(&i) {
            (e.to, e.from)
        } else {
            (e.from, e.to)
        };
        preds.entry(to).or_default().push(from);
        succs.entry(from).or_default().push(to);
    }

    // Topological order via Kahn's algorithm.
    let mut indeg: HashMap<u64, usize> = HashMap::new();
    for (k, ps) in &preds {
        indeg.insert(*k, ps.len());
    }
    let mut queue: std::collections::VecDeque<u64> = std::collections::VecDeque::new();
    for (k, &d) in &indeg {
        if d == 0 {
            queue.push_back(*k);
        }
    }
    let mut topo: Vec<u64> = Vec::with_capacity(graph.nodes.len());
    while let Some(v) = queue.pop_front() {
        topo.push(v);
        if let Some(ss) = succs.get(&v).cloned() {
            for s in ss {
                if let Some(d) = indeg.get_mut(&s) {
                    *d = d.saturating_sub(1);
                    if *d == 0 {
                        queue.push_back(s);
                    }
                }
            }
        }
    }
    // Fallback: any nodes still missing (shouldn't happen post cycle-removal)
    // are appended so layering still terminates.
    for n in &graph.nodes {
        if !topo.contains(&n.id) {
            topo.push(n.id);
        }
    }

    // Longest-path layer per node.
    let mut layer: HashMap<u64, usize> = HashMap::new();
    for v in &topo {
        let mut l = 0usize;
        if let Some(ps) = preds.get(v) {
            for p in ps {
                if let Some(&pl) = layer.get(p) {
                    l = l.max(pl + 1);
                }
            }
        }
        layer.insert(*v, l);
    }

    // Build LGraph.
    let mut lg = LGraph::default();
    let mut max_id: u64 = 0;
    for n in &graph.nodes {
        max_id = max_id.max(n.id);
        let l = *layer.get(&n.id).unwrap_or(&0);
        lg.add_node(LNode {
            id: n.id,
            layer: l,
            order: 0,
            width: n.width,
            height: n.height,
            x: 0.0,
            y: 0.0,
            is_dummy: false,
        });
    }
    lg.next_dummy_id = max_id + 1;

    for (i, e) in graph.edges.iter().enumerate() {
        let (from, to) = if reversed_set.contains(&i) {
            (e.to, e.from)
        } else {
            (e.from, e.to)
        };
        // Skip self-loops — they aren't part of the layered graph; the
        // renderer handles them with a back-curl.
        if from == to {
            continue;
        }
        lg.edges.push(LEdge {
            from,
            to,
            reversed: reversed_set.contains(&i),
            orig: i,
        });
    }

    // Initial per-layer order: stable by insertion order.
    let mut layer_counters: HashMap<usize, usize> = HashMap::new();
    for n in &mut lg.nodes {
        let c = layer_counters.entry(n.layer).or_insert(0);
        n.order = *c;
        *c += 1;
    }

    lg
}
