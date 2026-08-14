// ============================================================================
// graph_layout/cycle_removal.rs — Sugiyama step 1
//
// DFS over the graph; any edge whose head is on the DFS stack ("gray" node)
// is a back-edge. Collect their indices; the caller flips them after layout
// and tags them as `reversed` on the original GraphEdge.
// ============================================================================

use crate::ui::panels::graph_view::GraphData;
use std::collections::{HashMap, HashSet};

pub fn reverse_back_edges(graph: &GraphData) -> Vec<usize> {
    // Adjacency: node id -> list of (edge_index, target)
    let mut adj: HashMap<u64, Vec<(usize, u64)>> = HashMap::new();
    for (i, e) in graph.edges.iter().enumerate() {
        adj.entry(e.from).or_default().push((i, e.to));
    }

    enum Color {
        Gray,
        Black,
    }
    let mut color: HashMap<u64, Color> = HashMap::new();
    let mut reversed: HashSet<usize> = HashSet::new();

    // Iterative DFS. Stack entries are (node_id, child_iter_pos).
    let roots: Vec<u64> = if let Some(r) = graph.root_id {
        let mut v = vec![r];
        for n in &graph.nodes {
            if n.id != r {
                v.push(n.id);
            }
        }
        v
    } else {
        graph.nodes.iter().map(|n| n.id).collect()
    };

    for start in roots {
        if color.contains_key(&start) {
            continue;
        }
        let mut stack: Vec<(u64, usize)> = vec![(start, 0)];
        color.insert(start, Color::Gray);
        while let Some(&(nid, ci)) = stack.last() {
            let children = adj.get(&nid).cloned().unwrap_or_default();
            if ci >= children.len() {
                color.insert(nid, Color::Black);
                stack.pop();
                continue;
            }
            // Advance the iterator on the stack.
            if let Some(last) = stack.last_mut() {
                last.1 = ci + 1;
            }
            let (edge_i, child) = children[ci];
            match color.get(&child) {
                Some(Color::Gray) => {
                    // Back-edge — record and skip.
                    reversed.insert(edge_i);
                }
                Some(Color::Black) => {
                    // Cross/forward edge — fine.
                }
                None => {
                    color.insert(child, Color::Gray);
                    stack.push((child, 0));
                }
            }
        }
    }

    let mut out: Vec<usize> = reversed.into_iter().collect();
    out.sort_unstable();
    out
}
