// ============================================================================
// graph_layout/crossing_reduction.rs — Sugiyama step 4
//
// Eiglsperger-style median/barycenter two-layer sweep:
//   - For each layer i (processed in alternating down/up direction), compute
//     each node's median of neighbour positions in the *fixed* adjacent
//     layer. Sort nodes by median; break ties by current order.
//   - Count crossings between adjacent layers; keep the best ordering across
//     all sweeps.
//   - 24 sweeps total (12 down, 12 up).
// ============================================================================

use super::LGraph;
use std::collections::HashMap;

pub fn reduce_crossings(lg: &mut LGraph, sweeps: usize) {
    if lg.nodes.is_empty() {
        return;
    }
    let num_layers = lg.nodes.iter().map(|n| n.layer).max().unwrap_or(0) + 1;
    if num_layers < 2 {
        return;
    }

    // Snapshot the current ordering as the running best.
    let mut best_order: HashMap<u64, usize> =
        lg.nodes.iter().map(|n| (n.id, n.order)).collect();
    let mut best_cross = count_total_crossings(lg, num_layers);

    for s in 0..sweeps {
        let down = s % 2 == 0;
        if down {
            for li in 1..num_layers {
                sweep_layer(lg, li, li - 1);
            }
        } else {
            for li in (0..num_layers - 1).rev() {
                sweep_layer(lg, li, li + 1);
            }
        }
        let c = count_total_crossings(lg, num_layers);
        if c < best_cross {
            best_cross = c;
            best_order = lg.nodes.iter().map(|n| (n.id, n.order)).collect();
        }
    }

    // Restore the best ordering observed.
    for n in &mut lg.nodes {
        if let Some(&o) = best_order.get(&n.id) {
            n.order = o;
        }
    }
}

/// Resort the nodes on `target_layer` by the median of their neighbour
/// orders on `fixed_layer`, breaking ties by current order.
fn sweep_layer(lg: &mut LGraph, target_layer: usize, fixed_layer: usize) {
    // Collect (id, order) on fixed layer for quick lookup.
    let fixed_orders: HashMap<u64, usize> = lg
        .nodes
        .iter()
        .filter(|n| n.layer == fixed_layer)
        .map(|n| (n.id, n.order))
        .collect();

    // For each node on target layer, gather neighbour orders.
    let target_ids: Vec<u64> = lg
        .nodes
        .iter()
        .filter(|n| n.layer == target_layer)
        .map(|n| n.id)
        .collect();

    let mut median_for: HashMap<u64, f32> = HashMap::new();
    for &id in &target_ids {
        let mut ns: Vec<usize> = Vec::new();
        for e in &lg.edges {
            if e.from == id {
                if let Some(&p) = fixed_orders.get(&e.to) {
                    ns.push(p);
                }
            } else if e.to == id {
                if let Some(&p) = fixed_orders.get(&e.from) {
                    ns.push(p);
                }
            }
        }
        let m = if ns.is_empty() {
            // No neighbour on fixed layer — pin to current order.
            let cur = lg.node(id).order as f32;
            cur
        } else {
            ns.sort_unstable();
            let n = ns.len();
            // Median (lower-median for even counts is fine; use float average).
            if n % 2 == 1 {
                ns[n / 2] as f32
            } else {
                (ns[n / 2 - 1] as f32 + ns[n / 2] as f32) * 0.5
            }
        };
        median_for.insert(id, m);
    }

    // Sort target ids by median (ties broken by current order).
    let mut sorted = target_ids.clone();
    sorted.sort_by(|a, b| {
        let ma = median_for[a];
        let mb = median_for[b];
        ma.partial_cmp(&mb)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| lg.node(*a).order.cmp(&lg.node(*b).order))
    });
    for (new_order, id) in sorted.into_iter().enumerate() {
        lg.node_mut(id).order = new_order;
    }
}

/// Count crossings between every pair of adjacent layers, summed.
fn count_total_crossings(lg: &LGraph, num_layers: usize) -> usize {
    let mut total = 0usize;
    for li in 0..num_layers.saturating_sub(1) {
        total += count_crossings_between(lg, li, li + 1);
    }
    total
}

/// Brute-force pair counting: for every pair of edges going from layer `a`
/// to layer `b`, increment if their endpoint orders cross. Quadratic in
/// edge count between the two layers, fine at CFG scale.
fn count_crossings_between(lg: &LGraph, a: usize, b: usize) -> usize {
    let order_of: HashMap<u64, usize> = lg
        .nodes
        .iter()
        .filter(|n| n.layer == a || n.layer == b)
        .map(|n| (n.id, n.order))
        .collect();

    let edges: Vec<(usize, usize)> = lg
        .edges
        .iter()
        .filter_map(|e| {
            let lf = lg.node(e.from).layer;
            let lt = lg.node(e.to).layer;
            if lf == a && lt == b {
                Some((order_of[&e.from], order_of[&e.to]))
            } else {
                None
            }
        })
        .collect();

    let mut c = 0usize;
    for i in 0..edges.len() {
        for j in (i + 1)..edges.len() {
            let (u1, v1) = edges[i];
            let (u2, v2) = edges[j];
            if (u1 < u2 && v1 > v2) || (u1 > u2 && v1 < v2) {
                c += 1;
            }
        }
    }
    c
}
