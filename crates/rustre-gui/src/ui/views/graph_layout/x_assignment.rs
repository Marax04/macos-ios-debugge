// ============================================================================
// graph_layout/x_assignment.rs — Sugiyama step 5
//
// Brandes-Kopf (2001) "Fast and Simple Horizontal Coordinate Assignment":
//   - Build four alignments by combining {up, down} preference with
//     {left, right} priority.
//   - Compact each alignment with respect to per-layer node widths and the
//     minimum horizontal gap.
//   - Average the four x-coordinates per node — this both minimises
//     horizontal-edge bends and keeps the layout compact.
//
// The compaction is the simplified block-graph variant: each node is the
// root of a vertical block; blocks are placed left-to-right with the
// minimum separation `min_gap + (w_left + w_right) / 2`.
//
// Real-node widths come from `LNode.width`; dummy nodes have width 0 so
// long edges can stay straight without bloating their layer.
// ============================================================================

use super::LGraph;
use std::collections::HashMap;

pub fn assign_x(lg: &mut LGraph, min_gap: f32) {
    if lg.nodes.is_empty() {
        return;
    }

    let num_layers = lg.nodes.iter().map(|n| n.layer).max().unwrap_or(0) + 1;

    // Per-layer ordered node ids (by `order`).
    let mut layers: Vec<Vec<u64>> = vec![Vec::new(); num_layers];
    for n in &lg.nodes {
        layers[n.layer].push(n.id);
    }
    for layer in &mut layers {
        layer.sort_by_key(|id| lg.node(*id).order);
    }

    // Run four compactions and average. For pragmatic simplicity all four
    // variants share the same alignment skeleton (median upper neighbour for
    // up-preferences, lower for down) but choose left/right tie-break.
    let xs_ul = compact_pass(lg, &layers, min_gap, true, true);
    let xs_ur = compact_pass(lg, &layers, min_gap, true, false);
    let xs_dl = compact_pass(lg, &layers, min_gap, false, true);
    let xs_dr = compact_pass(lg, &layers, min_gap, false, false);

    // Per-node average of the four candidates, then translate so the
    // layout is centred around x = 0.
    let mut avg: HashMap<u64, f32> = HashMap::new();
    for id in xs_ul.keys() {
        let a = xs_ul[id];
        let b = xs_ur[id];
        let c = xs_dl[id];
        let d = xs_dr[id];
        avg.insert(*id, (a + b + c + d) * 0.25);
    }

    // Centre horizontally.
    let mut min_x = f32::MAX;
    let mut max_x = f32::MIN;
    for (id, &x) in &avg {
        let w = lg.node(*id).width;
        if x < min_x {
            min_x = x;
        }
        if x + w > max_x {
            max_x = x + w;
        }
    }
    let shift = -((min_x + max_x) * 0.5);
    for n in &mut lg.nodes {
        if let Some(&x) = avg.get(&n.id) {
            n.x = x + shift;
        }
    }
}

/// Compact one layer at a time, placing each node to the right of the
/// previous one on the same layer with `min_gap + (w_prev + w_cur)/2`
/// separation between centres, then biasing toward the median neighbour
/// position in the adjacent layer dictated by `prefer_up`/`prefer_left`.
fn compact_pass(
    lg: &LGraph,
    layers: &[Vec<u64>],
    min_gap: f32,
    prefer_up: bool,
    prefer_left: bool,
) -> HashMap<u64, f32> {
    let mut x: HashMap<u64, f32> = HashMap::new();

    // First pass: greedy left-packed coordinates per layer.
    for layer in layers {
        let mut cursor = 0.0f32;
        let iter: Box<dyn Iterator<Item = &u64>> = if prefer_left {
            Box::new(layer.iter())
        } else {
            Box::new(layer.iter().rev())
        };
        let mut placed: Vec<(u64, f32)> = Vec::new();
        for &id in iter {
            let w = lg.node(id).width;
            placed.push((id, cursor + w * 0.5));
            cursor += w + min_gap;
        }
        if !prefer_left {
            // Reverse so leftmost has smallest x.
            placed.reverse();
            let mut c = 0.0f32;
            for entry in &mut placed {
                let w = lg.node(entry.0).width;
                entry.1 = c + w * 0.5;
                c += w + min_gap;
            }
        }
        for (id, cx) in placed {
            x.insert(id, cx - lg.node(id).width * 0.5);
        }
    }

    // Second pass: pull each node toward the median of its adjacent-layer
    // neighbours in the preferred direction (up or down).
    for li in 0..layers.len() {
        let layer = &layers[li];
        let adj_layer_idx: Option<usize> = if prefer_up {
            if li == 0 {
                None
            } else {
                Some(li - 1)
            }
        } else if li + 1 < layers.len() {
            Some(li + 1)
        } else {
            None
        };
        let Some(ali) = adj_layer_idx else {
            continue;
        };
        let mut targets: Vec<(u64, f32)> = Vec::new();
        for &id in layer {
            let mut neigh_xs: Vec<f32> = Vec::new();
            for e in &lg.edges {
                if e.from == id && lg.node(e.to).layer == ali {
                    if let Some(&nx) = x.get(&e.to) {
                        neigh_xs.push(nx + lg.node(e.to).width * 0.5);
                    }
                } else if e.to == id && lg.node(e.from).layer == ali {
                    if let Some(&nx) = x.get(&e.from) {
                        neigh_xs.push(nx + lg.node(e.from).width * 0.5);
                    }
                }
            }
            if !neigh_xs.is_empty() {
                neigh_xs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                let n = neigh_xs.len();
                let med = if n % 2 == 1 {
                    neigh_xs[n / 2]
                } else {
                    (neigh_xs[n / 2 - 1] + neigh_xs[n / 2]) * 0.5
                };
                targets.push((id, med - lg.node(id).width * 0.5));
            }
        }

        // Apply targets while enforcing left-to-right non-overlap on the
        // layer (so the median pull never crashes neighbours through each
        // other).
        let mut new_x: HashMap<u64, f32> = layer
            .iter()
            .map(|id| (*id, *x.get(id).unwrap_or(&0.0)))
            .collect();
        for (id, t) in targets {
            new_x.insert(id, t);
        }
        let mut prev_right: Option<f32> = None;
        for &id in layer {
            let w = lg.node(id).width;
            let mut xi = new_x[&id];
            if let Some(pr) = prev_right {
                let min_left = pr + min_gap;
                if xi < min_left {
                    xi = min_left;
                }
            }
            new_x.insert(id, xi);
            prev_right = Some(xi + w);
        }
        for &id in layer {
            x.insert(id, new_x[&id]);
        }
    }

    x
}
