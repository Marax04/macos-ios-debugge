// ============================================================================
// ui/views/graph_layout/mod.rs
//
// Sugiyama-style layered graph layout used by the CFG / call-graph panel.
//
// Pipeline (Sugiyama 1981; Eiglsperger-Siebenhaller-Kaufmann 2005;
// Brandes-Kopf 2001):
//
//   1. cycle_removal      — DFS reverse back-edges, tag them as reversed
//   2. layer_assignment   — longest-path layering
//   3. insert_dummies     — split long edges through height-0/width-0 dummies
//   4. crossing_reduction — 24 sweep median/barycenter, keep best ordering
//   5. x_assignment       — Brandes-Kopf 4-way priority alignment + average
//   6. y_assignment       — uniform per-layer y with adaptive vertical spacing
//
// The pipeline writes (x, y) on real nodes and produces, per edge, the
// ordered list of waypoint (x, y) coordinates threading through the dummy
// chain. Edge-routing into actual polylines is a separate concern handled
// by the rendering pass.
// ============================================================================

pub mod cycle_removal;
pub mod layer_assignment;
pub mod dummies;
pub mod crossing_reduction;
pub mod x_assignment;

use crate::ui::panels::graph_view::GraphData;
use std::collections::HashMap;

/// Horizontal gap between adjacent nodes on the same layer (px).
pub const H_GAP: f32 = 24.0;
/// Vertical gap between adjacent layers (px).
pub const V_GAP: f32 = 48.0;
/// Minimum sweeps (12 down + 12 up).
pub const SWEEP_COUNT: usize = 24;

/// A node id inside the working graph. We mirror real ids and synthesise
/// fresh ids for dummy nodes by offsetting beyond the max real id.
pub type NodeId = u64;

/// A single layered graph entry. Dummy nodes have `is_dummy = true`,
/// zero width / height, and no corresponding real `GraphNode`.
#[derive(Clone, Debug)]
pub struct LNode {
    pub id: NodeId,
    pub layer: usize,
    pub order: usize, // x-order within the layer
    pub width: f32,
    pub height: f32,
    pub x: f32,
    pub y: f32,
    pub is_dummy: bool,
}

/// An edge in the proper (layered + dummy-split) graph. Always points from
/// a node on layer L to a node on layer L+1. The `reversed` flag is carried
/// through from cycle removal so the renderer can flip arrowheads.
#[derive(Clone, Debug)]
pub struct LEdge {
    pub from: NodeId,
    pub to: NodeId,
    pub reversed: bool,
    /// Original GraphData edge index this proper edge belongs to (so we
    /// can stitch the waypoint chain back onto the source edge).
    pub orig: usize,
}

/// The full intermediate representation the pipeline operates on.
#[derive(Default, Debug)]
pub struct LGraph {
    pub nodes: Vec<LNode>,
    pub edges: Vec<LEdge>,
    pub index: HashMap<NodeId, usize>, // id -> index into nodes
    pub next_dummy_id: NodeId,
}

impl LGraph {
    pub fn node(&self, id: NodeId) -> &LNode {
        &self.nodes[self.index[&id]]
    }
    pub fn node_mut(&mut self, id: NodeId) -> &mut LNode {
        let i = self.index[&id];
        &mut self.nodes[i]
    }
    pub fn add_node(&mut self, n: LNode) {
        self.index.insert(n.id, self.nodes.len());
        self.nodes.push(n);
    }
    pub fn fresh_dummy_id(&mut self) -> NodeId {
        let id = self.next_dummy_id;
        self.next_dummy_id += 1;
        id
    }
}

/// Run the full pipeline against a `GraphData`. Writes node x/y/width/height
/// in place and fills each edge's `waypoints` with the dummy-node coordinates
/// it threads through (empty for direct layer-to-layer edges).
pub fn run(graph: &mut GraphData) {
    if graph.nodes.is_empty() {
        return;
    }

    // Auto-size every node from its own label + sublabel so no text is ever
    // clipped — mirrors analysis/graph_layout.rs sizing constants.
    const GLYPH_W: f32 = 7.2;
    const H_PAD: f32 = 10.0;
    const V_PAD: f32 = 6.0;
    const HEADER_H: f32 = 18.0;
    const ROW_H: f32 = 14.0;
    const ADDR_GUTTER: f32 = 90.0;
    for node in &mut graph.nodes {
        let header_chars = node.label.chars().count();
        let sub_chars = node.sublabel.chars().count();
        let max_chars = header_chars.max(sub_chars).max(8);
        let lines = if node.sublabel.is_empty() { 0.0 } else { 1.0 };
        let extra = if node.instruction_count > 0 { ROW_H } else { 0.0 };
        let w = ((max_chars as f32) * GLYPH_W + 2.0 * H_PAD + ADDR_GUTTER).max(120.0);
        let h = HEADER_H + lines * ROW_H + V_PAD + extra;
        node.width = w;
        node.height = h;
    }

    // 1. Cycle removal — flip back-edges so the remaining graph is a DAG.
    let reversed = cycle_removal::reverse_back_edges(graph);

    // 2. Build LGraph with longest-path layer assignment.
    let mut lg = layer_assignment::assign_layers(graph, &reversed);

    // 3. Split long edges with dummy nodes.
    dummies::insert_dummies(&mut lg);

    // 4. Crossing reduction — best-of 24 sweeps.
    crossing_reduction::reduce_crossings(&mut lg, SWEEP_COUNT);

    // 5. X-coordinate assignment — Brandes-Kopf 4-way average.
    x_assignment::assign_x(&mut lg, H_GAP);

    // 6. Y-coordinate assignment — uniform per layer, adaptive gap.
    assign_y(&mut lg, V_GAP);

    // Stitch coordinates back onto GraphData.
    write_back(graph, &lg);

    // Unreverse the back-edges we flipped (preserve original direction; the
    // `reversed` flag on GraphEdge is what the renderer uses now).
    for &i in &reversed {
        let e = &mut graph.edges[i];
        std::mem::swap(&mut e.from, &mut e.to);
        e.reversed = true;
    }
}

/// Uniform Y per layer, gap = max(adjacent layer heights) + V_GAP.
fn assign_y(lg: &mut LGraph, v_gap: f32) {
    // Find max height per layer.
    let mut layer_heights: Vec<f32> = Vec::new();
    for n in &lg.nodes {
        if n.layer >= layer_heights.len() {
            layer_heights.resize(n.layer + 1, 0.0);
        }
        if n.height > layer_heights[n.layer] {
            layer_heights[n.layer] = n.height;
        }
    }
    // Cumulative y per layer.
    let mut y_at: Vec<f32> = Vec::with_capacity(layer_heights.len());
    let mut acc = 0.0f32;
    for (li, &h) in layer_heights.iter().enumerate() {
        y_at.push(acc);
        if li + 1 < layer_heights.len() {
            let next_h = layer_heights[li + 1];
            acc += h.max(next_h) + v_gap;
        }
    }
    for n in &mut lg.nodes {
        n.y = y_at[n.layer];
    }
}

/// Copy real-node coordinates back to GraphData, and assemble waypoint
/// chains for each original edge by walking its dummy chain in layer order.
fn write_back(graph: &mut GraphData, lg: &LGraph) {
    for n in &lg.nodes {
        if n.is_dummy {
            continue;
        }
        if let Some(real) = graph.nodes.iter_mut().find(|g| g.id == n.id) {
            real.x = n.x;
            real.y = n.y;
        }
    }

    // Build per-original-edge waypoint chains from dummy LEdges.
    let edge_count = graph.edges.len();
    let mut chains: Vec<Vec<(usize, f32, f32)>> = vec![Vec::new(); edge_count];
    for le in &lg.edges {
        let from = lg.node(le.from);
        let to = lg.node(le.to);
        if from.is_dummy {
            chains[le.orig].push((from.layer, from.x, from.y));
        }
        if to.is_dummy {
            chains[le.orig].push((to.layer, to.x, to.y));
        }
    }
    for (i, chain) in chains.into_iter().enumerate() {
        let mut dedup: Vec<(usize, f32, f32)> = chain;
        dedup.sort_by_key(|(l, _, _)| *l);
        dedup.dedup_by_key(|(l, _, _)| *l);
        graph.edges[i].waypoints = dedup.into_iter().map(|(_, x, y)| (x, y)).collect();
    }
}
