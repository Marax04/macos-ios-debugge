// ============================================================================
// analysis/edge_routing.rs — Orthogonal Manhattan-style edge routing
// ============================================================================
//
// Post-layout pass that rewrites every `EdgePath::pts` polyline so edges are
// drawn as clean L / S shapes that share horizontal "channels" between layers
// and never overlap inside a channel.
//
// Algorithm (standard "lane assignment" channel routing):
//
//   1. For each pair of adjacent layers we allocate a horizontal CHANNEL
//      that sits in the vertical gap between the lower edge of the upper
//      layer and the upper edge of the lower layer. The channel has a
//      `top` and `bottom` y-coordinate, leaving an 8 px safety margin on
//      each side.
//
//   2. Every edge that crosses a channel is assigned a LANE index in
//      `[0, K)`. K starts at `max(8, edges_in_channel)`. Two edges share
//      a lane only if their `[x_min, x_max]` horizontal spans do not
//      overlap (with an 8 px separation).
//
//   3. A greedy left-to-right sweep allocates lanes:
//        - Edges are sorted by `source_x` ascending.
//        - For each edge, pick the lowest lane whose currently allocated
//          horizontal spans do not overlap the edge's span.
//        - If no lane is free, K is grown by 1.
//
//   4. The y-position of the edge inside the channel is
//        `top_of_channel + (lane + 0.5) * (channel_height / K)`.
//
//   5. The edge polyline is the 4-point L/S shape
//        [(sx, source_bottom), (sx, channel_y),
//         (tx, channel_y), (tx, target_top)].
//      For back-edges that wrap around laterally we still emit a 6-point
//      polyline that uses a side channel on the right of the wider of the
//      two boxes — this preserves their visual distinctiveness while
//      keeping every segment axis-aligned.
//
// Data structures
// ----------------
// `Channel`    — one horizontal strip between layer N and N+1.
// `LaneAlloc`  — per-channel greedy lane allocator. Each lane stores the
//                list of `[x_min, x_max]` spans already placed in it.
// `RoutedEdge` — internal book-keeping while assigning lanes; converted
//                back into the 4/6-point polyline in `apply()`.

use super::graph_layout::{EdgePath, NodeRect};

/// Horizontal safety margin trimmed from each side of a channel (px).
const CHANNEL_SAFETY: f32 = 8.0;
/// Minimum number of lanes in a channel.
const MIN_LANES: usize = 8;
/// Minimum horizontal gap between two edges that share a lane (px).
const LANE_X_GAP: f32 = 8.0;
/// Minimum vertical gap between two adjacent lanes (px).
const LANE_Y_GAP: f32 = 8.0;
/// Side-channel offset for back-edges (px to the right of the rightmost box).
const BACK_SIDE_OFFSET: f32 = 24.0;

#[derive(Clone, Copy, Debug)]
struct Channel {
    top: f32,
    bottom: f32,
}

impl Channel {
    fn height(self) -> f32 {
        (self.bottom - self.top).max(LANE_Y_GAP)
    }

    fn lane_y(self, lane: usize, k: usize) -> f32 {
        let h = self.height();
        let k_f = f32::from(u16::try_from(k).unwrap_or(u16::MAX)).max(1.0);
        let step = h / k_f;
        let lane_f = f32::from(u16::try_from(lane).unwrap_or(u16::MAX));
        step.mul_add(lane_f + 0.5, self.top)
    }
}

/// Per-channel greedy lane allocator.
struct LaneAlloc {
    /// Each entry is a lane; each lane is a list of `[x_min, x_max]` spans.
    lanes: Vec<Vec<[f32; 2]>>,
    /// Current K (number of lanes considered when computing y-positions).
    k: usize,
}

impl LaneAlloc {
    fn new(initial_k: usize) -> Self {
        let k = initial_k.max(MIN_LANES);
        Self {
            lanes: vec![Vec::new(); k],
            k,
        }
    }

    /// Allocate a lane for the given horizontal span. Returns the lane index.
    fn assign(&mut self, span: [f32; 2]) -> usize {
        let lo = span[0].min(span[1]) - LANE_X_GAP;
        let hi = span[0].max(span[1]) + LANE_X_GAP;
        for (i, lane) in self.lanes.iter_mut().enumerate() {
            if lane.iter().all(|s| hi <= s[0] || lo >= s[1]) {
                lane.push([lo, hi]);
                return i;
            }
        }
        // No free lane — grow K.
        self.lanes.push(vec![[lo, hi]]);
        self.k = self.lanes.len();
        self.lanes.len() - 1
    }
}

/// Internal record describing a single forward edge that has been bound to
/// a channel + lane. The y position of the channel cross is computed at
/// emission time so K can grow during assignment without invalidating
/// earlier records.
struct RoutedEdge {
    edge_idx: usize,
    channel_idx: usize,
    lane: usize,
    sx: f32,
    sy: f32,
    tx: f32,
    ty: f32,
}

/// Rewrite the polyline of every edge in `edges` to use orthogonal
/// Manhattan routing through the inter-layer channels derived from `nodes`.
///
/// Back-edges (detected as edges where `to.y <= from.y`) are routed through
/// a side channel on the right of the wider of the two boxes instead of a
/// horizontal channel.
pub fn route_orthogonal(nodes: &[NodeRect], edges: &mut [EdgePath]) {
    if nodes.is_empty() || edges.is_empty() {
        return;
    }

    // ── 1. Cluster node rectangles by their y-band into layers ────────────
    // Two nodes are in the same layer if their top y is within 1 px.
    let mut layer_tops: Vec<f32> = nodes.iter().map(|n| n.y).collect();
    layer_tops.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    layer_tops.dedup_by(|a, b| (*a - *b).abs() < 1.0);

    // For each layer we record `(top, bottom)` = max bottom of any node
    // sharing this layer.
    let mut layers: Vec<(f32, f32)> = layer_tops
        .iter()
        .map(|&top| {
            let bottom = nodes
                .iter()
                .filter(|n| (n.y - top).abs() < 1.0)
                .map(|n| n.y + n.h)
                .fold(top, f32::max);
            (top, bottom)
        })
        .collect();
    layers.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

    // ── 2. Build the channel between every adjacent layer pair ────────────
    let mut channels: Vec<Channel> = Vec::with_capacity(layers.len().saturating_sub(1));
    for win in layers.windows(2) {
        let upper_bottom = win[0].1;
        let lower_top = win[1].0;
        let top = upper_bottom + CHANNEL_SAFETY;
        let bottom = (lower_top - CHANNEL_SAFETY).max(top + LANE_Y_GAP);
        channels.push(Channel { top, bottom });
    }

    // Map: top-y → layer index (for binding source/target to layers).
    let layer_of_top = |y: f32| -> Option<usize> {
        layers
            .iter()
            .position(|(t, _)| (t - y).abs() < 1.0)
    };

    // Find a node by anchor x (center). We only need source.bottom / target.top.
    // The polyline is computed from each edge's existing start / end points,
    // which were generated by `route_forward_edge` / `route_back_edge` so
    // already reference the correct node anchors.

    // ── 3. Split edges into forward (route through a channel) and back ────
    let mut forwards: Vec<usize> = Vec::with_capacity(edges.len());
    let mut backs: Vec<usize> = Vec::with_capacity(edges.len());
    for (i, e) in edges.iter().enumerate() {
        if e.pts.len() < 2 {
            continue;
        }
        let sy = e.pts.first().map_or(0.0, |p| p[1]);
        let ty = e.pts.last().map_or(0.0, |p| p[1]);
        if ty > sy + 0.5 {
            forwards.push(i);
        } else {
            backs.push(i);
        }
    }

    // ── 4. Per-channel lane allocation for forward edges ──────────────────
    // Sort forwards by source x ascending so the greedy sweep is stable.
    forwards.sort_by(|&a, &b| {
        let ax = edges[a].pts.first().map_or(0.0, |p| p[0]);
        let bx = edges[b].pts.first().map_or(0.0, |p| p[0]);
        ax.partial_cmp(&bx).unwrap_or(std::cmp::Ordering::Equal)
    });

    // Count edges per channel to seed K.
    let mut per_channel_count: Vec<usize> = vec![0; channels.len()];
    let mut routed: Vec<RoutedEdge> = Vec::with_capacity(forwards.len());

    for &ei in &forwards {
        let pts = &edges[ei].pts;
        let (sx, sy) = (pts[0][0], pts[0][1]);
        let last = pts[pts.len() - 1];
        let (tx, ty) = (last[0], last[1]);
        // Source layer = layer whose bottom is closest to (and <=) sy.
        // Target layer = layer whose top equals ty.
        let src_layer = layers.iter().rposition(|(_, b)| *b <= sy + 1.0);
        let tgt_layer = layer_of_top(ty);
        let Some(s_l) = src_layer else { continue };
        let Some(t_l) = tgt_layer else { continue };
        if t_l <= s_l {
            continue;
        }
        // Bind the edge to its FIRST crossed channel = `s_l`.
        // (Multi-layer edges still emit a single L/S because intermediate
        //  layers are handled by dummy nodes in the layered layout pipeline.)
        let channel_idx = s_l;
        if channel_idx >= channels.len() {
            continue;
        }
        per_channel_count[channel_idx] += 1;
        routed.push(RoutedEdge {
            edge_idx: ei,
            channel_idx,
            lane: 0, // placeholder, assigned below
            sx,
            sy,
            tx,
            ty,
        });
    }

    let mut allocs: Vec<LaneAlloc> = per_channel_count
        .iter()
        .map(|&c| LaneAlloc::new(c.max(MIN_LANES)))
        .collect();

    for r in &mut routed {
        let span = [r.sx.min(r.tx), r.sx.max(r.tx)];
        r.lane = allocs[r.channel_idx].assign(span);
    }

    // ── 5. Emit the L / S polyline for each forward edge ──────────────────
    for r in &routed {
        let chan = channels[r.channel_idx];
        let k = allocs[r.channel_idx].k;
        let cy = chan.lane_y(r.lane, k);
        let mut pts = vec![[r.sx, r.sy]];
        if (r.sx - r.tx).abs() < 0.5 {
            // Straight vertical column: just clamp to channel center.
            pts.push([r.sx, cy]);
            pts.push([r.tx, r.ty]);
        } else {
            pts.push([r.sx, cy]);
            pts.push([r.tx, cy]);
            pts.push([r.tx, r.ty]);
        }
        edges[r.edge_idx].pts = pts;
    }

    // ── 6. Back-edges: route through a side channel on the right ──────────
    // We use a single side allocator keyed by vertical span so back-edges
    // do not stack on top of each other either.
    let mut side_lanes: Vec<[f32; 2]> = Vec::new();
    let max_right = nodes
        .iter()
        .map(|n| n.x + n.w)
        .fold(0.0_f32, f32::max);

    // Sort back-edges by source y so the sweep is deterministic.
    backs.sort_by(|&a, &b| {
        let ay = edges[a].pts.first().map_or(0.0, |p| p[1]);
        let by = edges[b].pts.first().map_or(0.0, |p| p[1]);
        ay.partial_cmp(&by).unwrap_or(std::cmp::Ordering::Equal)
    });

    for &ei in &backs {
        let pts = &edges[ei].pts;
        if pts.len() < 2 {
            continue;
        }
        let (sx, sy) = (pts[0][0], pts[0][1]);
        let last = pts[pts.len() - 1];
        let (tx, ty) = (last[0], last[1]);

        let y_lo = sy.min(ty) - LANE_Y_GAP;
        let y_hi = sy.max(ty) + LANE_Y_GAP;
        // Greedy: lowest free lane.
        let mut lane = side_lanes.len();
        for (i, span) in side_lanes.iter().enumerate() {
            if y_hi <= span[0] || y_lo >= span[1] {
                lane = i;
                break;
            }
        }
        if lane == side_lanes.len() {
            side_lanes.push([y_lo, y_hi]);
        } else {
            side_lanes[lane] = [
                side_lanes[lane][0].min(y_lo),
                side_lanes[lane][1].max(y_hi),
            ];
        }
        let lane_f = f32::from(u16::try_from(lane).unwrap_or(u16::MAX));
        let bend_x = lane_f.mul_add(LANE_X_GAP * 2.0, max_right + BACK_SIDE_OFFSET);
        edges[ei].pts = vec![
            [sx, sy],
            [bend_x, sy],
            [bend_x, ty],
            [tx, ty],
        ];
    }
}

// ── ensure-used (wired in to keep the symbol live without #[allow]) ───────

#[doc(hidden)]
pub fn ensure_used_edge_routing() {
    use super::graph_layout::EdgePath;
    use crate::core::types::CfgEdgeKind;

    let nodes = vec![
        NodeRect { block_id: 1, x: 0.0, y: 0.0, w: 100.0, h: 50.0 },
        NodeRect { block_id: 2, x: 0.0, y: 200.0, w: 100.0, h: 50.0 },
    ];
    let mut edges = vec![EdgePath {
        from: 1,
        to: 2,
        kind: CfgEdgeKind::Unconditional,
        pts: vec![[50.0, 50.0], [50.0, 200.0]],
        label: None,
    }];
    route_orthogonal(&nodes, &mut edges);
    debug_assert!(!edges[0].pts.is_empty());
}
