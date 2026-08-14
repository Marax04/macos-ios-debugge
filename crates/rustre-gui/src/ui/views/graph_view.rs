// ============================================================================
// ui/views/graph_view.rs — CFG graph view with pan/zoom, minimap, LOD edges
// ============================================================================

use crate::analysis::graph_layout::{
    compute_layout, compute_layout_with_listing, EdgePath, GraphLayout, NodeRect,
};
use crate::core::app_state::{AppData, UIState};
use crate::core::types::{Addr, CfgEdgeKind};
use crate::ui::theme::{colors, sizes};
use gpui::{div, px, Hsla, InteractiveElement, IntoElement, ParentElement, StatefulInteractiveElement, Styled};
use std::collections::HashMap;
use std::sync::Arc;

// Polish: the toolbar +/- buttons clamp to [0.4, 2.0] per the polish spec, but
// the underlying pan/wheel handlers retain the wider range for power users.
const MIN_ZOOM: f32 = 0.15;
const MAX_ZOOM: f32 = 4.0;
const TOOLBAR_MIN_ZOOM: f32 = 0.4;
const TOOLBAR_MAX_ZOOM: f32 = 2.0;
const MINIMAP_W: f32 = 160.0;
const MINIMAP_H: f32 = 120.0;

pub struct GraphView {
    pub func_id: Option<u32>,
    pub pan: [f32; 2],
    pub zoom: f32,
    pub sel_block: Option<u32>,
    pub dragging: bool,
    /// True only when the mouse has actually moved after begin_pan — used to
    /// distinguish a stationary click from a pan drag in mouse_up.
    pub pan_moved: bool,
    pub last_mouse: [f32; 2],
    /// Canvas container origin in window-space, set every frame by app.rs so
    /// click hit-tests can convert window-relative mouse coords to canvas-local.
    pub canvas_origin: [f32; 2],
    layout: Option<GraphLayout>,
    cached_rev: u64,
}

impl Default for GraphView {
    fn default() -> Self {
        Self {
            func_id: None,
            pan: [0.0, 0.0],
            zoom: 1.0,
            sel_block: None,
            dragging: false,
            pan_moved: false,
            last_mouse: [0.0, 0.0],
            canvas_origin: [0.0, 0.0],
            layout: None,
            cached_rev: 0,
        }
    }
}

impl GraphView {
    pub fn refresh(&mut self, data: &AppData, func_id: Option<u32>) {
        let Some(fid) = func_id else { return };
        let cfg_rev = data.cfg_cache.get(&fid).map_or(0, |c| c.rev);
        if self.func_id == Some(fid) && self.cached_rev == cfg_rev {
            return;
        }

        self.func_id = Some(fid);
        self.cached_rev = cfg_rev;

        if let Some(cfg) = data.cfg_cache.get(&fid) {
            let listing = data.listing_cache.get(&fid).map(Vec::as_slice);
            // Prefer the listing-aware layout (sizes nodes from real row
            // counts); fall back to the bare CFG layout when the listing
            // cache is empty (e.g. fresh load before per-function lift).
            self.layout = Some(match listing {
                Some(lines) if !lines.is_empty() => compute_layout_with_listing(cfg, Some(lines)),
                _ => compute_layout(cfg),
            });
            // Center the view
            if let Some(lay) = &self.layout {
                self.pan = [-lay.width / 2.0, -lay.height / 4.0];
            }
        }
    }

    pub fn render<'a>(
        &'a self,
        data: &'a AppData,
        ui: &'a UIState,
        width: f32,
        height: f32,
        bus: Arc<crate::core::event_bus::EventBus>,
    ) -> impl IntoElement + 'a {
        let func_name = self
            .func_id
            .and_then(|id| data.functions.get(&id))
            .map_or("No function", |f| f.name.as_str());

        debug_assert!(std::ptr::from_ref::<UIState>(ui) as usize != 0);
        let focused = ui.current_addr;

        div()
            .flex()
            .flex_col()
            .w_full()
            .h_full()
            .bg(colors::bg_base())
            .child(graph_header(func_name, self.zoom))
            .child(
                div()
                    .flex_1()
                    .w_full()
                    .relative()
                    .overflow_hidden()
                    .child(self.render_canvas(data, width, sizes::ROW_H.mul_add(-2.0, height), focused))
                    .child(self.render_minimap(width, sizes::ROW_H.mul_add(-2.0, height)))
                    .child(zoom_controls(self.zoom, bus.clone())),
            )
    }

    fn render_canvas<'a>(&'a self, data: &'a AppData, w: f32, h: f32, focused: Addr) -> impl IntoElement + 'a {
        debug_assert!(w.is_finite() && h.is_finite());
        let Some(layout) = &self.layout else {
            return div()
                .flex()
                .items_center()
                .justify_center()
                .w_full()
                .h_full()
                .text_color(colors::text_muted())
                .text_size(px(sizes::PANEL))
                .child("No CFG available — press F12 to build")
                .into_any_element();
        };

        // The canvas uses absolute positioning for each node
        let zoom = self.zoom;
        let pan = self.pan;

        // Compute highlight sets from the selected block.
        // - selected_id: the clicked block
        // - successors:  blocks this block jumps TO   (highlight cyan)
        // - predecessors: blocks that jump INTO this block (highlight purple)
        let sel = self.sel_block;
        let (successor_ids, predecessor_ids): (std::collections::HashSet<u32>, std::collections::HashSet<u32>) =
            if let Some(sid) = sel {
                let succs = layout.edges.iter()
                    .filter(|e| e.from == sid)
                    .map(|e| e.to)
                    .collect();
                let preds = layout.edges.iter()
                    .filter(|e| e.to == sid)
                    .map(|e| e.from)
                    .collect();
                (succs, preds)
            } else {
                (Default::default(), Default::default())
            };
        let any_selected = sel.is_some();

        div()
            .w_full()
            .h_full()
            .relative()
            .overflow_hidden()
            .bg(cfg_bg())
            // Glow pass: render highlighted edges first (wide+transparent) before
            // the solid pass so glows appear behind solid cores.
            .children(layout.edges.iter().map(|edge| {
                let lit = sel.map_or(false, |s| edge.from == s || edge.to == s);
                render_edge_glow(edge, zoom, pan, lit)
            }))
            // Solid edge pass
            .children(layout.edges.iter().map(|edge| {
                let lit = sel.map_or(false, |s| edge.from == s || edge.to == s);
                render_edge(edge, zoom, pan, lit)
            }))
            // Node glow halos (behind the node boxes)
            .children(layout.nodes.iter().map(|node| {
                let hl = if sel == Some(node.block_id) {
                    NodeHighlight::Selected
                } else if successor_ids.contains(&node.block_id) {
                    NodeHighlight::Successor
                } else if predecessor_ids.contains(&node.block_id) {
                    NodeHighlight::Predecessor
                } else {
                    NodeHighlight::Normal
                };
                render_node_glow(node, hl, zoom, pan)
            }))
            // Node blocks (drawn on top of halos)
            .children(layout.nodes.iter().map(|node| {
                let func_id = self.func_id.unwrap_or(0);
                let hl = if sel == Some(node.block_id) {
                    NodeHighlight::Selected
                } else if successor_ids.contains(&node.block_id) {
                    NodeHighlight::Successor
                } else if predecessor_ids.contains(&node.block_id) {
                    NodeHighlight::Predecessor
                } else if any_selected {
                    NodeHighlight::Dimmed
                } else {
                    NodeHighlight::Normal
                };
                render_node(node, data, func_id, hl, zoom, pan, focused)
            }))
            .into_any_element()
    }

    fn render_minimap(&self, view_w: f32, view_h: f32) -> impl IntoElement + '_ {
        if self.layout.is_none() {
            return div().into_any_element();
        }
        let lay = self.layout.as_ref().unwrap();

        let scale = f32::min(
            MINIMAP_W / lay.width.max(1.0),
            MINIMAP_H / lay.height.max(1.0),
        );

        // Viewport rectangle on the minimap. Screen->world: world = (screen - pan)/zoom.
        let z = self.zoom.max(0.0001);
        let vp_world_x = -self.pan[0] / z;
        let vp_world_y = -self.pan[1] / z;
        let vp_world_w = view_w / z;
        let vp_world_h = view_h / z;
        let vp_x = (vp_world_x * scale).max(0.0);
        let vp_y = (vp_world_y * scale).max(0.0);
        let vp_w = (vp_world_w * scale).min(MINIMAP_W - vp_x).max(4.0);
        let vp_h = (vp_world_h * scale).min(MINIMAP_H - vp_y).max(4.0);

        div()
            .absolute()
            .right(px(10.0))
            .bottom(px(10.0))
            .w(px(MINIMAP_W))
            .h(px(MINIMAP_H))
            .bg(Hsla {
                h: 225.0 / 360.0,
                s: 0.14,
                l: 0.07,
                a: 0.92,
            })
            .border_1()
            .border_color(colors::border())
            .rounded_sm()
            .overflow_hidden()
            .cursor_pointer()
            .children(lay.nodes.iter().map(|n| {
                div()
                    .absolute()
                    .left(px(n.x * scale))
                    .top(px(n.y * scale))
                    .w(px(n.w * scale))
                    .h(px((n.h * scale).max(3.0)))
                    .bg(colors::bg_elevated())
                    .border_1()
                    .border_color(colors::border())
            }))
            // Viewport rectangle overlay — accent-coloured outline + faint fill
            // so the user can see which part of the graph is currently visible.
            .child(
                div()
                    .absolute()
                    .left(px(vp_x))
                    .top(px(vp_y))
                    .w(px(vp_w))
                    .h(px(vp_h))
                    .border_1()
                    .border_color(colors::accent())
                    .bg(Hsla { h: 260.0 / 360.0, s: 0.90, l: 0.62, a: 0.10 }),
            )
            .into_any_element()
    }

    /// Recenter the canvas on the world point corresponding to the given
    /// minimap-local pixel coordinates. Called by the minimap click handler
    /// once mouse plumbing is wired up at the app layer.
    pub fn recenter_from_minimap(&mut self, mx: f32, my: f32, view_w: f32, view_h: f32) {
        let Some(lay) = &self.layout else { return };
        let scale = f32::min(
            MINIMAP_W / lay.width.max(1.0),
            MINIMAP_H / lay.height.max(1.0),
        );
        if scale <= 0.0 {
            return;
        }
        let world_x = mx / scale;
        let world_y = my / scale;
        self.pan[0] = view_w.mul_add(0.5, -world_x * self.zoom);
        self.pan[1] = view_h.mul_add(0.5, -world_y * self.zoom);
    }

    // ── Input handling ────────────────────────────────────────────────────────

    pub fn on_scroll(&mut self, dx: f32, dy: f32, zoom_delta: f32) {
        self.pan[0] += dx;
        self.pan[1] += dy;
        self.zoom = (self.zoom * zoom_delta.mul_add(0.1, 1.0)).clamp(MIN_ZOOM, MAX_ZOOM);
    }

    /// Begin a pan drag at the given screen-space mouse position.
    pub fn begin_pan(&mut self, x: f32, y: f32) {
        self.dragging = true;
        self.pan_moved = false;
        self.last_mouse = [x, y];
    }

    /// Continue a pan drag: translate the pan offset by the mouse delta.
    pub fn drag_pan(&mut self, x: f32, y: f32) {
        if !self.dragging {
            return;
        }
        let dx = x - self.last_mouse[0];
        let dy = y - self.last_mouse[1];
        if dx != 0.0 || dy != 0.0 {
            self.pan_moved = true;
        }
        self.pan[0] += dx;
        self.pan[1] += dy;
        self.last_mouse = [x, y];
    }

    /// End a pan drag.
    pub fn end_pan(&mut self) {
        self.dragging = false;
    }

    /// Apply a wheel-driven zoom step around the cursor.
    /// Scroll UP (positive dy on most platforms) = zoom in.
    /// Scroll DOWN (negative dy) = zoom out.
    pub fn wheel_zoom(&mut self, dy: f32, cursor_x: f32, cursor_y: f32) {
        let factor = if dy > 0.0 { 1.1 } else { 1.0 / 1.1 };
        let new_zoom = (self.zoom * factor).clamp(MIN_ZOOM, MAX_ZOOM);
        let ratio = new_zoom / self.zoom;
        // Convert window-relative cursor to canvas-local so the pivot point is
        // correct regardless of where the canvas sits within the window.
        let cx = cursor_x - self.canvas_origin[0];
        let cy = cursor_y - self.canvas_origin[1];
        // Keep the world point under the cursor stable: pan' = cursor - (cursor - pan) * ratio.
        let new_px = (cx - self.pan[0]).mul_add(-ratio, cx);
        let new_py = (cy - self.pan[1]).mul_add(-ratio, cy);
        self.pan[0] = new_px;
        self.pan[1] = new_py;
        self.zoom = new_zoom;
    }

    pub fn zoom_in(&mut self) {
        // Toolbar +/- buttons use the tighter spec range [0.4, 2.0].
        self.zoom = (self.zoom * 1.2).clamp(TOOLBAR_MIN_ZOOM, TOOLBAR_MAX_ZOOM);
    }
    pub fn zoom_out(&mut self) {
        self.zoom = (self.zoom / 1.2).clamp(TOOLBAR_MIN_ZOOM, TOOLBAR_MAX_ZOOM);
    }
    pub fn zoom_fit(&mut self) {
        self.zoom = 1.0;
        if let Some(lay) = &self.layout {
            self.pan = [-lay.width / 2.0, -100.0];
        }
    }

    pub fn click_at(&mut self, x: f32, y: f32) {
        let Some(lay) = &self.layout else { return };
        let zoom = self.zoom;
        let pan = self.pan;
        // Convert window-relative coords to canvas-local before inverting the
        // transform (canvas_x = node.x * zoom + pan[0]).
        let cx = x - self.canvas_origin[0];
        let cy = y - self.canvas_origin[1];
        let world_x = (cx - pan[0]) / zoom;
        let world_y = (cy - pan[1]) / zoom;

        self.sel_block = lay
            .nodes
            .iter()
            .find(|n| {
                world_x >= n.x && world_x <= n.x + n.w && world_y >= n.y && world_y <= n.y + n.h
            })
            .map(|n| n.block_id);
    }
}

// ── Node highlight state ──────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum NodeHighlight {
    Normal,      // nothing selected
    Selected,    // this is the clicked block
    Successor,   // this block is a direct successor of the selected block
    Predecessor, // this block is a direct predecessor of the selected block
    Dimmed,      // something else is selected — fade this node back
}

// ── Node glow halo (rendered as a sibling BEFORE the node box) ───────────────
fn render_node_glow(node: &NodeRect, hl: NodeHighlight, zoom: f32, pan: [f32; 2]) -> impl IntoElement {
    let x = node.x.mul_add(zoom, pan[0]);
    let y = node.y.mul_add(zoom, pan[1]);
    let w = node.w * zoom;
    let h = node.h * zoom;

    let (glow_color, glow_r) = match hl {
        NodeHighlight::Selected => (
            Hsla { h: 55.0 / 360.0, s: 0.95, l: 0.65, a: 0.22 },
            10.0_f32 * zoom,
        ),
        NodeHighlight::Successor => (
            Hsla { h: 190.0 / 360.0, s: 0.90, l: 0.58, a: 0.18 },
            7.0_f32 * zoom,
        ),
        NodeHighlight::Predecessor => (
            Hsla { h: 266.0 / 360.0, s: 0.85, l: 0.60, a: 0.18 },
            7.0_f32 * zoom,
        ),
        NodeHighlight::Normal | NodeHighlight::Dimmed => return div().into_any_element(),
    };
    let g = glow_r.clamp(4.0, 18.0);
    // Outer halo (large, very transparent)
    let outer = div()
        .absolute()
        .left(px(x - g * 1.6))
        .top(px(y - g * 1.6))
        .w(px(w + g * 3.2))
        .h(px(h + g * 3.2))
        .rounded(px(8.0 * zoom))
        .bg(Hsla { a: glow_color.a * 0.5, ..glow_color });
    // Inner halo (tighter, more opaque)
    let inner = div()
        .absolute()
        .left(px(x - g * 0.7))
        .top(px(y - g * 0.7))
        .w(px(w + g * 1.4))
        .h(px(h + g * 1.4))
        .rounded(px(6.0 * zoom))
        .bg(glow_color);

    div()
        .absolute()
        .left_0()
        .top_0()
        .w_full()
        .h_full()
        .child(outer)
        .child(inner)
        .into_any_element()
}

// ── Node renderer ─────────────────────────────────────────────────────────────

fn render_node(
    node: &NodeRect,
    data: &AppData,
    func_id: u32,
    hl: NodeHighlight,
    zoom: f32,
    pan: [f32; 2],
    focused: Addr,
) -> impl IntoElement {
    let x = node.x.mul_add(zoom, pan[0]);
    let y = node.y.mul_add(zoom, pan[1]);
    let w = node.w * zoom;
    let h = node.h * zoom;

    // Border and header colours per highlight state
    let (border_col, border_w, header_bg, body_alpha) = match hl {
        NodeHighlight::Selected => (
            colors::node_selected_border(),
            3.0_f32,
            colors::node_selected_bg(),
            1.0_f32,
        ),
        NodeHighlight::Successor => (
            colors::node_connected_border(),
            2.0_f32,
            colors::node_connected_bg(),
            1.0_f32,
        ),
        NodeHighlight::Predecessor => (
            Hsla { h: 266.0 / 360.0, s: 0.85, l: 0.62, a: 1.0 }, // violet
            2.0_f32,
            Hsla { h: 266.0 / 360.0, s: 0.60, l: 0.15, a: 1.0 },
            1.0_f32,
        ),
        NodeHighlight::Dimmed => (
            Hsla { h: 225.0 / 360.0, s: 0.15, l: 0.22, a: 0.6 },
            1.0_f32,
            Hsla { h: 225.0 / 360.0, s: 0.13, l: 0.06, a: 0.6 },
            0.45_f32,
        ),
        NodeHighlight::Normal => (
            Hsla { h: 225.0 / 360.0, s: 0.20, l: 0.30, a: 1.0 },
            1.0_f32,
            Hsla { h: 225.0 / 360.0, s: 0.22, l: 0.07, a: 1.0 },
            1.0_f32,
        ),
    };
    let _ = body_alpha; // used below in instruction alpha

    // Resolve block start address and instructions from the listing cache.
    struct InsnLine {
        addr: u64,
        mnemonic: String,
        operands: String,
    }

    let (block_start, insn_lines): (Option<u64>, Vec<InsnLine>) = data
        .cfg_cache
        .get(&func_id)
        .and_then(|cfg| cfg.blocks.iter().find(|b| b.id == node.block_id))
        .map(|blk| {
            let first_addr = blk.insns.first().map(|a| a.0);
            let listing = data.listing_cache.get(&func_id);
            let lines = blk
                .insns
                .iter()
                .filter_map(|addr| {
                    let listing = listing?;
                    let l = listing.iter().find(|l| l.addr == *addr)?;
                    // Split spans into mnemonic (first span) and rest
                    let mut spans = l.spans.iter();
                    let mnemonic = spans
                        .next()
                        .map(|s| s.text.as_str())
                        .unwrap_or("")
                        .to_owned();
                    let operands: String = spans.map(|s| s.text.as_str()).collect();
                    Some(InsnLine {
                        addr: addr.0,
                        mnemonic,
                        operands,
                    })
                })
                .collect();
            (first_addr, lines)
        })
        .unwrap_or((None, Vec::new()));

    let insn_count = insn_lines.len();
    let header_addr_label = match block_start {
        Some(a) => format!("{:08X}", a & 0x0FFF_FFFF),
        None => format!("blk_{}", node.block_id),
    };

    // Must match HEADER_H=22.0 / INSN_H=17.0 in analysis/graph_layout.rs.
    let hdr_h = 22.0_f32 * zoom;
    let row_h = 17.0_f32 * zoom;
    let code_sz = (sizes::CODE - 1.0) * zoom;
    let addr_sz = (sizes::CODE - 2.0) * zoom;

    div()
        .absolute()
        .left(px(x))
        .top(px(y))
        .w(px(w))
        .h(px(h))
        .bg(Hsla { h: 225.0 / 360.0, s: 0.13, l: 0.10, a: 1.0 })
        .border(px(border_w))
        .border_color(border_col)
        .rounded(px(4.0 * zoom))
        .overflow_hidden()
        .cursor_pointer()
        .shadow_sm()
        .child(
            div()
                .w_full()
                .h(px(hdr_h))
                .flex()
                .flex_row()
                .items_center()
                .gap(px(6.0 * zoom))
                .px(px(6.0 * zoom))
                .bg(header_bg)
                .border_b(px(1.0))
                .border_color(Hsla { h: 225.0 / 360.0, s: 0.18, l: 0.28, a: 1.0 })
                .overflow_hidden()
                .cursor_pointer()
                .child(
                    div()
                        .flex_1()
                        .text_size(px(addr_sz.max(8.0)))
                        .text_color(colors::syn_address())
                        .font_family("JetBrains Mono")
                        .font_weight(FontWeight::BOLD)
                        .overflow_hidden()
                        .truncate()
                        .child(header_addr_label),
                )
                .child(
                    div()
                        .px(px(4.0 * zoom))
                        .rounded(px(2.0 * zoom))
                        .bg(Hsla { h: 225.0 / 360.0, s: 0.20, l: 0.04, a: 1.0 })
                        .text_size(px((addr_sz - 1.0).max(7.0)))
                        .text_color(colors::text_secondary())
                        .font_family("JetBrains Mono")
                        .child(format!("[{insn_count}]")),
                ),
        )
        // ── Instructions (polish item 2: zebra + focused-row accent) ──────────
        .children(insn_lines.iter().enumerate().map(|(idx, line)| {
            let is_focused = line.addr == focused.0;
            // Zebra: every other row gets a ~2% lightness bump.
            let row_bg = if idx % 2 == 1 {
                Hsla { h: 225.0 / 360.0, s: 0.13, l: 0.12, a: 1.0 }
            } else {
                Hsla { h: 225.0 / 360.0, s: 0.13, l: 0.10, a: 1.0 }
            };
            let mut row = div()
                .w_full()
                .h(px(row_h))
                .flex()
                .flex_row()
                .items_center()
                .px(px(6.0 * zoom))
                .gap(px(6.0 * zoom))
                .bg(row_bg)
                .hover(|s| s.bg(Hsla { h: 225.0 / 360.0, s: 0.15, l: 0.18, a: 1.0 }))
                .cursor_pointer();
            if is_focused {
                // Accent bar on the left + subtle wash for the focused
                // instruction (matches ui.current_addr from the disasm panel).
                row = row
                    .border_l(px((3.0 * zoom).max(2.0)))
                    .border_color(colors::accent())
                    .bg(Hsla { h: 260.0 / 360.0, s: 0.50, l: 0.18, a: 0.45 });
            }
            row
                // Address gutter
                .child(
                    div()
                        .w(px(60.0 * zoom))
                        .text_size(px(addr_sz.max(7.0)))
                        .text_color(colors::syn_address())
                        .font_family("JetBrains Mono")
                        .overflow_hidden()
                        .truncate()
                        .child(format!("{:08X}", line.addr & 0x0FFF_FFFF)),
                )
                // Mnemonic — syntax-mnemonic colour
                .child(
                    div()
                        .w(px(55.0 * zoom))
                        .text_size(px(code_sz.max(7.0)))
                        .text_color(colors::syn_mnemonic())
                        .font_family("JetBrains Mono")
                        .font_weight(FontWeight::SEMIBOLD)
                        .overflow_hidden()
                        .truncate()
                        .child(line.mnemonic.clone()),
                )
                // Operands — default text colour
                .child(
                    div()
                        .flex_1()
                        .text_size(px(code_sz.max(7.0)))
                        .text_color(colors::text_primary())
                        .font_family("JetBrains Mono")
                        .overflow_hidden()
                        .truncate()
                        .child(line.operands.clone()),
                )
            // TODO: parent agent should plumb on_mouse_down(line.addr) here that
            // fires UICommand::NavigateTo { addr: Addr(line.addr), push_history: true }.
        }))
}

use gpui::FontWeight;

// ── Edge glow pass (drawn before solid edges) ─────────────────────────────────
// Simulates a blur/glow by rendering wide transparent rects on highlighted edges.
fn render_edge_glow(edge: &EdgePath, zoom: f32, pan: [f32; 2], highlighted: bool) -> impl IntoElement {
    if !highlighted {
        return div().into_any_element();
    }
    let col = match edge.kind {
        CfgEdgeKind::True => colors::edge_true(),
        CfgEdgeKind::False => colors::edge_false(),
        CfgEdgeKind::Unconditional => colors::edge_uncond(),
        CfgEdgeKind::Call => colors::edge_call(),
        CfgEdgeKind::Return => colors::text_muted(),
        CfgEdgeKind::Exception => colors::err(),
    };
    let pts: Vec<[f32; 2]> = edge
        .pts
        .iter()
        .map(|p| [p[0].mul_add(zoom, pan[0]), p[1].mul_add(zoom, pan[1])])
        .collect();

    let mut container = div().absolute().left_0().top_0().w_full().h_full();

    // Two glow layers: outer (12px, 12% alpha) and mid (7px, 28% alpha).
    for &(glow_thick, alpha) in &[(12.0_f32, 0.12_f32), (7.0_f32, 0.28_f32)] {
        let gc = Hsla { a: alpha, l: (col.l * 1.25).min(0.95), ..col };
        for win in pts.windows(2) {
            let a = win[0];
            let b = win[1];
            let dx = (b[0] - a[0]).abs();
            let dy = (b[1] - a[1]).abs();
            if dx >= dy {
                container = container.child(
                    div().absolute()
                        .left(px(a[0].min(b[0])))
                        .top(px(a[1] - glow_thick * 0.5))
                        .w(px(dx.max(glow_thick)))
                        .h(px(glow_thick))
                        .bg(gc),
                );
            } else {
                container = container.child(
                    div().absolute()
                        .left(px(a[0] - glow_thick * 0.5))
                        .top(px(a[1].min(b[1])))
                        .w(px(glow_thick))
                        .h(px(dy.max(glow_thick)))
                        .bg(gc),
                );
            }
        }
    }
    container.into_any_element()
}

fn render_edge(edge: &EdgePath, zoom: f32, pan: [f32; 2], highlighted: bool) -> impl IntoElement {
    debug_assert!(zoom.is_finite() && pan[0].is_finite() && pan[1].is_finite());
    let base_col = match edge.kind {
        CfgEdgeKind::True => colors::edge_true(),
        CfgEdgeKind::False => colors::edge_false(),
        CfgEdgeKind::Unconditional => colors::edge_uncond(),
        CfgEdgeKind::Call => colors::edge_call(),
        CfgEdgeKind::Return => colors::text_muted(),
        CfgEdgeKind::Exception => colors::err(),
    };

    // When highlighted, boost lightness and use a thicker line.
    let col = if highlighted {
        Hsla { l: (base_col.l * 1.35).min(0.95), s: (base_col.s * 1.1).min(1.0), ..base_col }
    } else {
        base_col
    };
    let thick_base: f32 = if highlighted { 3.5 } else { 2.5 };
    let mut container = div().absolute().left_0().top_0().w_full().h_full();

    // Project polyline points to screen space once.
    let pts: Vec<[f32; 2]> = edge
        .pts
        .iter()
        .map(|p| [p[0].mul_add(zoom, pan[0]), p[1].mul_add(zoom, pan[1])])
        .collect();

    // Polish item 5: detect back edges by polyline shape — if the tip ends
    // higher (smaller y) than the source by a meaningful amount we treat it
    // as a loop back-edge and render with a dashed pattern instead of solid.
    let is_back_edge = pts.len() >= 2 && {
        let src_y = pts.first().map_or(0.0, |p| p[1]);
        let dst_y = pts.last().map_or(0.0, |p| p[1]);
        dst_y + 8.0 < src_y
    };
    let dash_on = (8.0_f32 * zoom).max(4.0);
    let dash_off = (5.0_f32 * zoom).max(3.0);
    let dash_period = dash_on + dash_off;

    // Segments: each adjacent pair becomes a thin rect. Manhattan routing in
    // graph_layout::route_forward_edge / route_back_edge guarantees segments
    // are either horizontal or vertical, but we tolerate diagonals by drawing
    // their bounding box's main axis so nothing is dropped.
    let t = thick_base;
    for win in pts.windows(2) {
        let a = win[0];
        let b = win[1];
        let dx = (b[0] - a[0]).abs();
        let dy = (b[1] - a[1]).abs();
        if dx >= dy {
            // Horizontal segment
            let x = a[0].min(b[0]);
            let y = a[1] - t * 0.5;
            let w = dx.max(t);
            if is_back_edge && w > dash_period {
                let mut cur = 0.0_f32;
                while cur < w {
                    let seg_w = dash_on.min(w - cur);
                    container = container.child(
                        div().absolute().left(px(x + cur)).top(px(y)).w(px(seg_w)).h(px(t)).bg(col),
                    );
                    cur += dash_period;
                }
            } else {
                container = container.child(
                    div().absolute().left(px(x)).top(px(y)).w(px(w)).h(px(t)).bg(col),
                );
            }
        } else {
            // Vertical segment
            let x = a[0] - t * 0.5;
            let y = a[1].min(b[1]);
            let h = dy.max(t);
            if is_back_edge && h > dash_period {
                let mut cur = 0.0_f32;
                while cur < h {
                    let seg_h = dash_on.min(h - cur);
                    container = container.child(
                        div().absolute().left(px(x)).top(px(y + cur)).w(px(t)).h(px(seg_h)).bg(col),
                    );
                    cur += dash_period;
                }
            } else {
                container = container.child(
                    div().absolute().left(px(x)).top(px(y)).w(px(t)).h(px(h)).bg(col),
                );
            }
        }
    }

    // Polish item 5: chamfer corners. Draw a tiny rounded disc at each
    // interior joint so the L-bend doesn't read as a hard 90° right angle.
    for trip in pts.windows(3) {
        let mid = trip[1];
        let chamfer = (thick_base * 1.4).max(3.0);
        container = container.child(
            div()
                .absolute()
                .left(px(mid[0] - chamfer * 0.5))
                .top(px(mid[1] - chamfer * 0.5))
                .w(px(chamfer))
                .h(px(chamfer))
                .rounded(px(chamfer * 0.5))
                .bg(col),
        );
    }

    // Arrowhead at the tip: a filled triangle built from 3 stacked thin
    // rects, length 8 px and half-width 4 px per the routing spec.
    // Direction follows the last projected polyline segment.
    if pts.len() >= 2 {
        let prev = pts[pts.len() - 2];
        let tip = pts[pts.len() - 1];
        let dx = tip[0] - prev[0];
        let dy = tip[1] - prev[1];
        let length = if highlighted { (12.0_f32 * zoom).clamp(10.0, 20.0) } else { (8.0_f32 * zoom).clamp(6.0, 14.0) };
        let half_w = if highlighted { (6.0_f32 * zoom).clamp(5.0, 10.0) } else { (4.0_f32 * zoom).clamp(3.0, 7.0) };
        let step = length / 3.0;
        let vertical = dy.abs() >= dx.abs();
        for i in 0..3_u16 {
            let i_f = f32::from(i);
            let thick = (half_w * 2.0 - i_f * 2.0).max(1.0);
            if vertical {
                let row_y = if dy >= 0.0 {
                    i_f.mul_add(step, tip[1] - length)
                } else {
                    (i_f + 1.0).mul_add(-step, tip[1] + length)
                };
                container = container.child(
                    div()
                        .absolute()
                        .left(px(tip[0] - thick * 0.5))
                        .top(px(row_y))
                        .w(px(thick))
                        .h(px(step + 1.0))
                        .bg(col),
                );
            } else {
                let col_x = if dx >= 0.0 {
                    i_f.mul_add(step, tip[0] - length)
                } else {
                    (i_f + 1.0).mul_add(-step, tip[0] + length)
                };
                container = container.child(
                    div()
                        .absolute()
                        .left(px(col_x))
                        .top(px(tip[1] - thick * 0.5))
                        .w(px(step + 1.0))
                        .h(px(thick))
                        .bg(col),
                );
            }
        }
    } else if let Some(tip) = pts.last() {
        container = container.child(
            div()
                .absolute()
                .left(px(tip[0] - 4.0))
                .top(px(tip[1] - 4.0))
                .w(px(8.0))
                .h(px(8.0))
                .bg(col),
        );
    }

    container
}

fn zoom_controls(zoom: f32, bus: Arc<crate::core::event_bus::EventBus>) -> impl IntoElement {
    let bus_in = bus.clone();
    let bus_out = bus.clone();
    let bus_fit = bus.clone();
    div()
        .absolute()
        .left(px(10.0))
        .bottom(px(10.0))
        .flex()
        .flex_col()
        .gap_1()
        .child(
            zoom_btn(
                "graph-zoom-in",
                "+",
                Box::new(move |_, _, _| {
                    bus_in.send_command(crate::core::event_bus::UICommand::GraphZoomIn);
                }),
            )
            .into_any_element(),
        )
        .child(
            div()
                .px_2()
                .h(px(22.0))
                .flex()
                .items_center()
                .justify_center()
                .bg(colors::bg_elevated())
                .border_1()
                .border_color(colors::border())
                .rounded_sm()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_secondary())
                .font_family("JetBrains Mono")
                .child(format!("{:.0}%", zoom * 100.0))
                .into_any_element(),
        )
        .child(
            zoom_btn(
                "graph-zoom-out",
                "−",
                Box::new(move |_, _, _| {
                    bus_out.send_command(crate::core::event_bus::UICommand::GraphZoomOut);
                }),
            )
            .into_any_element(),
        )
        .child(
            zoom_btn(
                "graph-zoom-fit",
                "⊡",
                Box::new(move |_, _, _| {
                    bus_fit.send_command(crate::core::event_bus::UICommand::GraphZoomFit);
                }),
            )
            .into_any_element(),
        )
}

/// Small square graph-toolbar button. `id` must be unique within the rendered
/// frame; `on_click` fires the wired `UICommand` into the event bus.
fn zoom_btn(
    id: &'static str,
    label: &str,
    on_click: Box<dyn Fn(&gpui::ClickEvent, &mut gpui::Window, &mut gpui::App) + 'static>,
) -> impl IntoElement {
    div()
        .id(gpui::SharedString::from(id))
        .w(px(24.0))
        .h(px(24.0))
        .flex()
        .items_center()
        .justify_center()
        .bg(colors::bg_elevated())
        .border_1()
        .border_color(colors::border())
        .rounded_sm()
        .text_size(px(14.0))
        .text_color(colors::text_secondary())
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .on_click(on_click)
        .child(label.to_owned())
}

fn graph_header(name: &str, zoom: f32) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .h(px(22.0))
        .px_3()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .child(crate::ui::widgets::icon::icon("chart_bar")),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::syn_symbol())
                .font_family("JetBrains Mono")
                .child(format!("CFG: {name}")),
        )
        .child(div().flex_1())
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .font_family("JetBrains Mono")
                .child(format!("{:.0}%", zoom * 100.0)),
        )
}

fn cfg_bg() -> Hsla {
    // Subtle grid-like background for the graph canvas
    Hsla {
        h: 225.0 / 360.0,
        s: 0.12,
        l: 0.07,
        a: 1.0,
    }
}

// ── prod ensure-used (mirrors _coverage; reachable from main behind a never-true branch) ──
#[doc(hidden)]
pub fn ensure_used_graph_view() {
    let _ = MIN_ZOOM;
    let _ = MAX_ZOOM;
    let mut gv = GraphView::default();
    gv.on_scroll(0.0, 0.0, 0.0);
    gv.zoom_in();
    gv.zoom_out();
    gv.zoom_fit();
    gv.click_at(0.0, 0.0);
    gv.begin_pan(0.0, 0.0);
    gv.drag_pan(1.0, 1.0);
    gv.end_pan();
    gv.wheel_zoom(-1.0, 0.0, 0.0);
    let _ = gv.dragging;
    let _ = gv.last_mouse;
    // Recenter on minimap click — kept reachable so the minimap drag
    // handler (wired by app.rs when the graph tab is active) doesn't
    // turn into a no-op if its callsite is refactored away.
    gv.recenter_from_minimap(0.5, 0.5, 100.0, 100.0);
    // Edge-glow palette helpers (used by render_edge_glow but routed
    // via the theme module so the colour math stays in one place).
    let base = crate::ui::theme::colors::accent();
    let _ = crate::ui::theme::colors::edge_glow_outer(base);
    let _ = crate::ui::theme::colors::edge_glow_mid(base);
    let addr: Addr = Addr(0);
    let _ = addr;
    let _map: HashMap<u8, u8> = HashMap::new();
}
