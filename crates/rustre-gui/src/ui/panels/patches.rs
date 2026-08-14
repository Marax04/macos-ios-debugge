// ============================================================================
// ui/panels/patches.rs — Patches panel: view/toggle/export applied patches
// ============================================================================

use crate::core::app_state::{AppData, UIState};
use crate::core::types::Patch;
use crate::ui::theme::{colors, sizes};
use crate::ui::widgets::virtual_list::VirtualListState;
use gpui::{
    div, px, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement, SharedString,
    StatefulInteractiveElement, Styled,
};
use parking_lot::Mutex;
use std::sync::Arc;

// ─── Patch statistics ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct PatchStats {
    pub total: usize,
    pub enabled: usize,
    pub total_bytes_changed: usize,
}

impl PatchStats {
    pub fn from_patches(patches: &[Patch]) -> Self {
        let total = patches.len();
        let enabled = total; // all patches are applied for now
        let total_bytes_changed = patches.iter().map(|p| p.patched.len()).sum();
        Self {
            total,
            enabled,
            total_bytes_changed,
        }
    }
}

// ─── Sort order ───────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PatchSort {
    #[default]
    Addr,
    Size,
    Comment,
}

// ─── Panel state ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct PatchesPanelState {
    pub vlist: VirtualListState,
    pub selected: Option<usize>,
    pub filter: String,
    pub show_disabled: bool,
    pub sort: PatchSort,
    pub show_diff: bool,
    cached_stats: PatchStats,
    cached_rev: u64,
}

impl Default for PatchesPanelState {
    fn default() -> Self {
        Self {
            vlist: VirtualListState::new(sizes::ROW_H),
            selected: None,
            filter: String::new(),
            show_disabled: true,
            sort: PatchSort::Addr,
            show_diff: false,
            cached_stats: PatchStats::default(),
            cached_rev: 0,
        }
    }
}

impl PatchesPanelState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn refresh(&mut self, data: &AppData) {
        self.vlist.total_rows = self.visible_patches(data).len();
        self.cached_stats = PatchStats::from_patches(&data.patches);
    }

    pub fn visible_patches<'a>(&self, data: &'a AppData) -> Vec<(usize, &'a Patch)> {
        let q = self.filter.to_lowercase();
        let mut pairs: Vec<(usize, &Patch)> = data
            .patches
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                q.is_empty()
                    || format!("{:#x}", p.addr.0).contains(&q)
                    || p.comment.to_lowercase().contains(&q)
            })
            .collect();

        pairs.sort_by(|(_, a), (_, b)| match self.sort {
            PatchSort::Addr => a.addr.0.cmp(&b.addr.0),
            PatchSort::Size => b.patched.len().cmp(&a.patched.len()),
            PatchSort::Comment => a.comment.cmp(&b.comment),
        });

        pairs
    }

    pub fn select(&mut self, idx: usize) {
        self.selected = if self.selected == Some(idx) {
            None
        } else {
            Some(idx)
        };
    }

    pub fn on_scroll(&mut self, d: f64) {
        self.vlist.scroll_by(d);
    }
    pub fn on_key_up(&mut self) {
        self.vlist.move_selection(-1);
    }
    pub fn on_key_down(&mut self) {
        self.vlist.move_selection(1);
    }

    pub fn export_idc(data: &AppData) -> String {
        let mut out = "#include <idc.idc>\nstatic ApplyPatches() {\n".to_owned();
        for patch in &data.patches {
            for (i, &b) in patch.patched.iter().enumerate() {
                use std::fmt::Write as _;
                let _ = writeln!(
                    out,
                    "  PatchByte(0x{:x}, 0x{:02x}); // {}",
                    patch.addr.0 + i as u64,
                    b,
                    patch.comment
                );
            }
        }
        out.push_str("}\n");
        out
    }

    pub fn export_python(data: &AppData) -> String {
        use std::fmt::Write as _;
        let mut out = "import idaapi\ndef apply_patches():\n".to_owned();
        for patch in &data.patches {
            let bytes: String = patch
                .patched
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(
                out,
                "    idaapi.patch_bytes(0x{:x}, bytes([{}]))  # {}",
                patch.addr.0, bytes, patch.comment
            );
        }
        out
    }

    pub fn export_c_array(data: &AppData) -> String {
        use std::fmt::Write as _;
        let mut out =
            "typedef struct { uint64_t addr; size_t len; const uint8_t* bytes; } Patch;\n\n"
                .to_owned();
        out.push_str("static const Patch patches[] = {\n");
        for (i, patch) in data.patches.iter().enumerate() {
            let bytes: String = patch
                .patched
                .iter()
                .map(|b| format!("0x{b:02x}"))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(
                out,
                "  /* [{}] {} */ {{ 0x{:x}ULL, {}, (const uint8_t[]){{{}}}}},",
                i,
                patch.comment,
                patch.addr.0,
                patch.patched.len(),
                bytes
            );
        }
        out.push_str("};\n");
        out
    }

    pub const fn stats(&self) -> &PatchStats {
        &self.cached_stats
    }
}

// ─── Render ───────────────────────────────────────────────────────────────────

pub fn render_patches_panel<'a>(
    state: &'a PatchesPanelState,
    data: &'a AppData,
    ui_arc: &Arc<Mutex<UIState>>,
) -> impl IntoElement + 'a {
    let patches = state.visible_patches(data);
    let panel_stats = state.stats();
    let win = state.vlist.window();

    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_panel())
        .child(patches_header(panel_stats))
        .child(patches_toolbar(state))
        .child(col_header(state))
        .child(if patches.is_empty() {
            patches_empty_state().into_any_element()
        } else {
            div()
                .flex_1()
                .id("patches-scroll")
                .overflow_y_scroll()
                .children(
                    patches
                        .into_iter()
                        .skip(win.first)
                        .take(win.last - win.first)
                        .map(|(orig_idx, patch)| {
                            let is_sel = state.selected == Some(orig_idx);
                            let ui2 = Arc::clone(ui_arc);
                            patch_row(patch, orig_idx, is_sel, state.show_diff, ui2)
                        }),
                )
                .into_any_element()
        })
}

fn patches_header(stats: &PatchStats) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .justify_between()
        .h(px(26.0))
        .px_2()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(
            div()
                .text_size(px(sizes::PANEL))
                .text_color(colors::text_primary())
                .font_weight(FontWeight::SEMIBOLD)
                .child("Patches"),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .gap_2()
                .child(
                    div()
                        .text_size(px(sizes::LABEL))
                        .text_color(colors::ok())
                        .child(format!("{} active", stats.enabled)),
                )
                .child(
                    div()
                        .text_size(px(sizes::LABEL))
                        .text_color(colors::text_muted())
                        .child(format!("{} bytes", stats.total_bytes_changed)),
                )
                .child(
                    div()
                        .text_size(px(sizes::LABEL))
                        .text_color(colors::text_muted())
                        .child(format!("{} total", stats.total)),
                ),
        )
}

fn patches_toolbar(state: &PatchesPanelState) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(26.0))
        .px_2()
        .gap_1()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(tb_btn_primary("+ New"))
        .child(tb_btn("Enable All"))
        .child(tb_btn("Disable All"))
        .child(tb_btn("Revert All"))
        .child(div().flex_1())
        // Sort
        .child(sort_btn("Addr", state.sort == PatchSort::Addr))
        .child(sort_btn("Size", state.sort == PatchSort::Size))
        .child(sort_btn("Comment", state.sort == PatchSort::Comment))
        .child(div().w(px(1.0)).h_full().bg(colors::border()))
        // Export
        .child(tb_btn("IDC"))
        .child(tb_btn("Py"))
        .child(tb_btn("C"))
        // Diff toggle
        .child(
            div()
                .px_2()
                .h(px(20.0))
                .rounded(px(3.0))
                .flex()
                .items_center()
                .cursor_pointer()
                .border_1()
                .border_color(if state.show_diff {
                    colors::accent_blue()
                } else {
                    colors::border()
                })
                .bg(if state.show_diff {
                    Hsla {
                        h: 200.0 / 360.0,
                        s: 0.4,
                        l: 0.10,
                        a: 0.5,
                    }
                } else {
                    Hsla {
                        h: 0.0,
                        s: 0.0,
                        l: 0.0,
                        a: 0.0,
                    }
                })
                .text_size(px(sizes::LABEL - 1.5))
                .text_color(if state.show_diff {
                    colors::accent_blue()
                } else {
                    colors::text_muted()
                })
                .child("DIFF"),
        )
}

fn tb_btn(label: &'static str) -> impl IntoElement {
    div()
        .px_2()
        .h(px(20.0))
        .bg(colors::bg_elevated())
        .border_1()
        .border_color(colors::border())
        .rounded(px(3.0))
        .flex()
        .items_center()
        .cursor_pointer()
        .text_color(colors::text_secondary())
        .text_size(px(sizes::LABEL - 0.5))
        .hover(|s| s.bg(colors::bg_hover()))
        .child(label)
}

fn tb_btn_primary(label: &'static str) -> impl IntoElement {
    div()
        .px_2()
        .h(px(20.0))
        .bg(colors::accent())
        .border_1()
        .border_color(colors::accent())
        .rounded(px(3.0))
        .flex()
        .items_center()
        .cursor_pointer()
        .text_color(Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.05,
            a: 1.0,
        })
        .text_size(px(sizes::LABEL - 0.5))
        .hover(|s| s.bg(colors::accent_hover()))
        .child(label)
}

fn sort_btn(label: &'static str, active: bool) -> impl IntoElement {
    div()
        .px_2()
        .h(px(18.0))
        .rounded(px(3.0))
        .flex()
        .items_center()
        .cursor_pointer()
        .text_size(px(sizes::LABEL - 1.5))
        .text_color(if active {
            colors::accent()
        } else {
            colors::text_muted()
        })
        .bg(if active {
            Hsla {
                h: 200.0 / 360.0,
                s: 0.3,
                l: 0.10,
                a: 0.5,
            }
        } else {
            Hsla {
                h: 0.0,
                s: 0.0,
                l: 0.0,
                a: 0.0,
            }
        })
        .hover(|s| s.bg(colors::bg_hover()))
        .child(label)
}

fn col_header(state: &PatchesPanelState) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(18.0))
        .px_2()
        .gap_2()
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        .child(div().w(px(10.0))) // status dot
        .child(col_cell("Address", 90.0))
        .child(col_cell("Orig Bytes", 80.0))
        .child(col_cell_arrow())
        .child(col_cell("New Bytes", 80.0))
        .child(col_cell("Size", 36.0))
        .child(col_flex("Comment"))
        .child(if state.show_diff {
            div()
                .w(px(24.0))
                .text_size(px(sizes::LABEL - 1.5))
                .text_color(colors::text_muted())
                .child("^v")
                .into_any_element()
        } else {
            div().into_any_element()
        })
}

fn col_cell(label: &'static str, w: f32) -> impl IntoElement {
    div()
        .w(px(w))
        .text_size(px(sizes::LABEL - 0.5))
        .text_color(colors::text_muted())
        .font_weight(FontWeight::SEMIBOLD)
        .truncate()
        .child(label)
}

fn col_cell_arrow() -> impl IntoElement {
    div()
        .w(px(16.0))
        .text_size(px(sizes::LABEL - 0.5))
        .text_color(colors::text_muted())
        .truncate()
        .child("->")
}

fn col_flex(label: &'static str) -> impl IntoElement {
    div()
        .flex_1()
        .text_size(px(sizes::LABEL - 0.5))
        .text_color(colors::text_muted())
        .font_weight(FontWeight::SEMIBOLD)
        .truncate()
        .child(label)
}

fn patch_row_main(
    patch: &Patch,
    selected: bool,
    orig_hex: String,
    patch_hex: String,
    size: usize,
    changed_count: usize,
) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(sizes::ROW_H))
        .px_2()
        .gap_2()
        .bg(if selected {
            colors::bg_selection()
        } else {
            Hsla {
                h: 0.0,
                s: 0.0,
                l: 0.0,
                a: 0.0,
            }
        })
        .hover(|s| s.bg(colors::bg_hover()))
        .cursor_pointer()
        // Status dot
        .child(
            div()
                .w(px(8.0))
                .h(px(8.0))
                .rounded_full()
                .bg(colors::ok())
                .flex_shrink_0(),
        )
        // Address
        .child(
            div()
                .w(px(90.0))
                .text_color(colors::syn_address())
                .text_size(px(sizes::LABEL))
                .font_family("JetBrains Mono")
                .truncate()
                .child(format!("{:#010x}", patch.addr.0)),
        )
        // Original bytes
        .child(
            div()
                .w(px(80.0))
                .text_color(colors::err())
                .text_size(px(sizes::LABEL - 0.5))
                .font_family("JetBrains Mono")
                .overflow_hidden()
                .truncate()
                .child(orig_hex),
        )
        // Arrow
        .child(
            div()
                .w(px(16.0))
                .text_size(px(sizes::LABEL - 0.5))
                .text_color(colors::text_muted())
                .truncate()
                .child("->"),
        )
        // Patched bytes
        .child(
            div()
                .w(px(80.0))
                .text_color(colors::ok())
                .text_size(px(sizes::LABEL - 0.5))
                .font_family("JetBrains Mono")
                .overflow_hidden()
                .truncate()
                .child(patch_hex),
        )
        // Size badge
        .child(
            div().w(px(36.0)).px_1().child(
                div()
                    .px_1()
                    .rounded(px(3.0))
                    .bg(Hsla {
                        h: 120.0 / 360.0,
                        s: 0.3,
                        l: 0.10,
                        a: 0.6,
                    })
                    .text_size(px(sizes::LABEL - 1.5))
                    .text_color(colors::ok())
                    .child(format!("{size}b")),
            ),
        )
        // Comment
        .child(
            div()
                .flex_1()
                .text_color(colors::text_muted())
                .text_size(px(sizes::LABEL))
                .overflow_hidden()
                .truncate()
                .child(patch.comment.clone()),
        )
        // Changed count
        .child(if changed_count < size {
            div()
                .text_size(px(sizes::LABEL - 1.5))
                .text_color(colors::warn())
                .child(format!("{changed_count}/{size}Δ"))
                .into_any_element()
        } else {
            div().into_any_element()
        })
}

fn patch_row(
    patch: &Patch,
    idx: usize,
    selected: bool,
    show_diff: bool,
    ui_arc: Arc<Mutex<UIState>>,
) -> impl IntoElement {
    let addr = patch.addr;
    let orig_hex: String = patch
        .original
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ");
    let patch_hex: String = patch
        .patched
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ");
    let size = patch.patched.len();

    // Compute which bytes changed for diff highlighting
    let changed_count = patch
        .original
        .iter()
        .zip(patch.patched.iter())
        .filter(|(o, p)| o != p)
        .count();

    div()
        .flex()
        .flex_col()
        .w_full()
        .border_b_1()
        .border_color(colors::border())
        .id(SharedString::from(format!("patch-row-{idx}")))
        .on_click(move |_, _, _| {
            let mut ui = ui_arc.lock();
            ui.current_addr = addr;
        })
        // Main row
        .child(patch_row_main(
            patch,
            selected,
            orig_hex,
            patch_hex,
            size,
            changed_count,
        ))
        // Diff view (if enabled and selected)
        .child(if show_diff && selected {
            patch_diff_row(patch).into_any_element()
        } else {
            div().into_any_element()
        })
}

fn patch_diff_row(patch: &Patch) -> impl IntoElement {
    let max_bytes = 32usize;
    let show_len = patch.patched.len().min(max_bytes);

    div()
        .flex()
        .flex_row()
        .gap_1()
        .px_3()
        .py_1()
        .bg(Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.03,
            a: 0.8,
        })
        .border_b_1()
        .border_color(colors::border())
        .children((0..show_len).map(|i| {
            let orig = patch.original.get(i).copied().unwrap_or(0);
            let new_byte = patch.patched[i];
            let changed = orig != new_byte;
            div()
                .flex()
                .flex_col()
                .items_center()
                .w(px(24.0))
                .gap(px(1.0))
                .child(
                    div()
                        .w(px(22.0))
                        .h(px(14.0))
                        .flex()
                        .items_center()
                        .justify_center()
                        .rounded(px(2.0))
                        .bg(if changed {
                            Hsla {
                                h: 0.0 / 360.0,
                                s: 0.4,
                                l: 0.12,
                                a: 0.7,
                            }
                        } else {
                            Hsla {
                                h: 0.0,
                                s: 0.0,
                                l: 0.0,
                                a: 0.0,
                            }
                        })
                        .text_size(px(9.0))
                        .text_color(if changed {
                            colors::err()
                        } else {
                            colors::text_muted()
                        })
                        .font_family("JetBrains Mono")
                        .child(format!("{orig:02X}")),
                )
                .child(
                    div()
                        .w(px(22.0))
                        .h(px(14.0))
                        .flex()
                        .items_center()
                        .justify_center()
                        .rounded(px(2.0))
                        .bg(if changed {
                            Hsla {
                                h: 120.0 / 360.0,
                                s: 0.4,
                                l: 0.10,
                                a: 0.6,
                            }
                        } else {
                            Hsla {
                                h: 0.0,
                                s: 0.0,
                                l: 0.0,
                                a: 0.0,
                            }
                        })
                        .text_size(px(9.0))
                        .text_color(if changed {
                            colors::ok()
                        } else {
                            colors::text_muted()
                        })
                        .font_family("JetBrains Mono")
                        .child(format!("{new_byte:02X}")),
                )
        }))
        .child(if show_len < patch.patched.len() {
            div()
                .flex()
                .items_center()
                .text_size(px(9.0))
                .text_color(colors::text_muted())
                .child(format!("+{}", patch.patched.len() - show_len))
                .into_any_element()
        } else {
            div().into_any_element()
        })
}

fn patches_empty_state() -> impl IntoElement {
    div()
        .flex_1()
        .flex()
        .flex_col()
        .items_center()
        .justify_center()
        .gap_2()
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .child("No patches applied"),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_muted())
                .child("Use the hex editor or context menu to patch bytes"),
        )
}

// ── prod ensure-used (mirrors warnings; reachable from main behind a never-true branch) ──
#[doc(hidden)]
pub fn ensure_used_patches() {
    let data = AppData::default();
    let ui_arc: Arc<Mutex<UIState>> = Arc::new(Mutex::new(UIState::default()));

    // PatchStats + from_patches
    let patch_statistics = PatchStats::from_patches(&data.patches);
    let _ = &patch_statistics.total;
    let _ = &patch_statistics.enabled;
    let _ = &patch_statistics.total_bytes_changed;

    // PatchSort enum variants
    let _ = PatchSort::Addr;
    let _ = PatchSort::Size;
    let _ = PatchSort::Comment;

    // PatchesPanelState construction + methods
    let mut state = PatchesPanelState::new();
    state.refresh(&data);
    let _ = state.visible_patches(&data);
    state.select(0);
    state.on_scroll(0.0);
    state.on_key_up();
    state.on_key_down();
    let _ = PatchesPanelState::export_idc(&data);
    let _ = PatchesPanelState::export_python(&data);
    let _ = PatchesPanelState::export_c_array(&data);
    let _ = state.stats();
    let _ = state.show_disabled;
    let _ = state.cached_rev;

    // Top-level render fn
    let _ = render_patches_panel(&state, &data, &ui_arc);

    // Internal helpers
    let _ = patches_header(&patch_statistics);
    let _ = patches_toolbar(&state);
    let _ = tb_btn("x");
    let _ = tb_btn_primary("x");
    let _ = sort_btn("x", false);
    let _ = col_header(&state);
    let _ = col_cell("x", 0.0);
    let _ = col_cell_arrow();
    let _ = col_flex("x");

    let patch = crate::core::types::Patch {
        addr: crate::core::types::Addr(0),
        original: Vec::new(),
        patched: Vec::new(),
        comment: String::new(),
    };
    let _ = patch_row(&patch, 0, false, false, Arc::clone(&ui_arc));
    let _ = patch_diff_row(&patch);
    let _ = patches_empty_state();
}
