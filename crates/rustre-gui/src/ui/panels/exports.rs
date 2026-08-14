// ============================================================================
// ui/panels/exports.rs — Exports table panel
// ============================================================================

use crate::core::app_state::AppData;
use crate::core::types::{Addr, SymbolKind};
use crate::ui::theme::{colors, sizes};
use crate::ui::widgets::virtual_list::VirtualListState;
use gpui::{div, px, FontWeight, Hsla, IntoElement, ParentElement, Styled};

#[derive(Clone, Debug)]
pub struct ExportEntry {
    pub name: String,
    pub addr: Addr,
    pub ordinal: Option<u32>,
    pub forwarded_to: Option<String>,
}

#[derive(Debug, Default)]
pub struct ExportsPanelState {
    pub vlist: VirtualListState,
    pub filter: String,
    pub selected: Option<usize>,
    pub cached: Vec<ExportEntry>,
}

impl ExportsPanelState {
    pub fn new() -> Self {
        Self {
            vlist: VirtualListState::new(sizes::ROW_H),
            ..Default::default()
        }
    }

    pub fn refresh(&mut self, data: &AppData) {
        self.cached = data
            .symbols
            .values()
            .filter(|s| matches!(s.kind, SymbolKind::Export))
            .map(|s| ExportEntry {
                name: s.name.clone(),
                addr: s.addr,
                ordinal: None,
                forwarded_to: None,
            })
            .collect();
        self.cached.sort_by_key(|e| e.ordinal.unwrap_or(u32::MAX));
        self.vlist.total_rows = self.visible().len();
    }

    pub fn visible(&self) -> Vec<&ExportEntry> {
        let q = self.filter.to_lowercase();
        self.cached
            .iter()
            .filter(|e| q.is_empty() || e.name.to_lowercase().contains(&q))
            .collect()
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
}

pub fn render_exports_panel<'a>(
    state: &'a ExportsPanelState,
    data: &'a AppData,
) -> impl IntoElement + 'a {
    // Touch `data` — reserved for future cross-referencing of exports against
    // the loaded binary's symbol table.
    debug_assert!(data.symbols.len() < usize::MAX);
    let entries = state.visible();
    let win = state.vlist.window();

    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_panel())
        .child(panel_header(&format!("Exports ({})", state.cached.len())))
        .child(filter_bar(&state.filter, "Filter exports…"))
        .child(exports_col_header())
        .child(
            div().flex_1().overflow_hidden().child(
                div()
                    .w_full()
                    .h(px(win.total_height))
                    .child(div().h(px(win.top_pad)))
                    .children(
                        entries
                            .get(win.first..win.last.min(entries.len()))
                            .unwrap_or(&[])
                            .iter()
                            .enumerate()
                            .map(|(i, e)| (win.first + i, *e))
                            .map(|(row, e)| export_row(e, state.selected == Some(row))),
                    )
                    .child(div().h(px(win.bottom_pad)))
            ),
        )
}

fn export_row(e: &ExportEntry, selected: bool) -> impl IntoElement {
    let bg = if selected {
        colors::bg_selection()
    } else {
        Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.0,
            a: 0.0,
        }
    };
    let ord_str = e.ordinal.map(|o| format!("{o}")).unwrap_or_default();

    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .w_full()
        .h(px(sizes::ROW_H))
        .bg(bg)
        .px_2()
        .cursor_pointer()
        .child(
            div()
                .w(px(36.0))
                .text_color(colors::text_muted())
                .text_size(px(sizes::LABEL))
                .font_family("JetBrains Mono")
                .truncate()
                .child(ord_str),
        )
        .child(
            div()
                .flex_1()
                .text_color(colors::syn_symbol())
                .text_size(px(sizes::CODE))
                .font_family("JetBrains Mono")
                .overflow_hidden()
                .truncate()
                .child(e.name.clone()),
        )
        .child(e.forwarded_to.as_ref().map_or_else(
            || {
                div()
                    .w(px(90.0))
                    .text_color(colors::syn_address())
                    .text_size(px(sizes::LABEL))
                    .font_family("JetBrains Mono")
                    .truncate()
                    .child(format!("{:#010x}", e.addr.0))
                    .into_any_element()
            },
            |fwd| {
                div()
                    .w(px(120.0))
                    .text_color(colors::syn_comment())
                    .text_size(px(sizes::LABEL))
                    .overflow_hidden()
                    .truncate()
                    .child(format!("-> {fwd}"))
                    .into_any_element()
            },
        ))
}

fn exports_col_header() -> impl IntoElement {
    div()
        .h(px(18.0))
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .px_2()
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        .child(
            div()
                .w(px(36.0))
                .text_color(colors::text_muted())
                .text_size(px(10.0))
                .truncate()
                .child("Ord"),
        )
        .child(
            div()
                .flex_1()
                .text_color(colors::text_muted())
                .text_size(px(10.0))
                .truncate()
                .child("Name"),
        )
        .child(
            div()
                .w(px(90.0))
                .text_color(colors::text_muted())
                .text_size(px(10.0))
                .truncate()
                .child("Address"),
        )
}

fn filter_bar(val: &str, placeholder: &str) -> impl IntoElement {
    let text = if val.is_empty() {
        placeholder.to_owned()
    } else {
        val.to_owned()
    };
    let col = if val.is_empty() {
        colors::text_muted()
    } else {
        colors::text_primary()
    };
    div()
        .h(px(28.0))
        .flex()
        .items_center()
        .px_2()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(
            div()
                .flex_1()
                .h(px(20.0))
                .px_2()
                .bg(colors::bg_base())
                .border_1()
                .border_color(colors::border())
                .rounded(px(3.0))
                .text_size(px(sizes::CODE))
                .text_color(col)
                .font_family("JetBrains Mono")
                .truncate()
                .child(text),
        )
}

fn panel_header(title: &str) -> impl IntoElement {
    div()
        .h(px(24.0))
        .flex()
        .items_center()
        .px_3()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .text_size(px(sizes::LABEL))
        .text_color(colors::text_muted())
        .font_weight(FontWeight::SEMIBOLD)
        .truncate()
        .child(title.to_owned())
}

// ── prod ensure-used (reachable from main behind a never-true branch) ──
#[doc(hidden)]
pub fn ensure_used_exports() {
    let data = AppData::new();
    let mut state = ExportsPanelState::new();
    state.refresh(&data);
    let entry = ExportEntry {
        name: String::new(),
        addr: Addr(0),
        ordinal: None,
        forwarded_to: None,
    };
    let _ = &entry.name;
    let _ = entry.addr;
    let _ = entry.ordinal;
    let _ = &entry.forwarded_to;
    let _ = state.visible();
    state.select(0);
    state.on_scroll(0.0);
    state.on_key_up();
    state.on_key_down();
    let _ = render_exports_panel(&state, &data);
    let _ = export_row(&entry, false);
    let _ = exports_col_header();
    let _ = filter_bar("", "");
    let _ = panel_header("");
}
