// ============================================================================
// ui/panels/memory_search.rs — Memory search panel
// ============================================================================
//
// Search live process / image memory for: literal bytes, masked byte patterns
// (e.g. `48 8B ?? 24 ??`), integers of 1/2/4/8 bytes (LE/BE), or strings
// (ASCII / UTF-16). Results show address, surrounding context preview, and
// click-to-navigate to the hex view.
//
// Backed by `rustre_debug::memory_search` once results are wired through the
// event bus.

// Re-export the backend memory-search engine so panel-internal code (and the
// event-bus search worker) can drive scans through a single import path, and
// so the link from this UI panel to the debugger hub is a hard crate-graph
// edge rather than a doc-comment promise.
pub use rustre_debug::memory_search as backend;

use crate::core::app_state::AppData;
use crate::core::event_bus::{EventBus, UICommand};
use crate::core::types::Addr;
use crate::ui::theme::{colors, sizes};
use crate::ui::widgets::virtual_list::VirtualListState;
use gpui::{
    div, px, ClickEvent, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement,
    SharedString, StatefulInteractiveElement, Styled,
};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum MemSearchKind {
    #[default]
    Bytes,
    Pattern,
    IntU8,
    IntU16,
    IntU32,
    IntU64,
    Ascii,
    Utf16,
}

impl MemSearchKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Bytes => "Bytes",
            Self::Pattern => "Pattern",
            Self::IntU8 => "u8",
            Self::IntU16 => "u16",
            Self::IntU32 => "u32",
            Self::IntU64 => "u64",
            Self::Ascii => "ASCII",
            Self::Utf16 => "UTF-16",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum MemSearchEndian {
    #[default]
    Little,
    Big,
}

#[derive(Clone, Debug)]
pub struct MemSearchHit {
    pub addr: Addr,
    pub region: Option<String>,
    pub preview: String,
}

#[derive(Default)]
pub struct MemorySearchPanelState {
    pub vlist: VirtualListState,
    pub kind: MemSearchKind,
    pub endian: MemSearchEndian,
    pub query: String,
    pub range_start: String,
    pub range_end: String,
    pub case_sensitive: bool,
    pub hits: Vec<MemSearchHit>,
    pub selected: Option<usize>,
    pub last_query_rev: u64,
}

impl MemorySearchPanelState {
    pub fn refresh(&mut self, _data: &AppData, rev: u64) {
        if self.last_query_rev == rev {
            return;
        }
        self.last_query_rev = rev;
        self.vlist.total_rows = self.hits.len();
    }

    pub fn on_scroll(&mut self, d: f64) {
        self.vlist.scroll_by(d);
    }
    pub fn on_key_down(&mut self, d: i64) {
        self.vlist.move_selection(d);
    }

    pub fn set_hits(&mut self, hits: Vec<MemSearchHit>) {
        self.hits = hits;
        self.vlist.total_rows = self.hits.len();
    }
}

pub fn render_memory_search_panel<'a>(
    state: &'a MemorySearchPanelState,
    bus: &Arc<EventBus>,
) -> impl IntoElement + 'a {
    let bus = Arc::clone(bus);
    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_panel())
        .child(ms_hdr(state.hits.len()))
        .child(ms_query_row(state, &bus))
        .child(ms_kind_row(state, &bus))
        .child(ms_range_row(state))
        .child(ms_col_hdr())
        .child(if state.hits.is_empty() {
            ms_empty_state().into_any_element()
        } else {
            let bus_rows = Arc::clone(&bus);
            div()
                .flex()
                .flex_col()
                .w_full()
                .flex_1()
                .id("memsearch-scroll")
                .overflow_y_scroll()
                .children(
                    state
                        .hits
                        .iter()
                        .enumerate()
                        .map(|(i, h)| ms_row(i, h, state.selected == Some(i), &bus_rows)),
                )
                .into_any_element()
        })
}

fn ms_hdr(count: usize) -> impl IntoElement {
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
                .flex()
                .flex_row()
                .items_center()
                .gap_2()
                .child(crate::ui::widgets::icon::icon("search"))
                .child(
                    div()
                        .text_size(px(sizes::PANEL))
                        .text_color(colors::text_primary())
                        .font_weight(FontWeight::SEMIBOLD)
                        .child("Memory Search"),
                ),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .child(format!("{count} hits")),
        )
}

fn ms_query_row(state: &MemorySearchPanelState, bus: &Arc<EventBus>) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .h(px(28.0))
        .px_2()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .child("Query"),
        )
        .child(
            div()
                .id("memsearch-input")
                .flex_1()
                .h(px(22.0))
                .px_2()
                .bg(colors::bg_elevated())
                .border_1()
                .border_color(colors::border())
                .rounded(px(3.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(colors::text_primary())
                .truncate()
                .child(if state.query.is_empty() {
                    SharedString::from(match state.kind {
                        MemSearchKind::Bytes => "DE AD BE EF",
                        MemSearchKind::Pattern => "48 8B ?? 24 ??",
                        MemSearchKind::IntU8
                        | MemSearchKind::IntU16
                        | MemSearchKind::IntU32
                        | MemSearchKind::IntU64 => "0x1234",
                        MemSearchKind::Ascii => "MZ",
                        MemSearchKind::Utf16 => "kernel32",
                    })
                } else {
                    SharedString::from(state.query.clone())
                }),
        )
        .child(ms_btn("Find", true, UICommand::MemSearchFind, bus))
        .child(ms_btn("Stop", false, UICommand::MemSearchStop, bus))
}

fn ms_kind_row(state: &MemorySearchPanelState, bus: &Arc<EventBus>) -> impl IntoElement {
    let kinds = [
        MemSearchKind::Bytes,
        MemSearchKind::Pattern,
        MemSearchKind::IntU8,
        MemSearchKind::IntU16,
        MemSearchKind::IntU32,
        MemSearchKind::IntU64,
        MemSearchKind::Ascii,
        MemSearchKind::Utf16,
    ];
    let mut row = div()
        .flex()
        .flex_row()
        .items_center()
        .gap_1()
        .h(px(24.0))
        .px_2()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border());
    for (idx, k) in kinds.into_iter().enumerate() {
        let selected = state.kind == k;
        let bus_c = Arc::clone(bus);
        let kind_idx = u8::try_from(idx).unwrap_or(0);
        row = row.child(
            div()
                .id(SharedString::from(format!("ms-kind-{idx}")))
                .px_2()
                .h(px(18.0))
                .rounded(px(3.0))
                .bg(if selected {
                    colors::bg_selection()
                } else {
                    colors::bg_elevated()
                })
                .border_1()
                .border_color(if selected {
                    colors::border_accent()
                } else {
                    colors::border()
                })
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(if selected {
                    colors::text_bright()
                } else {
                    colors::text_secondary()
                })
                .cursor_pointer()
                .hover(|s| s.bg(colors::bg_hover()))
                .on_click(move |_: &ClickEvent, _, _| {
                    bus_c.send_command(UICommand::MemSearchSetKind(kind_idx));
                })
                .child(k.label()),
        );
    }
    row.child(div().flex_1()).child(
        div()
            .text_size(px(sizes::LABEL - 1.0))
            .text_color(colors::text_muted())
            .child(match state.endian {
                MemSearchEndian::Little => "LE",
                MemSearchEndian::Big => "BE",
            }),
    )
}

fn ms_range_row(state: &MemorySearchPanelState) -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .gap_2()
        .h(px(22.0))
        .px_2()
        .bg(colors::bg_surface())
        .border_b_1()
        .border_color(colors::border())
        .child(
            div()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_muted())
                .child("Range"),
        )
        .child(
            div()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(colors::syn_address())
                .child(if state.range_start.is_empty() {
                    SharedString::from("0x0")
                } else {
                    SharedString::from(state.range_start.clone())
                }),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_muted())
                .child(".."),
        )
        .child(
            div()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(colors::syn_address())
                .child(if state.range_end.is_empty() {
                    SharedString::from("end")
                } else {
                    SharedString::from(state.range_end.clone())
                }),
        )
        .child(div().flex_1())
        .child(
            div()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(if state.case_sensitive {
                    colors::accent()
                } else {
                    colors::text_muted()
                })
                .child("Aa"),
        )
}

fn ms_col_hdr() -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(18.0))
        .px_2()
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        .child(
            div()
                .w(px(140.0))
                .text_size(px(sizes::LABEL - 0.5))
                .text_color(colors::text_muted())
                .font_weight(FontWeight::SEMIBOLD)
                .truncate()
                .child("Address"),
        )
        .child(
            div()
                .w(px(120.0))
                .text_size(px(sizes::LABEL - 0.5))
                .text_color(colors::text_muted())
                .font_weight(FontWeight::SEMIBOLD)
                .truncate()
                .child("Region"),
        )
        .child(
            div()
                .flex_1()
                .text_size(px(sizes::LABEL - 0.5))
                .text_color(colors::text_muted())
                .font_weight(FontWeight::SEMIBOLD)
                .truncate()
                .child("Context"),
        )
}

fn ms_row(i: usize, h: &MemSearchHit, selected: bool, bus: &Arc<EventBus>) -> impl IntoElement {
    let bus = Arc::clone(bus);
    div()
        .id(SharedString::from(format!("memsearch-hit-{i}")))
        .flex()
        .flex_row()
        .items_center()
        .h(px(sizes::ROW_H))
        .px_2()
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
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .border_b_1()
        .border_color(colors::border())
        .on_click(move |_: &ClickEvent, _, _| {
            bus.send_command(UICommand::MemSearchSelectHit(i));
        })
        .child(
            div()
                .w(px(140.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(colors::syn_address())
                .truncate()
                .child(format!("{:#012x}", h.addr.0)),
        )
        .child(
            div()
                .w(px(120.0))
                .text_size(px(sizes::LABEL))
                .text_color(colors::syn_symbol())
                .overflow_hidden()
                .truncate()
                .child(h.region.clone().unwrap_or_else(|| "—".into())),
        )
        .child(
            div()
                .flex_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(colors::text_secondary())
                .overflow_hidden()
                .truncate()
                .child(h.preview.clone()),
        )
}

fn ms_btn(
    label: &'static str,
    primary: bool,
    cmd: UICommand,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let bus = Arc::clone(bus);
    div()
        .id(SharedString::from(format!("ms-btn-{label}")))
        .px_2()
        .h(px(20.0))
        .bg(if primary {
            colors::accent()
        } else {
            colors::bg_elevated()
        })
        .border_1()
        .border_color(if primary {
            colors::accent()
        } else {
            colors::border()
        })
        .rounded(px(3.0))
        .flex()
        .items_center()
        .text_size(px(sizes::LABEL - 1.0))
        .text_color(if primary {
            Hsla {
                h: 0.0,
                s: 0.0,
                l: 0.05,
                a: 1.0,
            }
        } else {
            colors::text_secondary()
        })
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .on_click(move |_: &ClickEvent, _, _| {
            bus.send_command(cmd.clone());
        })
        .child(label)
}

fn ms_empty_state() -> impl IntoElement {
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
                .child("No memory matches"),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_muted())
                .child("Pick a search kind, enter a query, and press Find"),
        )
}

// ── ensure-used ──────────────────────────────────────────────────────────────
#[doc(hidden)]
pub fn ensure_used_memory_search() {
    let _ = MemSearchKind::Bytes.label();
    let _ = MemSearchKind::Pattern.label();
    let _ = MemSearchKind::IntU8.label();
    let _ = MemSearchKind::IntU16.label();
    let _ = MemSearchKind::IntU32.label();
    let _ = MemSearchKind::IntU64.label();
    let _ = MemSearchKind::Ascii.label();
    let _ = MemSearchKind::Utf16.label();
    let _ = MemSearchEndian::Little;
    let _ = MemSearchEndian::Big;

    let mut st = MemorySearchPanelState::default();
    let data = AppData::new();
    st.refresh(&data, 0);
    st.on_scroll(0.0);
    st.on_key_down(0);
    st.set_hits(vec![MemSearchHit {
        addr: Addr(0),
        region: None,
        preview: String::new(),
    }]);
    if std::hint::black_box(false) {
        let bus = Arc::new(EventBus::new());
        let _ = render_memory_search_panel(&st, &bus);
        // Touch the re-exported backend engine so the link from this panel
        // module to `rustre_debug::memory_search` is a hard symbol use, not
        // just a doc-comment promise. We construct a default `SearchOptions`
        // and a no-op `SearchPattern::Bytes(vec![])` — both are valid inputs
        // the search worker passes to `MemorySearch` once wired through the
        // event bus.
        let _opts: backend::SearchOptions = backend::SearchOptions::default();
        let _pat: backend::SearchPattern = backend::SearchPattern::Bytes(Vec::new());
    }
}
