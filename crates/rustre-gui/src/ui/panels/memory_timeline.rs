// ============================================================================
// ui/panels/memory_timeline.rs — Per-address memory history viewer.
// ============================================================================
//
// Queries the recorded trace events for a target address and lists every
// read/write touching it (seq, thread, value). Clicking a row dispatches a
// `TraceJumpToSeq` so the rest of the UI (registers, stack, listing) follows
// the cursor to that position in the trace.

use crate::core::app_state::AppData;
use crate::core::event_bus::{EventBus, UICommand};
use crate::core::types::{Addr, TraceEventKind, TraceEventRow};
use crate::ui::theme::{colors, sizes};
use gpui::{
    div, px, ClickEvent, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement,
    SharedString, StatefulInteractiveElement, Styled,
};
use std::sync::Arc;

/// Panel state — owns the query address and a cached row list.
#[derive(Clone, Debug, Default)]
pub struct MemoryTimelinePanelState {
    pub query: Addr,
    cached_rows: Vec<TraceEventRow>,
    cached_rev: u64,
    cached_query: u64,
}

impl MemoryTimelinePanelState {
    pub fn refresh(&mut self, data: &AppData, rev: u64) {
        if self.cached_rev == rev && self.cached_query == self.query.0 {
            return;
        }
        self.cached_rev = rev;
        self.cached_query = self.query.0;
        self.cached_rows = data
            .trace_events
            .iter()
            .filter(|e| e.addr == self.query && !matches!(e.kind, TraceEventKind::Exec))
            .cloned()
            .collect();
    }

    pub fn set_query(&mut self, addr: Addr) {
        self.query = addr;
        // Force refresh on next call.
        self.cached_rev = 0;
        self.cached_query = 0;
    }
}

pub fn render_memory_timeline_panel(
    state: &MemoryTimelinePanelState,
    bus: &Arc<EventBus>,
) -> impl IntoElement {
    let rows: Vec<TraceEventRow> = state.cached_rows.clone();
    let total = rows.len();
    let query = state.query;
    let bus_clone = Arc::clone(bus);

    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_panel())
        .child(mt_header(query, total, &bus_clone))
        .child(mt_col_hdr())
        .child(if rows.is_empty() {
            mt_empty(query).into_any_element()
        } else {
            div()
                .flex()
                .flex_col()
                .w_full()
                .flex_1()
                .id("memtl-scroll")
                .overflow_y_scroll()
                .children(
                    rows.into_iter()
                        .map(|r| mt_row(r, Arc::clone(&bus_clone))),
                )
                .into_any_element()
        })
}

fn mt_header(addr: Addr, total: usize, bus: &Arc<EventBus>) -> impl IntoElement {
    let bus = Arc::clone(bus);
    div()
        .flex()
        .flex_row()
        .items_center()
        .justify_between()
        .h(px(28.0))
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
                .child(
                    div()
                        .text_size(px(sizes::PANEL))
                        .text_color(colors::text_primary())
                        .font_weight(FontWeight::SEMIBOLD)
                        .truncate()
                        .child("Memory Timeline"),
                )
                .child(
                    div()
                        .text_size(px(sizes::LABEL))
                        .text_color(colors::syn_address())
                        .font_family("JetBrains Mono")
                        .truncate()
                        .child(if addr.0 == 0 {
                            "no address".to_owned()
                        } else {
                            format!("{:#018x}", addr.0)
                        }),
                ),
        )
        .child(
            div()
                .id(SharedString::from("memtl-refresh"))
                .px_2()
                .h(px(20.0))
                .flex()
                .items_center()
                .bg(colors::bg_elevated())
                .border_1()
                .border_color(colors::border())
                .rounded(px(3.0))
                .cursor_pointer()
                .hover(|s| s.bg(colors::bg_hover()))
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_secondary())
                .truncate()
                .child(format!("{total} hits"))
                .on_click(move |_: &ClickEvent, _, _| {
                    bus.send_command(UICommand::TraceQueryMemory { addr });
                }),
        )
}

fn mt_col_hdr() -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(18.0))
        .px_2()
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        .child(col_cell("Seq", 70.0))
        .child(col_cell("TID", 50.0))
        .child(col_cell("Kind", 50.0))
        .child(col_cell("PC", 140.0))
        .child(col_cell("Sz", 30.0))
        .child(col_flex("Value"))
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

fn col_flex(label: &'static str) -> impl IntoElement {
    div()
        .flex_1()
        .text_size(px(sizes::LABEL - 0.5))
        .text_color(colors::text_muted())
        .font_weight(FontWeight::SEMIBOLD)
        .truncate()
        .child(label)
}

fn kind_color(k: TraceEventKind) -> Hsla {
    match k {
        TraceEventKind::Read => colors::accent_blue(),
        TraceEventKind::Write => colors::err(),
        TraceEventKind::Exec => colors::accent(),
    }
}

const fn kind_label(k: TraceEventKind) -> &'static str {
    match k {
        TraceEventKind::Read => "R",
        TraceEventKind::Write => "W",
        TraceEventKind::Exec => "X",
    }
}

fn mt_row(r: TraceEventRow, bus: Arc<EventBus>) -> impl IntoElement {
    let id = SharedString::from(format!("memtl-row-{}", r.seq));
    let seq = r.seq;
    let kcol = kind_color(r.kind);
    let klabel = kind_label(r.kind);

    div()
        .id(id)
        .flex()
        .flex_row()
        .w_full()
        .h(px(sizes::ROW_H))
        .items_center()
        .px_2()
        .border_b_1()
        .border_color(colors::border())
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .active(|s| s.bg(colors::bg_active()))
        .child(
            div()
                .w(px(70.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(colors::syn_immediate())
                .truncate()
                .child(format!("{seq}")),
        )
        .child(
            div()
                .w(px(50.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(colors::text_secondary())
                .truncate()
                .child(format!("{}", r.thread)),
        )
        .child(
            div()
                .w(px(50.0))
                .child(
                    div()
                        .px_1()
                        .rounded(px(3.0))
                        .bg(colors::bg_elevated())
                        .text_size(px(sizes::LABEL - 1.5))
                        .text_color(kcol)
                        .font_weight(FontWeight::BOLD)
                        .truncate()
                        .child(klabel),
                ),
        )
        .child(
            div()
                .w(px(140.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(colors::syn_address())
                .truncate()
                .child(format!("{:#018x}", r.pc.0)),
        )
        .child(
            div()
                .w(px(30.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(colors::text_muted())
                .truncate()
                .child(format!("{}", r.size)),
        )
        .child(
            div()
                .flex_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(colors::syn_immediate())
                .overflow_hidden()
                .truncate()
                .child(format!("{:#x}", r.value)),
        )
        .on_click(move |_: &ClickEvent, _, _| {
            bus.send_command(UICommand::TraceJumpToSeq { seq });
        })
}

fn mt_empty(addr: Addr) -> impl IntoElement {
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
                .truncate()
                .child(if addr.0 == 0 {
                    "Right-click an address and choose Query Memory Timeline"
                } else {
                    "No recorded reads/writes for this address"
                }),
        )
}

// ── prod ensure-used ─────────────────────────────────────────────────────────
#[doc(hidden)]
pub fn ensure_used_memory_timeline() {
    let mut st = MemoryTimelinePanelState::default();
    st.set_query(Addr(0x4000));
    let data = AppData::new();
    st.refresh(&data, 1);
    let bus = Arc::new(EventBus::new());
    let _ = render_memory_timeline_panel(&st, &bus);
    let _ = kind_color(TraceEventKind::Read);
    let _ = kind_color(TraceEventKind::Write);
    let _ = kind_color(TraceEventKind::Exec);
    let _ = kind_label(TraceEventKind::Read);
    let _ = kind_label(TraceEventKind::Write);
    let _ = kind_label(TraceEventKind::Exec);
}
