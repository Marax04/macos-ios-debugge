// ============================================================================
// ui/panels/watchpoints_section.rs — Watchpoint sub-section used at the
// bottom of the Breakpoints panel. Lists every active `Watchpoint` with its
// address, size, kind, condition, trigger count, and last trace seq. This
// complements the standalone `watchpoints.rs` panel (which models hardware
// watchpoints via `Breakpoint`).
// ============================================================================

use crate::core::app_state::AppData;
use crate::core::event_bus::{EventBus, UICommand};
use crate::core::types::{WatchKind, Watchpoint};
use crate::ui::theme::{colors, sizes};
use crate::ui::widgets::icon::icon;
use gpui::{
    div, px, ClickEvent, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement,
    SharedString, StatefulInteractiveElement, Styled,
};
use std::sync::Arc;

pub fn render_watchpoints_section(data: &AppData, bus: &Arc<EventBus>) -> impl IntoElement {
    let wps: Vec<Watchpoint> = data.watchpoints.values().cloned().collect();
    let total = wps.len();
    let bus_clone = Arc::clone(bus);

    div()
        .flex()
        .flex_col()
        .w_full()
        .border_t_1()
        .border_color(colors::border_accent())
        .child(wp_header(total, &bus_clone))
        .child(wp_col_hdr())
        .child(if wps.is_empty() {
            div()
                .px_3()
                .py_2()
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(colors::text_muted())
                .truncate()
                .child("No watchpoints. Use Add Watchpoint to monitor a memory address.")
                .into_any_element()
        } else {
            div()
                .flex()
                .flex_col()
                .w_full()
                .id("wp-sec-scroll")
                .overflow_y_scroll()
                .children(wps.into_iter().map(|w| wp_row(w, Arc::clone(&bus_clone))))
                .into_any_element()
        })
}

fn wp_header(total: usize, bus: &Arc<EventBus>) -> impl IntoElement {
    let bus = Arc::clone(bus);
    div()
        .flex()
        .flex_row()
        .items_center()
        .justify_between()
        .h(px(22.0))
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
                        .text_size(px(sizes::PANEL - 1.0))
                        .text_color(colors::text_primary())
                        .font_weight(FontWeight::SEMIBOLD)
                        .truncate()
                        .child("Watchpoints"),
                )
                .child(
                    div()
                        .text_size(px(sizes::LABEL - 1.0))
                        .text_color(colors::text_muted())
                        .truncate()
                        .child(format!("{total}")),
                ),
        )
        .child(
            div()
                .id(SharedString::from("wp-sec-add"))
                .px_2()
                .h(px(18.0))
                .flex()
                .items_center()
                .gap_1()
                .bg(colors::accent())
                .rounded(px(3.0))
                .cursor_pointer()
                .hover(|s| s.bg(colors::accent_hover()))
                .text_size(px(sizes::LABEL - 1.0))
                .text_color(Hsla { h: 0.0, s: 0.0, l: 0.05, a: 1.0 })
                .truncate()
                .child("+ Watch")
                .on_click(move |_: &ClickEvent, _, _| {
                    bus.send_command(UICommand::AddWatchpoint {
                        addr: crate::core::types::Addr(0),
                        size: 4,
                        condition: None,
                    });
                }),
        )
}

fn wp_col_hdr() -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .items_center()
        .h(px(18.0))
        .px_2()
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        .child(col_cell("#", 26.0))
        .child(col_cell("Kind", 40.0))
        .child(col_cell("Address", 130.0))
        .child(col_cell("Size", 36.0))
        .child(col_flex("Condition"))
        .child(col_cell("Trig", 36.0))
        .child(col_cell("LastSeq", 60.0))
        .child(div().w(px(18.0)))
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

const fn kind_label(k: WatchKind) -> &'static str {
    match k {
        WatchKind::Read => "R",
        WatchKind::Write => "W",
        WatchKind::Access => "RW",
    }
}

fn kind_color(k: WatchKind) -> Hsla {
    match k {
        WatchKind::Read => colors::accent_blue(),
        WatchKind::Write => colors::err(),
        WatchKind::Access => colors::accent(),
    }
}

fn wp_row(w: Watchpoint, bus: Arc<EventBus>) -> impl IntoElement {
    let wp_id = w.id;
    let dot_color = if w.enabled {
        colors::bp_enabled()
    } else {
        colors::bp_disabled()
    };
    let bus_toggle = Arc::clone(&bus);
    let bus_del = Arc::clone(&bus);

    div()
        .flex()
        .flex_row()
        .w_full()
        .h(px(sizes::ROW_H))
        .items_center()
        .px_2()
        .border_b_1()
        .border_color(colors::border())
        .hover(|s| s.bg(colors::bg_hover()))
        .child(
            div()
                .id(SharedString::from(format!("wp-sec-toggle-{wp_id}")))
                .w(px(12.0))
                .h(px(12.0))
                .rounded_full()
                .bg(dot_color)
                .mr_1()
                .cursor_pointer()
                .hover(|s| s.opacity(0.7))
                .on_click(move |_: &ClickEvent, _, _| {
                    bus_toggle.send_command(UICommand::ToggleWatchpoint { wp_id });
                }),
        )
        .child(
            div()
                .w(px(26.0))
                .text_size(px(sizes::LABEL))
                .text_color(dot_color)
                .font_family("JetBrains Mono")
                .truncate()
                .child(format!("#{wp_id}")),
        )
        .child(
            div()
                .w(px(40.0))
                .child(
                    div()
                        .px_1()
                        .rounded(px(3.0))
                        .bg(colors::bg_elevated())
                        .text_size(px(sizes::LABEL - 1.5))
                        .text_color(kind_color(w.kind))
                        .font_weight(FontWeight::BOLD)
                        .truncate()
                        .child(kind_label(w.kind)),
                ),
        )
        .child(
            div()
                .w(px(130.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(colors::syn_address())
                .truncate()
                .child(format!("{:#018x}", w.addr.0)),
        )
        .child(
            div()
                .w(px(36.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(colors::text_secondary())
                .truncate()
                .child(format!("{}", w.size)),
        )
        .child(
            div()
                .flex_1()
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.0))
                .text_color(if w.condition.is_some() {
                    colors::syn_immediate()
                } else {
                    colors::text_muted()
                })
                .overflow_hidden()
                .truncate()
                .child(w.condition.unwrap_or_else(|| "—".to_owned())),
        )
        .child(
            div()
                .w(px(36.0))
                .text_size(px(sizes::LABEL))
                .text_color(if w.trigger_count > 0 {
                    colors::ok()
                } else {
                    colors::text_muted()
                })
                .truncate()
                .child(format!("×{}", w.trigger_count)),
        )
        .child(
            div()
                .w(px(60.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(colors::text_muted())
                .truncate()
                .child(
                    w.last_seq
                        .map_or_else(|| "—".to_owned(), |s| format!("{s}")),
                ),
        )
        .child(
            div()
                .id(SharedString::from(format!("wp-sec-del-{wp_id}")))
                .w(px(18.0))
                .h(px(18.0))
                .flex()
                .items_center()
                .justify_center()
                .rounded(px(3.0))
                .cursor_pointer()
                .hover(|s| s.bg(colors::err()))
                .child(icon("cross"))
                .on_click(move |_: &ClickEvent, _, _| {
                    bus_del.send_command(UICommand::DeleteWatchpoint { wp_id });
                }),
        )
}

// ── prod ensure-used ─────────────────────────────────────────────────────────
#[doc(hidden)]
pub fn ensure_used_watchpoints_section() {
    let data = AppData::new();
    let bus = Arc::new(EventBus::new());
    let _ = render_watchpoints_section(&data, &bus);
    let _ = kind_label(WatchKind::Read);
    let _ = kind_label(WatchKind::Write);
    let _ = kind_label(WatchKind::Access);
    let _ = kind_color(WatchKind::Read);
    let _ = kind_color(WatchKind::Write);
    let _ = kind_color(WatchKind::Access);
}
