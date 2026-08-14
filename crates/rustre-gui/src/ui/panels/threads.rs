// ============================================================================
// ui/panels/threads.rs — Threads panel with state badges, active-thread
// highlighting, PC display, column headers, and empty-state placeholder.
// ============================================================================
use crate::core::app_state::AppData;
use crate::core::event_bus::{EventBus, UICommand};
use crate::core::types::{Thread, ThreadState};
use crate::ui::theme::{colors, sizes};
use gpui::{
    div, px, ClickEvent, FontWeight, Hsla, InteractiveElement, IntoElement, ParentElement,
    SharedString, StatefulInteractiveElement, Styled,
};
use std::sync::Arc;

// ── Public entry point ────────────────────────────────────────────────────────

/// Render the Threads panel. Each row dispatches `UICommand::SelectThread`
/// on click so other thread-scoped panels (Registers / Stack) can re-render
/// for the chosen tid.
pub fn render_threads_panel<'a>(
    data: &'a AppData,
    active_tid: Option<u64>,
    bus: &Arc<EventBus>,
) -> impl IntoElement + 'a {
    let threads = &data.threads;
    let is_attached = data.dbg_attached;

    div()
        .flex()
        .flex_col()
        .w_full()
        .h_full()
        .bg(colors::bg_panel())
        .child(threads_panel_header(is_attached, threads.len()))
        .child(thread_col_headers())
        .child(
            div()
                .id("threads-scroll")
                .flex()
                .flex_col()
                .w_full()
                .flex_1()
                .overflow_y_scroll()
                .children(
                    threads
                        .iter()
                        .map(|t| thread_row(t, active_tid == Some(t.tid), bus)),
                )
                .child(if threads.is_empty() {
                    thread_empty_state(is_attached).into_any_element()
                } else {
                    div().into_any_element()
                }),
        )
}

// ── Panel header ──────────────────────────────────────────────────────────────

fn threads_panel_header(is_attached: bool, count: usize) -> impl IntoElement {
    let status_bg = if is_attached {
        colors::ok()
    } else {
        Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.3,
            a: 1.0,
        }
    };
    let status_text = if is_attached { "LIVE" } else { "IDLE" };

    // Count running vs stopped threads (shown in subtitle)
    let subtitle = format!("{count} thread{}", if count == 1 { "" } else { "s" });

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
                        .child("Threads"),
                )
                .child(
                    div()
                        .px(px(5.0))
                        .h(px(14.0))
                        .flex()
                        .items_center()
                        .rounded_sm()
                        .bg(status_bg)
                        .text_size(px(8.5))
                        .text_color(Hsla {
                            h: 0.0,
                            s: 0.0,
                            l: 0.06,
                            a: 1.0,
                        })
                        .font_weight(FontWeight::BOLD)
                        .child(status_text),
                ),
        )
        .child(
            div()
                .text_size(px(sizes::LABEL))
                .text_color(colors::text_muted())
                .child(subtitle),
        )
}

// ── Column headers ────────────────────────────────────────────────────────────

fn thread_col_headers() -> impl IntoElement {
    div()
        .flex()
        .flex_row()
        .w_full()
        .h(px(18.0))
        .items_center()
        .px_2()
        .bg(colors::bg_elevated())
        .border_b_1()
        .border_color(colors::border())
        // Active indicator column
        .child(div().w(px(12.0)))
        // TID
        .child(
            div()
                .w(px(72.0))
                .text_size(px(8.5))
                .text_color(colors::text_muted())
                .font_weight(FontWeight::SEMIBOLD)
                .child("TID")
                .truncate(),
        )
        // State
        .child(
            div()
                .w(px(52.0))
                .text_size(px(8.5))
                .text_color(colors::text_muted())
                .font_weight(FontWeight::SEMIBOLD)
                .child("State")
                .truncate(),
        )
        // PC
        .child(
            div()
                .w(px(130.0))
                .text_size(px(8.5))
                .text_color(colors::text_muted())
                .font_weight(FontWeight::SEMIBOLD)
                .child("PC")
                .truncate(),
        )
        // Name
        .child(
            div()
                .flex_1()
                .text_size(px(8.5))
                .text_color(colors::text_muted())
                .font_weight(FontWeight::SEMIBOLD)
                .child("Name")
                .truncate(),
        )
}

// ── Thread row ────────────────────────────────────────────────────────────────

fn thread_row_name_cell(t: &Thread, is_active: bool) -> impl IntoElement {
    let name_color = if is_active {
        colors::text_primary()
    } else {
        colors::text_secondary()
    };
    div()
        .flex_1()
        .flex()
        .flex_row()
        .items_center()
        .gap_1()
        .child(
            div()
                .text_size(px(sizes::CODE - 1.0))
                .text_color(name_color)
                .child(t.name.clone())
                .truncate(),
        )
        .child(if is_active {
            div()
                .px(px(4.0))
                .h(px(12.0))
                .flex()
                .items_center()
                .rounded_sm()
                .bg(colors::ok())
                .text_size(px(7.5))
                .text_color(Hsla {
                    h: 0.0,
                    s: 0.0,
                    l: 0.05,
                    a: 1.0,
                })
                .font_weight(FontWeight::BOLD)
                .child("ACTIVE")
                .into_any_element()
        } else {
            div().into_any_element()
        })
}

fn thread_row_state_cell(t: &Thread) -> impl IntoElement {
    let state_color = thread_state_color(t.state);
    let state_label = thread_state_label(t.state);
    let state_bg = thread_state_bg(t.state);
    div().w(px(52.0)).child(
        div()
            .px(px(4.0))
            .h(px(14.0))
            .flex()
            .items_center()
            .rounded_sm()
            .bg(state_bg)
            .border_1()
            .border_color(state_color)
            .text_size(px(8.0))
            .text_color(state_color)
            .font_weight(FontWeight::SEMIBOLD)
            .child(state_label),
    )
}

fn thread_row(t: &Thread, is_active: bool, bus: &Arc<EventBus>) -> impl IntoElement {
    let bus = Arc::clone(bus);
    let tid = t.tid;
    let row_bg = if is_active {
        Hsla {
            h: 0.58,
            s: 0.4,
            l: 0.14,
            a: 0.45,
        }
    } else {
        Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.0,
            a: 0.0,
        }
    };

    div()
        .id(SharedString::from(format!("thread-row-{tid}")))
        .flex()
        .flex_row()
        .w_full()
        .h(px(sizes::ROW_H + 2.0))
        .items_center()
        .px_2()
        .bg(row_bg)
        .border_b_1()
        .border_color(Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.12,
            a: 0.4,
        })
        .cursor_pointer()
        .hover(|s| s.bg(colors::bg_hover()))
        .on_click(move |_: &ClickEvent, _, _| {
            bus.send_command(UICommand::SelectThread { tid });
        })
        // Active indicator dot
        .child(
            div()
                .w(px(8.0))
                .h(px(8.0))
                .rounded_full()
                .mr(px(4.0))
                .bg(if is_active {
                    colors::ok()
                } else {
                    Hsla {
                        h: 0.0,
                        s: 0.0,
                        l: 0.0,
                        a: 0.0,
                    }
                })
                .flex_shrink_0(),
        )
        // TID (hex)
        .child(
            div()
                .w(px(72.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(if is_active {
                    colors::syn_address()
                } else {
                    colors::text_secondary()
                })
                .font_weight(if is_active {
                    FontWeight::SEMIBOLD
                } else {
                    FontWeight::NORMAL
                })
                .child(format!("{:#x}", t.tid))
                .truncate(),
        )
        // State badge
        .child(thread_row_state_cell(t))
        // PC
        .child(
            div()
                .w(px(130.0))
                .font_family("JetBrains Mono")
                .text_size(px(sizes::CODE - 1.5))
                .text_color(colors::syn_address())
                .child(format!("{:#016x}", t.pc.0))
                .truncate(),
        )
        // Thread name
        .child(thread_row_name_cell(t, is_active))
}

// ── Empty state ───────────────────────────────────────────────────────────────

fn thread_empty_state(is_attached: bool) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .items_center()
        .justify_center()
        .w_full()
        .pt(px(24.0))
        .gap(px(6.0))
        .child(
            div()
                .text_size(px(11.0))
                .text_color(colors::text_muted())
                .child(if is_attached {
                    "No threads found"
                } else {
                    "No active debug session"
                }),
        )
        .child(
            div()
                .text_size(px(10.0))
                .text_color(colors::text_muted())
                .child(if is_attached {
                    "Thread list will appear when the process has threads."
                } else {
                    "Attach or launch a process to see threads."
                }),
        )
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const fn thread_state_label(state: ThreadState) -> &'static str {
    match state {
        ThreadState::Running => "RUN",
        ThreadState::Stopped => "STOP",
        ThreadState::Suspended => "SUSP",
        ThreadState::Unknown => "???",
    }
}

const fn thread_state_color(state: ThreadState) -> Hsla {
    match state {
        ThreadState::Running => colors::ok(),
        ThreadState::Stopped => colors::warn(),
        ThreadState::Suspended => colors::text_muted(),
        ThreadState::Unknown => colors::err(),
    }
}

const fn thread_state_bg(state: ThreadState) -> Hsla {
    match state {
        ThreadState::Running => Hsla {
            h: colors::ok().h,
            s: 0.4,
            l: 0.12,
            a: 0.35,
        },
        ThreadState::Stopped => Hsla {
            h: colors::warn().h,
            s: 0.5,
            l: 0.12,
            a: 0.35,
        },
        ThreadState::Suspended => Hsla {
            h: 0.0,
            s: 0.0,
            l: 0.14,
            a: 0.3,
        },
        ThreadState::Unknown => Hsla {
            h: colors::err().h,
            s: 0.4,
            l: 0.12,
            a: 0.35,
        },
    }
}
